import { execFile } from 'node:child_process'
import { realpathSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from 'vitest'
import * as core from '@sentinel/core'
import { removeClone } from '../src/commands/scan.js'
import { run } from '../src/index.js'
import type { Deps } from '../src/index.js'

vi.mock('@sentinel/core', async (orig) => {
  const real = await orig<typeof import('@sentinel/core')>()
  return { ...real, decideExitCode: vi.fn(real.decideExitCode) }
})

const root = fileURLToPath(new URL('../../../', import.meta.url))
const fixture = (...p: string[]): string => join(root, 'tests/fixtures', ...p)
const express = fixture('targets/express-vulnerable')
const badRegistry = fixture('registry/one-bad-entry')

// The clone-cleanup tests below assert on a listing of os.tmpdir(), but other test FILES create `sentinel-*`
// directories there too (the MCP server's tests do exactly this), and vitest runs files in parallel — so the listing
// races them and the assertion fails on a directory that is another file's live clone, not a leak. Give this file its
// own private tmp root for the duration. os.tmpdir() reads the environment on every call, and the scope lock resolves
// it at clone time, so both follow the redirect. The root's name deliberately avoids the `sentinel-` prefix, or it
// would appear in the other file's listing and move the flake rather than fix it.
let tmpRoot: string
let prevTmpdir: string | undefined
beforeAll(async () => {
  prevTmpdir = process.env.TMPDIR
  tmpRoot = await mkdtemp(join(realpathSync(tmpdir()), 'cli-tmproot-'))
  process.env.TMPDIR = tmpRoot
})
afterAll(async () => {
  if (prevTmpdir === undefined) delete process.env.TMPDIR
  else process.env.TMPDIR = prevTmpdir
  await rm(tmpRoot, { recursive: true, force: true })
})

// Scans need an attestation (spec 9.2). By default each scan is preceded by a real `init <target>` in a private working
// directory; pass { attest: false } to scan unattested. The directory holds the consent record, never the target.
let consentDir: string | undefined
async function cli(argv: string[], deps: Deps = {}, o: { attest?: boolean; cwd?: string } = {}): Promise<{ code: number; out: string; err: string }> {
  const cwd = o.cwd ?? (consentDir ??= await mkdtemp(join(tmpdir(), 'cli-consent-')))
  const lines = ['yes', 'no']
  const readLine = async (): Promise<string | null> => lines.shift() ?? null
  if (argv[0] === 'scan' && o.attest !== false) {
    const target = argv[1]!
    await run(['init', target], { out: () => {}, err: () => {} }, { ...deps, cwd, readLine }) // an out-of-scope target stays unattested and the scan refuses it
  }
  let out = ''
  let err = ''
  const code = await run(argv, { out: (s) => void (out += s), err: (s) => void (err += s) }, { ...deps, cwd })
  return { code, out, err }
}

const temps: string[] = []
async function tmpTarget(files: Record<string, string>): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'cli-test-'))
  temps.push(d)
  for (const [f, text] of Object.entries(files)) {
    await mkdir(join(d, f, '..'), { recursive: true })
    await writeFile(join(d, f), text)
  }
  return d
}
afterEach(async () => {
  if (consentDir) await rm(consentDir, { recursive: true, force: true })
  consentDir = undefined
  vi.mocked(core.decideExitCode).mockClear()
  await Promise.all(temps.splice(0).map((d) => rm(d, { recursive: true, force: true })))
})

describe('scan output', () => {
  test('markdown report has a summary and a coverage section, and exits 0 on a clean fixture', async () => {
    const r = await cli(['scan', express])
    expect(r.code).toBe(0)
    expect(r.out).toMatch(/^## Summary/m)
    expect(r.out).toMatch(/^## Coverage/m)
    expect(r.out).toMatch(/files scanned/)
  })

  test('says in plain words that no hunters ran, so zero findings is not a clean result', async () => {
    const r = await cli(['scan', express])
    expect(r.err).toMatch(/no hunter/i)
    expect(r.err).toMatch(/not a clean result/i)
    expect(r.out).toMatch(/Coverage warnings/)
  })

  test('states the technique coverage per stack, naming the exact match', async () => {
    const r = await cli(['scan', express])
    expect(r.err).toMatch(/node: \d+ technique/)
    expect(r.err).toMatch(/exact/)
  })

  test('--format sarif emits only valid SARIF 2.1.0 JSON on stdout; warnings stay on stderr', async () => {
    const r = await cli(['scan', express, '--format', 'sarif'])
    expect(r.code).toBe(0)
    const log = JSON.parse(r.out)
    expect(log.version).toBe('2.1.0')
    expect(r.err).toMatch(/no hunter/i) // the warning path was taken, and stdout is still pure JSON
  })

  test('SARIF carries the CLI-known coverage gaps in run properties.coverage_warnings', async () => {
    const t = await tmpTarget({ 'main.tf': 'x\n' })
    const run0 = JSON.parse((await cli(['scan', t, '--format', 'sarif', '--registry', badRegistry])).out).runs[0]
    expect(run0.properties.mode).toBe('pure-reasoning')
    const w: string[] = run0.properties.coverage_warnings
    expect(w).toEqual(expect.arrayContaining([expect.stringMatching(/^No hunter agents/), expect.stringMatching(/^No stack could be derived/), expect.stringMatching(/^1 registry entry failed to load/)]))
  })
})

describe('silent-failure guards', () => {
  test('a target with no classifiable language warns that no stack could be derived', async () => {
    const t = await tmpTarget({ 'main.tf': 'resource "x" "y" {}\n', 'ci.yaml': 'a: 1\n' })
    const r = await cli(['scan', t])
    expect(r.code).toBe(0)
    expect(r.err).toMatch(/no stack (token )?could be derived/i)
    expect(r.err).toMatch(/stack-specific techniques will not apply/i)
  })

  // One recognised file used to derive a stack and silence every coverage warning for the whole tree.
  test('one recognised file does not suppress the coverage warning for the files around it', async () => {
    const t = await tmpTarget({
      'package.json': '{"name":"x"}\n',
      'src/a.lua': 'print(1)\n', // not in the walker's extension table; C and C++ used to be the examples here
      'src/b.kt': 'fun main() {}\n',
      'main.tf': 'resource "aws_s3_bucket_acl" "b" { acl = "public-read" }\n',
      'config.yml': 'db:\n  password: "hunter2"\n',
      'server.js': 'const express = require("express")\n',
    })
    const r = await cli(['scan', t])
    expect(r.err).toMatch(/node: \d+ technique/) // a stack is still derived from the one JavaScript file
    expect(r.err).toMatch(/Of 6 files scanned, 1 carries a language Sentinel recognises/)
    expect(r.err).toMatch(/5 \(83%\)/)
    expect(r.out).toMatch(/examined by no stack-specific technique/) // and it reaches the report, not just stderr
  })

  test('a truncated scan says so as a warning, not only in the coverage section', async () => {
    const t = await tmpTarget({ 'a.js': 'const a = 1\n', 'b.js': 'const b = 2\n', 'c.js': 'const c = 3\n' })
    const r = await cli(['scan', t, '--max-files', '2'])
    expect(r.err).toMatch(/warning: The file limit was reached/)
    expect(r.out).toMatch(/file limit was reached/)
  })

  test('a language with no technique stack is called out as NOT examined', async () => {
    const t = await tmpTarget({ 'main.rs': 'fn main() {}\n', 'a.py': 'print(1)\n' })
    const r = await cli(['scan', t])
    expect(r.err).toMatch(/rust/i)
    expect(r.err).toMatch(/not.*examined/i)
  })

  test('a stack no technique covers is reported as none, not as covered', async () => {
    const t = await tmpTarget({ 'a.go': 'package main\n' })
    const r = await cli(['scan', t, '--registry', badRegistry])
    expect(r.err).toMatch(/go: 0 techniques.*\bnone\b/)
  })

  test('a stack with only generic techniques is reported as wildcard-only', async () => {
    const t = await tmpTarget({ 'a.go': 'package main\n' })
    const src = await readFile(join(badRegistry, 'packs/fixture-pack/techniques/sql-injection-string-concat.md'), 'utf8')
    const reg = await tmpTarget({
      'packs/p/pack.yaml': await readFile(join(badRegistry, 'packs/fixture-pack/pack.yaml'), 'utf8'),
      'packs/p/techniques/t.md': src.replace('stacks: [node, python]', 'stacks: [generic]'),
    })
    const r = await cli(['scan', t, '--registry', reg])
    expect(r.err).toMatch(/go: 1 technique.*wildcard-only/)
  })

  test('registry load errors are counted and their files named', async () => {
    const r = await cli(['scan', express, '--registry', badRegistry])
    expect(r.code).toBe(0)
    expect(r.err).toMatch(/\d+ registry entr(y|ies) failed to load/)
    expect(r.err).toMatch(/\.md/)
  })

  test('an empty registry is stated, not silently treated as full coverage', async () => {
    const reg = await tmpTarget({ 'packs/.keep': '' })
    const r = await cli(['scan', express, '--registry', reg])
    expect(r.err).toMatch(/no techniques/i)
  })
})

describe('refusal and errors', () => {
  test.each([['a file, not a directory', fixture('scope/file.txt')], ['a path that does not exist', '/nonexistent-sentinel-target'], ['a non-GitHub URL', 'https://example.com/a/b']])(
    'an out-of-scope target (%s) is refused with exit 2 and a reason on stderr, nothing on stdout',
    async (_, target) => {
    const r = await cli(['scan', target])
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/scope|refus/i)
    expect(r.out).toBe('')
    },
  )

  test('an unknown --format is an error (exit 2), not a silent default', async () => {
    const r = await cli(['scan', express, '--format', 'html'])
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/format/i)
  })

  test('an unreadable registry root is an error with a reason, not a stack trace', async () => {
    const r = await cli(['scan', express, '--registry', '/nonexistent-registry'])
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/registry/i)
    expect(r.err).not.toMatch(/\n\s+at /)
  })
})

describe('--fail-on wiring (when a gate can be evaluated)', () => {
  const hunters = { huntersAvailable: true }
  test('passes the chosen band through to core decideExitCode, with the recorded findings', async () => {
    const r = await cli(['scan', express, '--fail-on', 'high'], hunters)
    expect(r.code).toBe(0)
    expect(core.decideExitCode).toHaveBeenCalledWith([], 'high')
  })

  test('passes null when --fail-on is absent', async () => {
    await cli(['scan', express])
    expect(core.decideExitCode).toHaveBeenCalledWith([], null)
  })

  test('uses the exit code core decides', async () => {
    vi.mocked(core.decideExitCode).mockReturnValueOnce(1)
    expect((await cli(['scan', express, '--fail-on', 'low'], hunters)).code).toBe(1)
  })

  test('rejects a band that does not exist', async () => {
    expect((await cli(['scan', express, '--fail-on', 'severe'], hunters)).code).toBe(2)
  })
})

describe('--fail-on is a gate that must be able to trip', () => {
  test('in this build (no hunters) it exits 2 and says the gate cannot be evaluated', async () => {
    const r = await cli(['scan', express, '--fail-on', 'high'])
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/gate cannot be evaluated/)
    expect(r.err).toMatch(/No hunter agents/)
    expect(core.decideExitCode).not.toHaveBeenCalled()
  })

  test.each([
    ['a stack with no techniques', { 'a.go': 'package main\n' }, badRegistry, /go: 0 techniques/],
    ['no derivable stack', { 'main.tf': 'x\n' }, undefined, /No stack could be derived/],
    ['registry load errors', { 'a.js': 'x\n' }, badRegistry, /registry entry failed to load/],
  ])('even with hunters, %s exits 2', async (_, files, reg, msg) => {
    const t = await tmpTarget(files)
    const r = await cli(['scan', t, '--fail-on', 'high', ...(reg ? ['--registry', reg] : [])], { huntersAvailable: true })
    expect(r.code).toBe(2)
    expect(r.err).toMatch(msg)
  })

  // Deliberate: almost every repository holds a file with no recognised language, so this warning is loud but
  // does not block. Only the conditions that make the gate meaningless (no stack at all, truncation) block it.
  test('the unexamined-share warning is printed but does not block the gate', async () => {
    const t = await tmpTarget({ 'a.js': 'const a = 1\n', 'main.tf': 'resource "x" "y" {}\n' })
    const r = await cli(['scan', t, '--fail-on', 'high'], { huntersAvailable: true })
    expect(r.code).toBe(0)
    expect(r.err).toMatch(/examined by no stack-specific technique/)
    expect(r.err).not.toMatch(/gate cannot be evaluated/)
  })

  // A gate on a scan that walked 5 of 50,000 files must not exit 0.
  test('a truncated scan blocks the gate', async () => {
    const t = await tmpTarget({ 'a.js': 'const a = 1\n', 'b.js': 'const b = 2\n', 'c.js': 'const c = 3\n' })
    const r = await cli(['scan', t, '--fail-on', 'high', '--max-files', '2'], { huntersAvailable: true })
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/gate cannot be evaluated/)
    expect(r.err).toMatch(/file limit was reached/)
  })

  test('without --fail-on the same scan still exits 0 with warnings', async () => {
    expect((await cli(['scan', express])).code).toBe(0)
  })
})

describe('clone removal guard', () => {
  test('refuses to recursively delete a path that is not a Sentinel temp directory', async () => {
    const d = await tmpTarget({ 'keep.txt': 'x' })
    let err = ''
    await removeClone(d, { out: () => undefined, err: (s) => void (err += s) })
    expect(err).toMatch(/refused to delete/)
    expect((await readdir(d)).length).toBe(1)
  })
})

describe('GitHub clone ownership', () => {
  const sentinelTemps = async (): Promise<string[]> => (await readdir(tmpdir())).filter((n) => n.startsWith('sentinel-') && !n.startsWith('sentinel-mcp-test-'))
  const fakeGh =
    (clone: 'dir' | 'file'): NonNullable<Deps['gh']> =>
    async (args) => {
      if (args[1] === 'view') return { code: 0, stdout: JSON.stringify({ nameWithOwner: 'a/b' }) }
      const dest = args[3]!
      if (clone === 'file') await writeFile(dest, 'not a directory') // profiling will fail
      else {
        await mkdir(dest, { recursive: true })
        await writeFile(join(dest, 'x.py'), 'print(1)\n')
      }
      return { code: 0, stdout: '' }
    }

  test('the temporary clone is deleted after a successful scan', async () => {
    const before = await sentinelTemps()
    const r = await cli(['scan', 'https://github.com/a/b'], { gh: fakeGh('dir') })
    expect(r.code).toBe(0)
    expect(await sentinelTemps()).toEqual(before)
  })

  test('the temporary clone is deleted when the scan fails', async () => {
    const before = await sentinelTemps()
    const r = await cli(['scan', 'https://github.com/a/b'], { gh: fakeGh('file') })
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/failed/i)
    expect(await sentinelTemps()).toEqual(before)
  })
})

describe('built binary', () => {
  const bin = resolve(root, 'packages/cli/dist/bin.js')
  const exec = promisify(execFile)
  test('a refusal exits 2 with a reason and no stack trace', async () => {
    const r = await exec('node', [bin, 'scan', '/nonexistent-sentinel-target']).catch((e: { code: number; stderr: string; stdout: string }) => e)
    expect((r as { code: number }).code).toBe(2)
    expect((r as { stderr: string }).stderr).toMatch(/refus|scope/i)
    expect((r as { stderr: string }).stderr).not.toMatch(/\n\s+at /)
  })
  test('sarif piped from the real process is pure JSON', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'cli-bin-'))
    temps.push(cwd)
    await new Promise<void>((res, rej) => {
      const p = execFile('node', [bin, 'init', express], { cwd }, (e) => (e ? rej(e) : res()))
      p.stdin?.end('yes\nno\n')
    })
    const r = await exec('node', [bin, 'scan', express, '--format', 'sarif'], { cwd })
    expect(JSON.parse(r.stdout).version).toBe('2.1.0')
    expect(r.stderr).toMatch(/no hunter/i)
  })
})

describe('attestation is enforced (spec 9.2)', () => {
  test('an unattested target is refused: exit 2, names the target and the init command, no report', async () => {
    const r = await cli(['scan', express], {}, { attest: false })
    expect(r.code).toBe(2)
    expect(r.out).toBe('')
    expect(r.err).toContain(`Not attested: ${realpathSync(express)}`)
    expect(r.err).toMatch(/sentinel init /)
  })
  test('the same target is scanned once it has been attested', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'cli-consent-'))
    temps.push(cwd)
    expect((await cli(['scan', express], {}, { attest: false, cwd })).code).toBe(2)
    expect((await cli(['scan', express], {}, { cwd })).code).toBe(0)
  })
  test('attesting target A does not authorize target B', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'cli-consent-'))
    temps.push(cwd)
    const b = await tmpTarget({ 'x.js': 'console.log(1)\n' })
    expect((await cli(['scan', express], {}, { cwd })).code).toBe(0) // attests express
    const r = await cli(['scan', b], {}, { attest: false, cwd })
    expect(r.code).toBe(2)
    expect(r.err).toContain(`Not attested: ${realpathSync(b)}`)
  })
  test('a consent record that predates a changed AUTHORIZATION.md no longer authorizes a scan', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'cli-consent-'))
    temps.push(cwd)
    await cli(['scan', express], {}, { cwd })
    const changed = join(cwd, 'AUTH.md')
    await writeFile(changed, 'a different legal text\n')
    const r = await cli(['scan', express], { authorizationPath: changed }, { attest: false, cwd })
    expect(r.code).toBe(2)
    expect(r.err).toMatch(/Not attested/)
  })
  test('a corrupt consent record is an error naming the file, not a reset', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'cli-consent-'))
    temps.push(cwd)
    await mkdir(join(cwd, '.sentinel'))
    await writeFile(join(cwd, '.sentinel', 'consent.json'), 'garbage')
    const r = await cli(['scan', express], {}, { attest: false, cwd })
    expect(r.code).toBe(2)
    expect(r.err).toContain('consent.json')
    expect(await readFile(join(cwd, '.sentinel', 'consent.json'), 'utf8')).toBe('garbage')
  })
})
