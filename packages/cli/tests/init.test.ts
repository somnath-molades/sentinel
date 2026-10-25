import { execFile } from 'node:child_process'
import { existsSync, readdirSync, realpathSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, expect, test } from 'vitest'
import { attestationHash, readConsent } from '@sentinel/core'
import { run } from '../src/index.js'
import type { Deps } from '../src/index.js'

const root = fileURLToPath(new URL('../../../', import.meta.url))
const AUTH = join(root, 'AUTHORIZATION.md')
const temps: string[] = []
const tmp = async (): Promise<string> => {
  const d = await mkdtemp(join(tmpdir(), 'init-test-'))
  temps.push(d)
  return d
}
afterEach(async () => void (await Promise.all(temps.splice(0).map((d) => rm(d, { recursive: true, force: true })))))

/** Feeds `lines` to the prompts one by one; once exhausted it behaves like EOF (null). */
async function init(cwd: string, lines: string[], args: string[] = [], deps: Deps = {}): Promise<{ code: number; out: string; err: string }> {
  const q = [...lines]
  let out = ''
  let err = ''
  const code = await run(['init', ...args], { out: (s) => void (out += s), err: (s) => void (err += s) }, { cwd, readLine: async () => q.shift() ?? null, ...deps })
  return { code, out, err }
}

test('typing the required word records pure-reasoning mode', async () => {
  const cwd = await tmp()
  const r = await init(cwd, ['yes', 'no'])
  expect(r.code).toBe(0)
  expect(readConsent(cwd)).toMatchObject({ mode: 'pure-reasoning', sentinel_version: '0.1.0', targets: [] })
})

test('displays AUTHORIZATION.md verbatim and hashes exactly what was shown', async () => {
  const cwd = await tmp()
  const text = await readFile(AUTH, 'utf8')
  const r = await init(cwd, ['yes', 'no'])
  expect(r.out).toContain(text)
  expect(readConsent(cwd)?.attestation_text_hash).toBe(attestationHash(text))
})

// Every near-miss is a refusal: non-zero, nothing on disk (not even the directory).
test.each([['y'], ['Y'], ['YES'], ['Yes'], ['yes '], [' yes'], ['yes.'], [''], ['  '], ['no'], ['\t']])('input %j is a refusal and leaves nothing behind', async (word) => {
  const cwd = await tmp()
  const r = await init(cwd, [word, 'no'])
  expect(r.code).not.toBe(0)
  expect(r.err).toMatch(/not recorded|refused/i)
  expect(readdirSync(cwd)).toEqual([])
})

test('EOF at the attestation prompt is a refusal', async () => {
  const cwd = await tmp()
  const r = await init(cwd, [])
  expect(r.code).not.toBe(0)
  expect(readdirSync(cwd)).toEqual([])
})

test('a Windows line ending after yes is accepted', async () => {
  const cwd = await tmp()
  expect((await init(cwd, ['yes\r', 'no'])).code).toBe(0)
})

test('declining the toolchain prints the coverage warning naming what is lost', async () => {
  const r = await init(await tmp(), ['yes', 'no'])
  expect(r.out).toMatch(/dependency CVE/i)
  expect(r.out).toMatch(/entropy-based secret scanning/i)
})

test('anything but "no" at the toolchain prompt is refused and writes no record', async () => {
  for (const second of ['yes', 'y', '', null]) {
    const cwd = await tmp()
    const r = await init(cwd, second === null ? ['yes'] : ['yes', second])
    expect(r.code).not.toBe(0)
    expect(readdirSync(cwd)).toEqual([])
  }
})

test('re-running init with unchanged text does not prompt again', async () => {
  const cwd = await tmp()
  await init(cwd, ['yes', 'no'])
  const before = await readFile(join(cwd, '.sentinel', 'consent.json'), 'utf8')
  const r = await init(cwd, [])
  expect(r.code).toBe(0)
  expect(await readFile(join(cwd, '.sentinel', 'consent.json'), 'utf8')).toBe(before)
})

test('re-running init when the attestation text has changed re-prompts, and refusal keeps the old record untouched', async () => {
  const cwd = await tmp()
  const changed = join(await tmp(), 'AUTH.md')
  const text = await readFile(AUTH, 'utf8')
  await init(cwd, ['yes', 'no'])
  await writeFile(changed, text.replace('Sentinel', 'Sentinel!'))
  const refused = await init(cwd, [], [], { authorizationPath: changed })
  expect(refused.code).not.toBe(0)
  expect(readConsent(cwd)?.attestation_text_hash).toBe(attestationHash(text))
  const ok = await init(cwd, ['yes', 'no'], [], { authorizationPath: changed })
  expect(ok.code).toBe(0)
  expect(readConsent(cwd)?.attestation_text_hash).toBe(attestationHash(await readFile(changed, 'utf8')))
})

test('attesting a target records it; another target is not covered and must be attested itself', async () => {
  const cwd = await tmp()
  const a = await tmp()
  const b = await tmp()
  expect((await init(cwd, ['yes', 'no'], [a])).code).toBe(0)
  expect(readConsent(cwd)?.targets.map((t) => t.target)).toEqual([realpathSync(a)])
  // Same target again: already attested, no prompt.
  expect((await init(cwd, [], [a])).code).toBe(0)
  // A different target: refused without the typed word.
  const refused = await init(cwd, [], [b])
  expect(refused.code).not.toBe(0)
  expect(readConsent(cwd)?.targets).toHaveLength(1)
  // With the word it is added (no toolchain prompt again: the mode is already recorded).
  expect((await init(cwd, ['yes'], [b])).code).toBe(0)
  expect(readConsent(cwd)?.targets.map((t) => t.target)).toEqual([realpathSync(a), realpathSync(b)])
})

test('nothing is written into the target', async () => {
  const cwd = await tmp()
  const target = await tmp()
  await init(cwd, ['yes', 'no'], [target])
  expect(readdirSync(target)).toEqual([])
})

test('refuses when the working directory is inside the target, since the record would land in it', async () => {
  const target = await tmp()
  const r = await init(target, ['yes', 'no'], [target])
  expect(r.code).not.toBe(0)
  expect(r.err).toMatch(/inside the target/i)
  expect(readdirSync(target)).toEqual([])
})

test('an out-of-scope target is refused by the scope lock', async () => {
  const cwd = await tmp()
  const r = await init(cwd, ['yes', 'no'], ['ssh://x/y'])
  expect(r.code).not.toBe(0)
  expect(r.err).toMatch(/scope lock/i)
  expect(readdirSync(cwd)).toEqual([])
})

test('the real binary reads the attestation from piped stdin', async () => {
  const bin = join(root, 'packages/cli/dist/bin.js')
  const cwd = await tmp()
  const run1 = (input: string): Promise<{ code: number }> =>
    new Promise((res) => {
      const p = execFile('node', [bin, 'init'], { cwd }, (e) => res({ code: e ? (typeof e.code === 'number' ? e.code : 1) : 0 }))
      p.stdin?.end(input)
    })
  expect((await run1('y\nno\n')).code).not.toBe(0)
  expect(existsSync(join(cwd, '.sentinel'))).toBe(false)
  expect((await run1('')).code).not.toBe(0)
  expect((await run1('yes\nno\n')).code).toBe(0)
  expect(readConsent(cwd)).toMatchObject({ mode: 'pure-reasoning' })
})
