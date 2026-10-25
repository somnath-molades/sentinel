import { realpathSync } from 'node:fs'
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { GhRunner } from '../src/tools.js'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from 'vitest'
import { SENTINEL_CORE_VERSION, attestationHash, loadAuthorization, readConsent, writeConsent } from '@sentinel/core'
import { createSentinelServer } from '../src/server.js'

type Opts = Parameters<typeof createSentinelServer>[0]
type Res = { isError?: boolean; content: { type: string; text: string }[] }

let dir: string
let consent: string // the user's own directory holding .sentinel/consent.json, separate from every target
let closers: (() => Promise<void>)[] = []

async function connect(opts: Opts = {}): Promise<Client> {
  const s = createSentinelServer({ consentRoot: consent, ...opts })
  const [a, b] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '0' })
  await Promise.all([s.server.connect(a), client.connect(b)])
  closers.push(async () => {
    await client.close()
    await s.close()
  })
  return client
}
// Attests exactly what a user would have attested with `sentinel init <target>`: the realpathed root, or github:owner/repo.
function attest(target: string): void {
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/]+)$/.exec(target)
  let id: string
  try {
    id = m ? `github:${m[1]}/${m[2]}`.toLowerCase() : realpathSync(target)
  } catch {
    return // out of scope: leave it unattested, the scope lock refuses it
  }
  const text = loadAuthorization()
  const prior = readConsent(consent)
  const base = prior ?? { schema_version: 1 as const, mode: 'pure-reasoning' as const, sentinel_version: SENTINEL_CORE_VERSION, attested_at: new Date().toISOString(), attestation_text_hash: attestationHash(text), targets: [] }
  writeConsent(consent, { ...base, targets: [...base.targets, { target: id, attested_at: new Date().toISOString(), attestation_text_hash: attestationHash(text) }] })
}
const callRaw = async (c: Client, name: string, args: Record<string, unknown>): Promise<Res> => (await c.callTool({ name, arguments: args })) as Res
const call = async (c: Client, name: string, args: Record<string, unknown>): Promise<Res> => {
  if (name === 'profile_target' && typeof args.target === 'string') attest(args.target)
  return callRaw(c, name, args)
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const json = (r: Res): any => JSON.parse(r.content[0]!.text)

const F = { technique_id: 'sql-injection-built-query-string', file: 'src/app.js', line: 3, snippet: 'db.query("x" + id)', depth_tier: 'L1', reachability: 'reached from GET /u' }
const FACTORS = { exploitability: 3, reachability: 3, blast_radius: 2, data_sensitivity: 2 }

// The clone-cleanup tests below assert on a listing of os.tmpdir(), but other test
// FILES create `sentinel-*` directories there too (the CLI's scan tests do exactly
// this), and vitest runs files in parallel — so the listing races them and the
// assertion fails on a directory that is another file's live clone, not a leak.
// Give this file its own private tmp root for the duration. os.tmpdir() reads the
// environment on every call, and the scope lock resolves it at clone time, so both
// follow the redirect. The root's name deliberately avoids the `sentinel-` prefix,
// or it would appear in the other file's listing and move the flake rather than fix it.
let tmpRoot: string
let prevTmpdir: string | undefined
beforeAll(async () => {
  prevTmpdir = process.env.TMPDIR
  tmpRoot = await mkdtemp(join(realpathSync(tmpdir()), 'mcp-tmproot-'))
  process.env.TMPDIR = tmpRoot
})
afterAll(async () => {
  if (prevTmpdir === undefined) delete process.env.TMPDIR
  else process.env.TMPDIR = prevTmpdir
  await rm(tmpRoot, { recursive: true, force: true })
})

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sentinel-mcp-test-'))
  consent = await mkdtemp(join(tmpdir(), 'mcp-consent-'))
  await mkdir(join(dir, 'src'))
  await writeFile(join(dir, 'src', 'app.js'), 'const express = require("express")\napp.get("/u", (req, res) => db.query("x" + req.query.id))\n')
  await writeFile(join(dir, 'main.rs'), 'fn main() {}\n')
})
afterEach(async () => {
  for (const c of closers) await c()
  closers = []
  await rm(dir, { recursive: true, force: true })
  await rm(consent, { recursive: true, force: true })
})

describe('tool set', () => {
  test('registers exactly the Phase 1 tools', async () => {
    const c = await connect()
    expect((await c.listTools()).tools.map((t) => t.name).sort()).toEqual(['profile_target', 'record_finding', 'report', 'select_techniques', 'verify_finding'])
  })
})

describe('profile_target', () => {
  test('refuses an out-of-scope target as a tool error, not an exception', async () => {
    const c = await connect()
    const r = await call(c, 'profile_target', { target: '/definitely/not/here' })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/scope|refus/i)
  })
  test('refuses a remote target when GitHub is not enabled', async () => {
    const c = await connect()
    expect((await call(c, 'profile_target', { target: 'https://github.com/a/b' })).isError).toBe(true)
  })
  test('profiles a local dir and maps languages onto stack tokens, flagging unmapped ones', async () => {
    const c = await connect()
    const r = await call(c, 'profile_target', { target: dir })
    expect(r.isError).toBeFalsy()
    const out = json(r)
    expect(out.stacks.suggested).toEqual(['node'])
    expect(out.stacks.unmapped_languages).toEqual(['rust'])
    expect(out.stacks.warning).toMatch(/rust/)
  })
})

describe('empty or partial inputs never read as clean', () => {
  test('a target with no classifiable language warns at profile time and again in the report, even after selecting generic', async () => {
    await rm(join(dir, 'src'), { recursive: true })
    await rm(join(dir, 'main.rs'))
    await writeFile(join(dir, 'main.lua'), 'print(1)\n') // .lua is not in the walker table; C used to be the example here
    const c = await connect()
    const p = json(await call(c, 'profile_target', { target: dir }))
    expect(p.stacks.suggested).toEqual([])
    expect(p.stacks.warning).toMatch(/No stack could be derived/)
    expect(json(await call(c, 'select_techniques', { stack: 'generic' })).coverage).toBe('exact')
    const rep = json(await call(c, 'report', {}))
    expect(rep.coverage_warnings.join(' ')).toMatch(/No stack could be derived/)
    expect(rep.report).toMatch(/No stack could be derived/)
  })
  test('registry load errors are surfaced in selections, rejections and the report', async () => {
    const reg = await mkdtemp(join(tmpdir(), 'sentinel-mcp-test-reg-'))
    try {
      await cp(join(process.cwd(), 'registry'), reg, { recursive: true })
      const pack = (await readdir(join(reg, 'packs')))[0]!
      const tdir = join(reg, 'packs', pack, 'techniques')
      const bad = (await readdir(tdir))[0]!
      await writeFile(join(tdir, bad), 'not a technique')
      const c = await connect({ registryRoot: reg })
      await call(c, 'profile_target', { target: dir })
      const sel = json(await call(c, 'select_techniques', { stack: 'node' }))
      expect(sel.registry_warning).toMatch(new RegExp(`1 registry entry failed to load.*${bad}`))
      expect(json(await call(c, 'report', {})).coverage_warnings.join(' ')).toMatch(/failed to load/)
    } finally {
      await rm(reg, { recursive: true, force: true })
    }
  })
})

describe('select_techniques coverage signal', () => {
  test('exact', async () => {
    const c = await connect()
    const out = json(await call(c, 'select_techniques', { stack: 'node' }))
    expect(out.coverage).toBe('exact')
    expect(out.techniques.length).toBeGreaterThan(0)
    expect(out.warning).toBeUndefined()
  })
  test('wildcard-only is explicit and warns', async () => {
    const c = await connect()
    const out = json(await call(c, 'select_techniques', { stack: 'java', vuln_class: 'taint-flow' }))
    expect(out.coverage).toBe('wildcard-only')
    expect(out.techniques.length).toBeGreaterThan(0)
    expect(out.warning).toMatch(/only generic/i)
    expect(out.warning).toMatch(/not.*clean/i)
  })
  test('none is explicit, warns, and is not an empty-looking success', async () => {
    const c = await connect()
    const out = json(await call(c, 'select_techniques', { stack: 'java', vuln_class: 'sql-injection' }))
    expect(out.coverage).toBe('none')
    expect(out.techniques).toEqual([])
    expect(out.warning).toMatch(/nothing was examined/i)
  })
  test('a known language alias maps to its stack token', async () => {
    const c = await connect()
    const out = json(await call(c, 'select_techniques', { language: 'typescript' }))
    expect(out.stack).toBe('node')
    expect(out.coverage).toBe('exact')
  })
  test('an unmapped language is refused loudly, never passed through', async () => {
    const c = await connect()
    const r = await call(c, 'select_techniques', { language: 'rust' })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/rust/)
    expect(r.content[0]!.text).toMatch(/not.*clean/i)
  })
  test('language and stack together are refused', async () => {
    const c = await connect()
    expect((await call(c, 'select_techniques', { language: 'python', stack: 'node' })).isError).toBe(true)
  })
  test('an unknown stack token is refused as a tool error', async () => {
    const c = await connect()
    expect((await call(c, 'select_techniques', { stack: 'typescript' })).isError).toBe(true)
  })
})

describe('record_finding', () => {
  test('one bad finding does not abort the batch; rejections say which and why', async () => {
    const c = await connect()
    const r = await call(c, 'record_finding', {
      reporting_agent: 'hunter-1',
      findings: [F, { ...F, snippet: '   ' }, { ...F, line: 9, snippet: 'other()' }, { ...F, depth_tier: 'L9' }, { ...F, technique_id: 'nope' }, 'garbage', { ...F, file: '../../etc/passwd' }],
    })
    const out = json(r)
    expect(out.accepted).toHaveLength(2)
    expect(out.rejected.map((x: { index: number }) => x.index)).toEqual([1, 3, 4, 5, 6])
    expect(out.rejected[0].reason).toMatch(/snippet/)
    expect(out.rejected[2].reason).toMatch(/technique/)
    expect(r.isError).toBeFalsy()
  })
  test('a batch where every finding is rejected is an error, not an empty success', async () => {
    const c = await connect()
    const r = await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [{ ...F, reachability: '' }] })
    expect(r.isError).toBe(true)
    expect(json(r).rejected).toHaveLength(1)
  })
  test('additional_locations survive: a duplicate sink at another line is carried, not dropped', async () => {
    const c = await connect()
    await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [F] })
    const out = json(await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [{ ...F, line: 40, reachability: 'second sink' }] }))
    expect(out.accepted[0].additional_locations).toEqual([{ line: 40, reachability: 'second sink' }])
  })
})

describe('verify_finding', () => {
  async function seeded(): Promise<{ c: Client; id: string }> {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    const id = json(await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [F] })).accepted[0].id as string
    return { c, id }
  }
  const V = { agent: 'v1', outcome: 'confirmed', reasoning: 'traced to sink' }
  test('records a verdict and severity', async () => {
    const { c, id } = await seeded()
    const out = json(await call(c, 'verify_finding', { finding_id: id, ...V, severity_factors: FACTORS }))
    expect(out.finding.status).toBe('confirmed')
    expect(out.finding.severity.score).toBe(26)
    expect(out.finding.severity.band).toBe('critical')
  })
  test.each([[{ ...FACTORS, exploitability: 7 }], [{ ...FACTORS, blast_radius: 2.5 }], [{ ...FACTORS, reachability: -1 }], [{ exploitability: 1 }], [{ ...FACTORS, extra: 1 }], ['high']])(
    'rejects bad severity factors %j before the scorer and records no verdict',
    async (bad) => {
      const { c, id } = await seeded()
      const r = await call(c, 'verify_finding', { finding_id: id, ...V, severity_factors: bad })
      expect(r.isError).toBe(true)
      const rep = json(await call(c, 'report', { format: 'sarif' }))
      expect(rep.findings_recorded).toBe(1)
      expect(JSON.stringify(rep.report)).not.toMatch(/traced to sink/)
    },
  )
  test('the highest band wins across verifiers, and the disagreement is returned', async () => {
    const { c, id } = await seeded()
    const first = json(await call(c, 'verify_finding', { finding_id: id, ...V, severity_factors: FACTORS }))
    expect(first.severity.band).toBe('critical')
    expect(first.severity_disputed).toBe(false)
    expect(first.severity_overwritten).toBeUndefined()
    const low = { exploitability: 0, reachability: 0, blast_radius: 0, data_sensitivity: 0 }
    const second = json(await call(c, 'verify_finding', { finding_id: id, agent: 'v2', outcome: 'confirmed', reasoning: 'r', severity_factors: low }))
    expect(second.severity.band).toBe('critical') // a lower rating no longer replaces a higher one
    expect(second.severity_disputed).toBe(true)
    expect(second.severity_by_agent.map((x: { agent: string }) => x.agent)).toEqual(['v1', 'v2'])
    const third = json(await call(c, 'verify_finding', { finding_id: id, agent: 'v3', outcome: 'confirmed', reasoning: 'r' }))
    expect(third.severity.band).toBe('critical') // no factors supplied: the standing severity is reported, not hidden
  })
  test('unknown finding id, unknown outcome and severity on a non-confirmation are tool errors', async () => {
    const { c, id } = await seeded()
    expect((await call(c, 'verify_finding', { finding_id: 'zzz', ...V })).isError).toBe(true)
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, outcome: 'maybe' })).isError).toBe(true)
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, outcome: 'disproved', severity_factors: FACTORS })).isError).toBe(true)
  })
  test('the reporting agent cannot confirm its own finding through the tools', async () => {
    const { c, id } = await seeded()
    const r = await call(c, 'verify_finding', { finding_id: id, ...V, agent: 'hunter-1' })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/reporting agent/)
    expect(json(await call(c, 'report', {})).report).not.toMatch(/traced to sink/)
  })
  test('a spelling variant of the reporting agent is refused too', async () => {
    const { c, id } = await seeded()
    const r = await call(c, 'verify_finding', { finding_id: id, ...V, agent: 'HUNTER-1' })
    expect(r.content[0]!.text).toMatch(/reporting agent/)
  })
  test('the second reporter of a deduped finding cannot confirm it either', async () => {
    const { c, id } = await seeded()
    await call(c, 'record_finding', { reporting_agent: 'hunter-2', findings: [{ ...F, line: 77 }] })
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, agent: 'hunter-2' })).isError).toBe(true)
  })
  test('a different agent can still verify it', async () => {
    const { c, id } = await seeded()
    const r = await call(c, 'verify_finding', { finding_id: id, ...V, agent: 'verifier-1' })
    expect(r.isError).toBeFalsy()
    expect(json(r).finding.status).toBe('confirmed')
  })
  test.each(['hunter 1', 'hunter​-1', 'huntеr-1', ''])('verify_finding rejects the agent id %j', async (agent) => {
    const { c, id } = await seeded()
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, agent })).isError).toBe(true)
  })
})

describe('record_finding reporting_agent', () => {
  test('is required', async () => {
    const c = await connect()
    expect((await call(c, 'record_finding', { findings: [F] })).isError).toBe(true)
  })
  test.each(['', '   ', 'hunter 1', 'hunter​-1', 'huntеr-1', 'café'])('rejects the agent id %j', async (reporting_agent) => {
    const c = await connect()
    expect((await call(c, 'record_finding', { reporting_agent, findings: [F] })).isError).toBe(true)
  })
  test('a verifier cannot later report the finding it verified', async () => {
    const c = await connect()
    const id = json(await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [F] })).accepted[0].id as string
    await call(c, 'verify_finding', { finding_id: id, agent: 'verifier-1', outcome: 'confirmed', reasoning: 'r' })
    const r = await call(c, 'record_finding', { reporting_agent: 'verifier-1', findings: [F] })
    expect(r.isError).toBe(true)
    expect(json(r).rejected[0].reason).toMatch(/verdict/)
  })
})

describe('report', () => {
  test('refuses before a target is profiled', async () => {
    const c = await connect()
    expect((await call(c, 'report', {})).isError).toBe(true)
  })
  test('round-trips a confirmed finding with severity, in markdown and SARIF', async () => {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    await call(c, 'select_techniques', { stack: 'node' })
    const id = json(await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [F] })).accepted[0].id
    await call(c, 'verify_finding', { finding_id: id, agent: 'v', outcome: 'confirmed', reasoning: 'ok', severity_factors: FACTORS })
    const md = json(await call(c, 'report', {}))
    expect(md.report).toContain('sql-injection-built-query-string')
    expect(md.report).toContain('critical')
    const sarif = json(await call(c, 'report', { format: 'sarif' }))
    expect(sarif.report.runs[0].results).toHaveLength(1)
  })
  test('passes the real mode: pure-reasoning is declared in markdown and in the warnings', async () => {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    const out = json(await call(c, 'report', {}))
    expect(out.report).toMatch(/pure-reasoning/i)
    expect(out.coverage_warnings.join(' ')).toMatch(/pure-reasoning/i)
  })
  test('a report with no technique selection says nothing was examined, loudly', async () => {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    const out = json(await call(c, 'report', {}))
    expect(out.coverage_warnings.join(' ')).toMatch(/nothing was examined/i)
    expect(out.report).toMatch(/Coverage warnings/)
  })
  test('unmapped languages, a non-exact selection and rejected findings are all surfaced', async () => {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    await call(c, 'select_techniques', { stack: 'java', vuln_class: 'sql-injection' })
    await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [{ ...F, snippet: '' }] })
    const w = json(await call(c, 'report', {})).coverage_warnings.join(' ')
    expect(w).toMatch(/java/)
    expect(w).toMatch(/rejected/)
    expect(w).toMatch(/rust/)
  })
})

describe('GitHub clone cleanup', () => {
  const sentinelTemps = async (): Promise<string[]> => (await readdir(tmpdir())).filter((n) => n.startsWith('sentinel-') && !n.startsWith('sentinel-mcp-test-'))
  // `gh repo clone <url> <root> -- --depth 1`: args[3] is the clone destination.
  const fakeGh =
    (clone: 'dir' | 'file'): GhRunner =>
    async (args) => {
      if (args[1] === 'view') return { code: 0, stdout: JSON.stringify({ nameWithOwner: 'a/b' }) }
      const root = args[3]!
      if (clone === 'file') await writeFile(root, 'not a directory') // profiling the "clone" will fail
      else {
        await mkdir(root, { recursive: true })
        await writeFile(join(root, 'x.py'), 'print(1)\n')
      }
      return { code: 0, stdout: '' }
    }
  test('an unattested GitHub target is refused and its clone is deleted', async () => {
    const before = await sentinelTemps()
    const c = await connect({ allowGitHub: true, gh: fakeGh('dir') })
    const r = await callRaw(c, 'profile_target', { target: 'https://github.com/a/b' })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toContain('Not attested: github:a/b')
    expect(await sentinelTemps()).toEqual(before)
  })
  test('report does not delete the clone (repeatable query); it says so, and close deletes it', async () => {
    const before = await sentinelTemps()
    const s = createSentinelServer({ consentRoot: consent, allowGitHub: true, gh: fakeGh('dir') })
    const [x, y] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 't', version: '0' })
    await Promise.all([s.server.connect(x), client.connect(y)])
    expect((await call(client, 'profile_target', { target: 'https://github.com/a/b' })).isError).toBeFalsy()
    expect((await sentinelTemps()).length).toBe(before.length + 1)
    const rep = json(await call(client, 'report', {}))
    expect(rep.clone_retained).toMatch(/stays on disk/)
    expect((await sentinelTemps()).length).toBe(before.length + 1)
    await call(client, 'report', {}) // re-running still works
    await client.close()
    await s.close()
    expect(await sentinelTemps()).toEqual(before)
  })
  test('a second profile_target deletes the first clone and says so', async () => {
    const before = await sentinelTemps()
    const c = await connect({ allowGitHub: true, gh: fakeGh('dir') })
    await call(c, 'profile_target', { target: 'https://github.com/a/b' })
    const out = json(await call(c, 'profile_target', { target: dir }))
    expect(out.previous_clone_deleted).toMatch(/deleted/)
    expect(await sentinelTemps()).toEqual(before)
  })
  test('overlapping profile_target calls leak no clone', async () => {
    const before = await sentinelTemps()
    const slow: GhRunner = async (args) => {
      if (args[1] === 'clone') await new Promise((r) => setTimeout(r, 30))
      return fakeGh('dir')(args, 0)
    }
    const s = createSentinelServer({ consentRoot: consent, allowGitHub: true, gh: slow })
    const [x, y] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 't', version: '0' })
    await Promise.all([s.server.connect(x), client.connect(y)])
    const rs = await Promise.all([1, 2, 3].map(() => call(client, 'profile_target', { target: 'https://github.com/a/b' })))
    expect(rs.every((r) => !r.isError)).toBe(true)
    expect((await sentinelTemps()).length).toBe(before.length + 1) // only the latest clone is alive
    await client.close()
    await s.close()
    expect(await sentinelTemps()).toEqual(before)
  })
  test('the clone is deleted when the server closes mid-scan', async () => {
    const before = await sentinelTemps()
    const s = createSentinelServer({ consentRoot: consent, allowGitHub: true, gh: fakeGh('dir') })
    const [a, b] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 't', version: '0' })
    await Promise.all([s.server.connect(a), client.connect(b)])
    await call(client, 'profile_target', { target: 'https://github.com/a/b' })
    expect((await sentinelTemps()).length).toBe(before.length + 1)
    await client.close()
    await s.close()
    expect(await sentinelTemps()).toEqual(before)
  })
  test('the clone is deleted when profiling fails', async () => {
    const before = await sentinelTemps()
    const c = await connect({ allowGitHub: true, gh: fakeGh('file') })
    const r = await call(c, 'profile_target', { target: 'https://github.com/a/b' })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/clone was deleted/)
    expect(await sentinelTemps()).toEqual(before)
  })
})

describe('attestation is enforced (spec 9.2)', () => {
  test('an unattested target is refused as a tool error naming the target, and no session state is created', async () => {
    const c = await connect()
    const r = await callRaw(c, 'profile_target', { target: dir })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toContain(`Not attested: ${realpathSync(dir)}`)
    expect(r.content[0]!.text).toMatch(/sentinel init/)
    expect((await callRaw(c, 'report', {})).isError).toBe(true) // nothing was profiled
  })
  test('the target is profiled once it has been attested', async () => {
    const c = await connect()
    expect((await callRaw(c, 'profile_target', { target: dir })).isError).toBe(true)
    attest(dir)
    expect((await callRaw(c, 'profile_target', { target: dir })).isError).toBeFalsy()
  })
  test('attesting target A does not authorize target B', async () => {
    const other = await mkdtemp(join(tmpdir(), 'sentinel-mcp-other-'))
    try {
      await writeFile(join(other, 'a.js'), '1\n')
      const c = await connect()
      attest(dir)
      expect((await callRaw(c, 'profile_target', { target: dir })).isError).toBeFalsy()
      const r = await callRaw(c, 'profile_target', { target: other })
      expect(r.isError).toBe(true)
      expect(r.content[0]!.text).toContain(`Not attested: ${realpathSync(other)}`)
    } finally {
      await rm(other, { recursive: true, force: true })
    }
  })
  test('a corrupt consent record is an error naming the file, not a reset', async () => {
    await mkdir(join(consent, '.sentinel'))
    await writeFile(join(consent, '.sentinel', 'consent.json'), 'garbage')
    const c = await connect()
    const r = await callRaw(c, 'profile_target', { target: dir })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toContain('consent.json')
    expect(await readFile(join(consent, '.sentinel', 'consent.json'), 'utf8')).toBe('garbage')
  })
})
