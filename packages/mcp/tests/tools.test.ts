import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { GhRunner } from '../src/tools.js'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { createSentinelServer } from '../src/server.js'

type Opts = Parameters<typeof createSentinelServer>[0]
type Res = { isError?: boolean; content: { type: string; text: string }[] }

let dir: string
let closers: (() => Promise<void>)[] = []

async function connect(opts: Opts = {}): Promise<Client> {
  const s = createSentinelServer(opts)
  const [a, b] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '0' })
  await Promise.all([s.server.connect(a), client.connect(b)])
  closers.push(async () => {
    await client.close()
    await s.close()
  })
  return client
}
const call = async (c: Client, name: string, args: Record<string, unknown>): Promise<Res> => (await c.callTool({ name, arguments: args })) as Res
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const json = (r: Res): any => JSON.parse(r.content[0]!.text)

const F = { technique_id: 'sql-injection-built-query-string', file: 'src/app.js', line: 3, snippet: 'db.query("x" + id)', depth_tier: 'L1', reachability: 'reached from GET /u' }
const FACTORS = { exploitability: 3, reachability: 3, blast_radius: 2, data_sensitivity: 2 }

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sentinel-mcp-test-'))
  await mkdir(join(dir, 'src'))
  await writeFile(join(dir, 'src', 'app.js'), 'const express = require("express")\napp.get("/u", (req, res) => db.query("x" + req.query.id))\n')
  await writeFile(join(dir, 'main.rs'), 'fn main() {}\n')
})
afterEach(async () => {
  for (const c of closers) await c()
  closers = []
  await rm(dir, { recursive: true, force: true })
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
    const r = await call(c, 'record_finding', { findings: [{ ...F, reachability: '' }] })
    expect(r.isError).toBe(true)
    expect(json(r).rejected).toHaveLength(1)
  })
  test('additional_locations survive: a duplicate sink at another line is carried, not dropped', async () => {
    const c = await connect()
    await call(c, 'record_finding', { findings: [F] })
    const out = json(await call(c, 'record_finding', { findings: [{ ...F, line: 40, reachability: 'second sink' }] }))
    expect(out.accepted[0].additional_locations).toEqual([{ line: 40, reachability: 'second sink' }])
  })
})

describe('verify_finding', () => {
  async function seeded(): Promise<{ c: Client; id: string }> {
    const c = await connect()
    await call(c, 'profile_target', { target: dir })
    const id = json(await call(c, 'record_finding', { findings: [F] })).accepted[0].id as string
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
  test('unknown finding id, unknown outcome and severity on a non-confirmation are tool errors', async () => {
    const { c, id } = await seeded()
    expect((await call(c, 'verify_finding', { finding_id: 'zzz', ...V })).isError).toBe(true)
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, outcome: 'maybe' })).isError).toBe(true)
    expect((await call(c, 'verify_finding', { finding_id: id, ...V, outcome: 'disproved', severity_factors: FACTORS })).isError).toBe(true)
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
    const id = json(await call(c, 'record_finding', { findings: [F] })).accepted[0].id
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
    await call(c, 'record_finding', { findings: [{ ...F, snippet: '' }] })
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
  test('the clone is deleted after report', async () => {
    const before = await sentinelTemps()
    const c = await connect({ allowGitHub: true, gh: fakeGh('dir') })
    expect((await call(c, 'profile_target', { target: 'https://github.com/a/b' })).isError).toBeFalsy()
    expect((await sentinelTemps()).length).toBe(before.length + 1)
    await call(c, 'report', {})
    expect(await sentinelTemps()).toEqual(before)
  })
  test('the clone is deleted when the server closes mid-scan', async () => {
    const before = await sentinelTemps()
    const s = createSentinelServer({ allowGitHub: true, gh: fakeGh('dir') })
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
    expect(await sentinelTemps()).toEqual(before)
  })
})
