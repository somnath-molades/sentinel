// These tests prove PLUMBING with canned agent output: ids, verdicts and severity travel through the real
// tools into the real reports. They say nothing about whether a real hunter finds bugs or a real verifier
// judges them correctly (spec 8.1). A green run here never means the agents are good.
import { readFileSync, realpathSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'
import { SENTINEL_CORE_VERSION, attestationHash, loadAuthorization, writeConsent } from '@sentinel/core'
import { createSentinelServer } from '../src/server.js'

type Res = { isError?: boolean; content: { type: string; text: string }[] }
const TARGET = join(process.cwd(), 'tests', 'fixtures', 'targets', 'express-vulnerable')
const TECHNIQUE = 'sql-injection-built-query-string'

let consent: string
let closers: (() => Promise<void>)[] = []
beforeEach(async () => {
  consent = await mkdtemp(join(tmpdir(), 'hunt-loop-consent-'))
})
afterEach(async () => {
  for (const c of closers) await c()
  closers = []
  await rm(consent, { recursive: true, force: true })
})

async function session(): Promise<Client> {
  const s = createSentinelServer({ consentRoot: consent })
  const [a, b] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '0' })
  await Promise.all([s.server.connect(a), client.connect(b)])
  closers.push(async () => {
    await client.close()
    await s.close()
  })
  const hash = attestationHash(loadAuthorization())
  const at = new Date().toISOString()
  writeConsent(consent, { schema_version: 1, mode: 'pure-reasoning', sentinel_version: SENTINEL_CORE_VERSION, attested_at: at, attestation_text_hash: hash, targets: [{ target: realpathSync(TARGET), attested_at: at, attestation_text_hash: hash }] })
  await client.callTool({ name: 'profile_target', arguments: { target: TARGET } })
  await client.callTool({ name: 'select_techniques', arguments: { stack: 'node' } })
  return client
}
const callRaw = async (c: Client, name: string, args: Record<string, unknown>): Promise<Res> => (await c.callTool({ name, arguments: args })) as Res
type Hit = { id: string; technique_id: string; file: string; line: number; reachability: string }
type Body = { accepted: Hit[]; rejected: { index: number; reason: string }[]; report: string; findings_recorded: number }
const json = (r: Res): Body => JSON.parse(r.content[0]!.text)
const sarifOf = (r: Res): { report: { runs: { results: unknown[] }[] } } => JSON.parse(r.content[0]!.text)

// Canned hunter candidates, pointed at lines found in the fixture text so a fixture edit either keeps working or fails here, loudly.
const fixtureLines = readFileSync(join(TARGET, 'src', 'server.js'), 'utf8').split('\n')
function lineOf(needle: string): { line: number; text: string } {
  const i = fixtureLines.findIndex((l) => l.includes(needle))
  if (i < 0) throw new Error(`fixture server.js no longer contains ${needle}; update the hunt-loop candidates`)
  return { line: i + 1, text: fixtureLines[i]!.trim() }
}
const candidate = (at: { line: number; text: string }) => ({ technique_id: TECHNIQUE, file: 'src/server.js', line: at.line, snippet: at.text, depth_tier: 'L1', reachability: 'reached from GET /users' })
const VULNERABLE = candidate(lineOf(`WHERE name = '" +`)) // string-built SQL
const SAFE_AT = lineOf('WHERE name = $1') // the parameterized counterpart
const SAFE = candidate(SAFE_AT)
const HIGH = { exploitability: 3, reachability: 3, blast_radius: 2, data_sensitivity: 2 }


// No tool reads a finding back (there is no get_finding), so the verifier knows nothing the hunter's result
// did not carry. Relaying that result to the verifier is the HARNESS's job, exactly as the dispatcher's job
// in skills/sentinel-verify/SKILL.md. The payload below is what the verifier is handed and nothing else.
type VerifierPayload = { finding_id: string; technique_id: string; file: string; line: number; reachability: string; reporter: string; verifier: string }
async function hunt(c: Client, f: Record<string, unknown>, hunter = 'hunter-1'): Promise<VerifierPayload> {
  const accepted: Hit = json(await callRaw(c, 'record_finding', { reporting_agent: hunter, findings: [f] })).accepted[0]!
  return { finding_id: accepted.id, technique_id: accepted.technique_id, file: accepted.file, line: accepted.line, reachability: accepted.reachability, reporter: hunter, verifier: 'verifier-1' }
}
const verify = (c: Client, p: VerifierPayload, outcome: 'confirmed' | 'disproved' | 'ambiguous', extra: Record<string, unknown> = {}) =>
  callRaw(c, 'verify_finding', { finding_id: p.finding_id, agent: p.verifier, outcome, reasoning: 'canned', ...extra })
const reportMd = async (c: Client): Promise<string> => json(await callRaw(c, 'report', { format: 'markdown' })).report
const reportSarif = async (c: Client) => sarifOf(await callRaw(c, 'report', { format: 'sarif' })).report

describe('stubbed-agent loop (plumbing only; no claim about agent judgement)', () => {
  test('a canned hunter candidate, verified by a different agent, reaches the report as confirmed', async () => {
    const c = await session()
    const p = await hunt(c, VULNERABLE)
    expect(p.reporter).not.toBe(p.verifier)
    expect((await verify(c, p, 'confirmed', { severity_factors: HIGH })).isError).toBeFalsy()
    const md = await reportMd(c)
    expect(md).toContain('## Confirmed findings')
    expect(md).toContain(p.technique_id)
    expect(md).toContain('Confirmed: 1')
    expect((await reportSarif(c)).runs[0].results).toHaveLength(1)
  })

  test('a disproved candidate never appears as confirmed in either output', async () => {
    const c = await session()
    const p = await hunt(c, VULNERABLE)
    expect((await verify(c, p, 'disproved')).isError).toBeFalsy()
    const md = await reportMd(c)
    expect(md).toContain('Confirmed: 0')
    expect(md).toContain('1 disproved by verification (not listed)')
    expect(md).not.toContain('[NOT CONFIRMED]')
    expect(md).not.toContain('req.query.name')
    expect((await reportSarif(c)).runs[0].results).toEqual([])
  })

  test('plumbing only: a candidate on the parameterized line, disproved by a canned verdict, reaches neither report as confirmed', async () => {
    const c = await session()
    const p = await hunt(c, SAFE)
    expect(p.line).toBe(SAFE_AT.line)
    expect((await verify(c, p, 'disproved')).isError).toBeFalsy()
    const md = await reportMd(c)
    expect(md).toContain('Confirmed: 0')
    expect(md).not.toContain('$1')
    expect((await reportSarif(c)).runs[0].results).toEqual([])
  })

  test('an ambiguous verdict lands in needs-review and is labelled not confirmed', async () => {
    const c = await session()
    const p = await hunt(c, VULNERABLE)
    expect((await verify(c, p, 'ambiguous')).isError).toBeFalsy()
    const md = await reportMd(c)
    expect(md).toContain('## Needs review')
    expect(md).toContain('[NOT CONFIRMED]')
    expect(md).toContain('Confirmed: 0')
    expect((await reportSarif(c)).runs[0].results).toEqual([])
  })

  test('a self-confirmation attempt is refused at the tool boundary as a tool error', async () => {
    const c = await session()
    const p = await hunt(c, VULNERABLE)
    const r = await verify(c, { ...p, verifier: p.reporter }, 'confirmed')
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/reporting agent/)
    expect(await reportMd(c)).toContain('Confirmed: 0')
  })
})

describe('agent output is untrusted: file paths are checked against what was walked', () => {
  const rec = (c: Client, file: string) => callRaw(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [{ ...VULNERABLE, file }] })

  test('a path outside the target is refused for being outside the target, not for some other reason', async () => {
    const c = await session()
    const r = await rec(c, '../../etc/passwd')
    expect(r.isError).toBe(true)
    expect(json(r).rejected[0].reason).toMatch(/relative path inside the target/)
  })

  test('a well-formed relative path that was never walked is refused, and says so', async () => {
    const c = await session()
    const r = await rec(c, 'src/invented.js')
    expect(r.isError).toBe(true)
    expect(json(r).rejected[0].reason).toMatch(/not.*walked/i)
    expect(json(r).rejected[0].reason).toContain('src/invented.js')
    // Honest about why: an unwalked file may well exist (skipped, or past the file limit), so it must not claim nobody read it.
    expect(json(r).rejected[0].reason).toMatch(/may exist but not have been covered/)
    expect(json(r).rejected[0].reason).toMatch(/skipped/)
    expect(json(r).rejected[0].reason).not.toMatch(/no one read|never read|made up/)
    expect(json(r).rejected[0].reason).not.toContain('This scan hit its file limit') // the target is small: no truncation clause
    expect((await reportSarif(c)).runs[0].results).toEqual([])
  })

  test('a file that WAS walked is accepted, in the plain and the ./ and backslash spellings, stored in the walked form', async () => {
    const c = await session()
    for (const [i, file] of ['src/server.js', './src/server.js', 'src\\util.js'].entries()) {
      const r = await rec(c, file)
      expect(r.isError, file).toBeFalsy()
      expect(json(r).accepted[0].file).toBe(i === 2 ? 'src/util.js' : 'src/server.js')
    }
  })

  test('./src/server.js and src/server.js are one finding in the same session', async () => {
    const c = await session()
    const first = json(await rec(c, 'src/server.js')).accepted[0]!
    const second = json(await rec(c, './src/server.js')).accepted[0]!
    expect(second.id).toBe(first.id)
    expect(json(await callRaw(c, 'report', {})).findings_recorded).toBe(1)
  })

  test('a case variant of a walked file is not a walked file', async () => {
    const c = await session()
    expect(json(await rec(c, 'SRC/Server.js')).rejected[0].reason).toMatch(/not.*walked/i)
  })

  test('a walked-file finding and an invented one in one batch: only the invented one is rejected', async () => {
    const c = await session()
    const r = json(await callRaw(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [VULNERABLE, { ...VULNERABLE, file: 'nope.js' }] }))
    expect(r.accepted).toHaveLength(1)
    expect(r.rejected.map((x: { index: number }) => x.index)).toEqual([1])
  })

  test('before any target is profiled, record_finding is the same tool error report and plan_hunts give', async () => {
    const s = createSentinelServer({ consentRoot: consent })
    const [a, b] = InMemoryTransport.createLinkedPair()
    const client = new Client({ name: 'test', version: '0' })
    await Promise.all([s.server.connect(a), client.connect(b)])
    closers.push(async () => {
      await client.close()
      await s.close()
    })
    const r = await callRaw(client, 'record_finding', { reporting_agent: 'hunter-1', findings: [VULNERABLE] })
    expect(r.isError).toBe(true)
    expect(r.content[0]!.text).toMatch(/No target has been profiled in this session\. Call profile_target first\./)
  })
})
