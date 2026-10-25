// The hunt ledger: report must say which planned domains no agent reported on. These sessions deliberately do
// NOT call select_techniques (hunt-loop.test.ts's session() does, which hid the plan_hunts-only condition).
import { readFileSync, realpathSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterEach, beforeEach, expect, test } from 'vitest'
import { DOMAINS, SENTINEL_CORE_VERSION, attestationHash, loadAuthorization, writeConsent } from '@sentinel/core'
import { createSentinelServer } from '../src/server.js'

type Res = { isError?: boolean; content: { type: string; text: string }[] }
const TARGET = join(process.cwd(), 'tests', 'fixtures', 'targets', 'express-vulnerable')

let consent: string
let closers: (() => Promise<void>)[] = []
beforeEach(async () => {
  consent = await mkdtemp(join(tmpdir(), 'hunt-ledger-consent-'))
})
afterEach(async () => {
  for (const c of closers) await c()
  closers = []
  await rm(consent, { recursive: true, force: true })
})

async function bare(): Promise<Client> {
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
  return client
}
const call = async (c: Client, name: string, args: Record<string, unknown> = {}): Promise<Res> => (await c.callTool({ name, arguments: args })) as Res
const warnings = async (c: Client): Promise<string[]> => JSON.parse((await call(c, 'report')).content[0]!.text).coverage_warnings
const unreportedLine = (w: string[]): string | undefined => w.find((x) => x.startsWith('Planned but no agent reported'))

const lines = readFileSync(join(TARGET, 'src', 'server.js'), 'utf8').split('\n')
const at = lines.findIndex((l) => l.includes(`WHERE name = '" +`))
const FINDING = { technique_id: 'sql-injection-built-query-string', file: 'src/server.js', line: at + 1, snippet: lines[at]!.trim(), depth_tier: 'L1', reachability: 'reached from GET /users' }

test('plan_hunts then report with nothing recorded says no agent reported for any planned domain', async () => {
  const c = await bare()
  await call(c, 'plan_hunts')
  const line = unreportedLine(await warnings(c))
  expect(line).toBeDefined()
  for (const d of DOMAINS) expect(line).toContain(d)
  expect(line).toMatch(/does not know whether a hunter ran/i)
  expect(line).toMatch(/not a clean result/i)
})

test('a finding for an injection technique removes injection from the unreported list and leaves the other nine', async () => {
  const c = await bare()
  await call(c, 'plan_hunts')
  expect((await call(c, 'record_finding', { reporting_agent: 'hunter-1', findings: [FINDING] })).isError).toBeUndefined()
  const line = unreportedLine(await warnings(c))!
  const listed = line.split(':').slice(1).join(':')
  expect(listed).not.toMatch(/\binjection\b/)
  for (const d of DOMAINS.filter((x) => x !== 'injection')) expect(listed).toContain(d)
})

test('select_techniques only: the original never-planned and coverage warnings still hold, and no ledger line appears', async () => {
  const c = await bare()
  let w = await warnings(c)
  expect(w.join('\n')).toMatch(/select_techniques was never called/)
  expect(unreportedLine(w)).toBeUndefined()
  await call(c, 'select_techniques', { stack: 'cobol-not-a-stack' }) // refused: still never recorded
  await call(c, 'select_techniques', { stack: 'node', vuln_class: 'no-such-class' })
  w = await warnings(c)
  expect(w.join('\n')).not.toMatch(/select_techniques was never called/)
  expect(w.join('\n')).toMatch(/No techniques exist for node \/ no-such-class/)
  expect(unreportedLine(w)).toBeUndefined()
})

test('plan_hunts keeps its none-coverage warnings alongside the ledger line', async () => {
  const c = await bare()
  await call(c, 'plan_hunts')
  const w = (await warnings(c)).join('\n')
  expect(w).toContain('No techniques exist for the iac domain: nothing was examined for it.')
})

test('a genuine crash is still labelled an internal error (only policy refusals are exempt)', async () => {
  const s = createSentinelServer({ consentRoot: consent, registryRoot: join(consent, 'does-not-exist') })
  const [a, b] = InMemoryTransport.createLinkedPair()
  const client = new Client({ name: 'test', version: '0' })
  await Promise.all([s.server.connect(a), client.connect(b)])
  closers.push(async () => {
    await client.close()
    await s.close()
  })
  const r = await call(client, 'select_techniques', { stack: 'node' })
  expect(r.isError).toBe(true)
  expect(r.content[0]!.text).toMatch(/^Internal error: /)
})
