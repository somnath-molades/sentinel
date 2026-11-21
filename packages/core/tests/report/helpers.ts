import { FindingsStore, type Finding, type TargetProfile } from '@sentinel/core'

export const profile: TargetProfile = {
  schema_version: 1,
  target: { kind: 'local', root: '/x' },
  generated_at: '2026-10-24T00:00:00.000Z',
  languages: [],
  frameworks: [],
  entrypoints: [],
  auth_surfaces: [],
  data_layer: [],
  iac: [],
  ci: [],
  client_boundary: [],
  hotspots: [],
  skipped: [],
  file_count: 10,
  truncated: false,
}

const sev = (band: 'critical' | 'high' | 'medium' | 'low' | 'info', score: number) => ({
  band,
  score,
  factors: { exploitability: 3 as const, reachability: 2 as const, blast_radius: 1 as const, data_sensitivity: 2 as const },
})
const mk = (id: string, status: Finding['status'], over: Partial<Finding> = {}): Finding => ({
  id,
  status,
  technique_id: 'sqli',
  file: 'src/db.ts',
  line: 40,
  snippet: 'query(a + b)',
  depth_tier: 'L1',
  reachability: 'handler reads req.body',
  verdicts: [{ agent: 'v1', outcome: status === 'dropped' ? 'disproved' : status === 'needs-review' ? 'ambiguous' : 'confirmed', reasoning: 'checked the data flow' }],
  additional_locations: [],
  reporting_agents: ['h1'],
  severity_disputed: false,
  severity_by_agent: [],
  ...over,
})

export const findings: Finding[] = [
  mk('c1', 'confirmed', { severity: sev('critical', 25), additional_locations: [{ line: 90, reachability: 'second sink in admin route' }] }),
  mk('c2', 'confirmed', { technique_id: 'xss', file: 'src/ui.ts', line: 7, severity: sev('low', 5) }),
  mk('n1', 'needs-review', { technique_id: 'ssrf', file: 'src/fetch.ts', line: 12, severity: sev('high', 18) }),
  mk('d1', 'dropped', { technique_id: 'csrf', file: 'src/form.ts', line: 3 }),
]
export const confirmedCount = 2

// Built through the real store so the fixtures cannot drift from what recordVerdict produces.
// Scores (3*exploit + 3*reach + 2*blast + 2*data): HIGH = 9+6+2+4 = 21 (high, 17-23);
// LOW = 3+3+0+0 = 6 (low, 4-9); HIGH2 = 9+6+4+4 = 23 (high). Disputed = high vs low; agreed = high vs high.
const HIGH = { exploitability: 3, reachability: 2, blast_radius: 1, data_sensitivity: 2 } as const
const HIGH2 = { exploitability: 3, reachability: 2, blast_radius: 2, data_sensitivity: 2 } as const
const LOW = { exploitability: 1, reachability: 1, blast_radius: 0, data_sensitivity: 0 } as const
function verified(ratings: [string, typeof HIGH | typeof HIGH2 | typeof LOW][]): Finding {
  const store = new FindingsStore()
  const { id } = store.add(
    { technique_id: 'sqli', file: 'src/db.ts', line: 40, snippet: 'query(a + b)' },
    { depth_tier: 'L1', reachability: 'handler reads req.body', reporting_agent: 'h1' },
  )
  for (const [agent, factors] of ratings) store.recordVerdict(id, { agent, outcome: 'confirmed', reasoning: 'checked the data flow', factors })
  return store.list()[0]!
}
export const disputed: Finding = verified([['v1', HIGH], ['v2', LOW]])
export const agreed: Finding = verified([['v1', HIGH], ['v2', HIGH2]])
// Task 7's rule: a disproof wipes ratings. Used to show a reporter never sees a dispute on a dropped finding.
export const droppedAfterDispute: Finding = (() => {
  const store = new FindingsStore()
  const { id } = store.add(
    { technique_id: 'sqli', file: 'src/db.ts', line: 40, snippet: 'query(a + b)' },
    { depth_tier: 'L1', reachability: 'handler reads req.body', reporting_agent: 'h1' },
  )
  store.recordVerdict(id, { agent: 'v1', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  store.recordVerdict(id, { agent: 'v2', outcome: 'confirmed', reasoning: 'r', factors: LOW })
  store.recordVerdict(id, { agent: 'v3', outcome: 'disproved', reasoning: 'r' })
  return store.list()[0]!
})()
