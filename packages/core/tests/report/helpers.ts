import type { Finding, TargetProfile } from '@sentinel/core'

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
