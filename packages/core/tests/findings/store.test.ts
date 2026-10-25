import { FindingsStore, decideExitCode, type Finding, type Severity } from '@sentinel/core'

const base = { technique_id: 'sqli', file: 'a.ts', line: 40, snippet: 'query(a + b)' }
const meta = { depth_tier: 'L1' as const, reachability: 'handler reads req.body' }
const m = { ...meta, reporting_agent: 'hunter-0' }
const v = (outcome: 'confirmed' | 'disproved' | 'ambiguous', agent = 'v1') => ({ agent, outcome, reasoning: 'r' })

test('adding the same defect twice yields one finding', () => {
  const s = new FindingsStore()
  const a = s.add(base, m)
  const b = s.add({ ...base, line: 41 }, m)
  expect(b.id).toBe(a.id)
  expect(s.list()).toHaveLength(1)
})
test('a finding starts as candidate and keeps its meta', () => {
  const f = new FindingsStore().add(base, m)
  expect(f).toMatchObject({ status: 'candidate', ...meta })
})
test('a confirming verdict promotes to confirmed', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, m).id, v('confirmed')).status).toBe('confirmed')
})
test('a disproving verdict drops the finding', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, m).id, v('disproved')).status).toBe('dropped')
})
test('an ambiguous verdict yields needs-review, never confirmed', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, m).id, v('ambiguous')).status).toBe('needs-review')
})
test('a disproving verdict after a confirming one wins', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, m)
  s.recordVerdict(id, v('confirmed'))
  expect(s.recordVerdict(id, v('disproved', 'v2')).status).toBe('dropped')
})
test('precedence holds for every ordering of the three outcomes', () => {
  const orders = [
    ['confirmed', 'ambiguous', 'disproved'], ['confirmed', 'disproved', 'ambiguous'],
    ['ambiguous', 'confirmed', 'disproved'], ['ambiguous', 'disproved', 'confirmed'],
    ['disproved', 'confirmed', 'ambiguous'], ['disproved', 'ambiguous', 'confirmed'],
  ] as const
  for (const o of orders) {
    const s = new FindingsStore()
    const { id } = s.add(base, m)
    o.forEach((x) => s.recordVerdict(id, v(x)))
    expect(s.get(id)?.status).toBe('dropped')
  }
  const s = new FindingsStore()
  const { id } = s.add(base, m)
  s.recordVerdict(id, v('confirmed'))
  expect(s.recordVerdict(id, v('ambiguous', 'v2')).status).toBe('needs-review')
})
test('re-adding a verdicted finding does not reset it', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, m)
  s.recordVerdict(id, v('disproved'))
  expect(s.add({ ...base, snippet: '  query(a   +   b) ' }, m).status).toBe('dropped')
})
test('list filters by status; unknown id throws', () => {
  const s = new FindingsStore()
  s.recordVerdict(s.add(base, m).id, v('confirmed'))
  s.add({ ...base, file: 'b.ts' }, m)
  expect(s.list({ status: 'confirmed' })).toHaveLength(1)
  expect(s.list({ status: 'candidate' })).toHaveLength(1)
  expect(() => s.recordVerdict('nope', v('confirmed'))).toThrow()
})

describe('reporting agent identity', () => {
  test('add requires a non-blank reporting agent', () => {
    expect(() => new FindingsStore().add(base, { ...meta, reporting_agent: '  ' })).toThrow(/reporting_agent/)
  })
  test('the reporting agent cannot confirm its own finding', () => {
    const s = new FindingsStore()
    const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
    expect(() => s.recordVerdict(f.id, v('confirmed', 'hunter-1'))).toThrow(/reporting agent/)
    expect(s.get(f.id)).toMatchObject({ status: 'candidate', verdicts: [] })
  })
  test('a different agent can confirm it', () => {
    const s = new FindingsStore()
    const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
    expect(s.recordVerdict(f.id, v('confirmed', 'verifier-1')).status).toBe('confirmed')
  })
  test('a second reporter of a deduped finding also cannot confirm it', () => {
    const s = new FindingsStore()
    const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
    s.add({ ...base, line: 41 }, { ...meta, reporting_agent: 'hunter-2' })
    s.add({ ...base, line: 42 }, { ...meta, reporting_agent: 'hunter-2' })
    expect(s.list()).toHaveLength(1)
    expect(s.get(f.id)!.reporting_agents.sort()).toEqual(['hunter-1', 'hunter-2'])
    expect(() => s.recordVerdict(f.id, v('confirmed', 'hunter-2'))).toThrow(/reporting agent/)
  })
  test('padding the agent id does not evade the gate', () => {
    const s = new FindingsStore()
    const f = s.add(base, { ...meta, reporting_agent: ' hunter-1 ' })
    expect(s.get(f.id)!.reporting_agents).toEqual(['hunter-1'])
    expect(() => s.recordVerdict(f.id, v('confirmed', 'hunter-1  '))).toThrow(/reporting agent/)
  })
})

const mk = (status: Finding['status'], band?: Severity['band']): Finding => {
  const f: Finding = { ...base, ...meta, id: 'x', status, verdicts: [], additional_locations: [], reporting_agents: [] }
  if (band) {
    f.severity = { band, score: 0, factors: { exploitability: 0, reachability: 0, blast_radius: 0, data_sensitivity: 0 } }
  }
  return f
}
test('returned findings are copies: mutation cannot change status or erase a disproof', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, m)
  s.recordVerdict(id, v('disproved'))
  const g = s.get(id)!
  g.status = 'confirmed'
  g.verdicts.length = 0
  s.list()[0]!.status = 'confirmed'
  expect(s.get(id)).toMatchObject({ status: 'dropped' })
  expect(s.get(id)!.verdicts).toHaveLength(1)
  expect(s.recordVerdict(id, v('confirmed', 'v2')).status).toBe('dropped')
})
test('an unknown outcome is refused and changes nothing', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, m)
  expect(() => s.recordVerdict(id, { agent: 'a', outcome: 'confirmd' as 'confirmed', reasoning: 'r' })).toThrow(/outcome/)
  expect(s.get(id)).toMatchObject({ status: 'candidate', verdicts: [] })
})
test('extra runtime properties on input are not stored', () => {
  const s = new FindingsStore()
  const sneaky = { ...base, severity: { band: 'critical' }, status: 'confirmed' } as typeof base
  const f = s.add(sneaky, m)
  expect(f.status).toBe('candidate')
  expect(f).not.toHaveProperty('severity')
})
test('empty reachability and empty or whitespace snippets are refused', () => {
  const s = new FindingsStore()
  expect(() => s.add(base, { ...m, reachability: '  ' })).toThrow(/reachability/)
  expect(() => s.add({ ...base, snippet: ' \n\t' }, m)).toThrow(/snippet/)
  expect(s.list()).toHaveLength(0)
})
test('a duplicate at another line keeps its location and reachability as evidence', () => {
  const s = new FindingsStore()
  const a = s.add(base, m)
  s.add({ ...base, line: 90 }, { ...m, reachability: 'cron job passes env value' })
  s.add({ ...base, line: 90 }, { ...m, reachability: 'cron job passes env value' })
  const f = s.get(a.id)!
  expect(s.list()).toHaveLength(1)
  expect(f.line).toBe(40)
  expect(f.additional_locations).toEqual([{ line: 90, reachability: 'cron job passes env value' }])
})

describe('decideExitCode', () => {
  test('at or above threshold exits 1', () => {
    expect(decideExitCode([mk('confirmed', 'high')], 'high')).toBe(1)
    expect(decideExitCode([mk('confirmed', 'critical')], 'high')).toBe(1)
  })
  test('only below threshold exits 0', () => {
    expect(decideExitCode([mk('confirmed', 'medium'), mk('confirmed', 'low')], 'high')).toBe(0)
  })
  test('no findings exits 0', () => expect(decideExitCode([], 'info')).toBe(0))
  test('failOn null always exits 0', () => expect(decideExitCode([mk('confirmed', 'critical')], null)).toBe(0))
  test('needs-review, dropped and candidate never trip it', () => {
    const fs = [mk('needs-review', 'critical'), mk('dropped', 'critical'), mk('candidate', 'critical')]
    expect(decideExitCode(fs, 'info')).toBe(0)
  })
  test('confirmed without severity does not trip', () => expect(decideExitCode([mk('confirmed')], 'info')).toBe(0))
})
