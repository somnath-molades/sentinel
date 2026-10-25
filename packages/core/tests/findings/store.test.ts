import { FindingsStore, decideExitCode, type Finding, type Severity } from '@sentinel/core'

const base = { technique_id: 'sqli', file: 'a.ts', line: 40, snippet: 'query(a + b)' }
const meta = { depth_tier: 'L1' as const, reachability: 'handler reads req.body' }
const v = (outcome: 'confirmed' | 'disproved' | 'ambiguous', agent = 'v1') => ({ agent, outcome, reasoning: 'r' })

test('adding the same defect twice yields one finding', () => {
  const s = new FindingsStore()
  const a = s.add(base, meta)
  const b = s.add({ ...base, line: 41 }, meta)
  expect(b.id).toBe(a.id)
  expect(s.list()).toHaveLength(1)
})
test('a finding starts as candidate and keeps its meta', () => {
  const f = new FindingsStore().add(base, meta)
  expect(f).toMatchObject({ status: 'candidate', ...meta })
})
test('a confirming verdict promotes to confirmed', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, meta).id, v('confirmed')).status).toBe('confirmed')
})
test('a disproving verdict drops the finding', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, meta).id, v('disproved')).status).toBe('dropped')
})
test('an ambiguous verdict yields needs-review, never confirmed', () => {
  const s = new FindingsStore()
  expect(s.recordVerdict(s.add(base, meta).id, v('ambiguous')).status).toBe('needs-review')
})
test('a disproving verdict after a confirming one wins', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, meta)
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
    const { id } = s.add(base, meta)
    o.forEach((x) => s.recordVerdict(id, v(x)))
    expect(s.get(id)?.status).toBe('dropped')
  }
  const s = new FindingsStore()
  const { id } = s.add(base, meta)
  s.recordVerdict(id, v('confirmed'))
  expect(s.recordVerdict(id, v('ambiguous', 'v2')).status).toBe('needs-review')
})
test('re-adding a verdicted finding does not reset it', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, meta)
  s.recordVerdict(id, v('disproved'))
  expect(s.add({ ...base, snippet: '  query(a   +   b) ' }, meta).status).toBe('dropped')
})
test('list filters by status; unknown id throws', () => {
  const s = new FindingsStore()
  s.recordVerdict(s.add(base, meta).id, v('confirmed'))
  s.add({ ...base, file: 'b.ts' }, meta)
  expect(s.list({ status: 'confirmed' })).toHaveLength(1)
  expect(s.list({ status: 'candidate' })).toHaveLength(1)
  expect(() => s.recordVerdict('nope', v('confirmed'))).toThrow()
})

const mk = (status: Finding['status'], band?: Severity['band']): Finding => {
  const f: Finding = { ...base, ...meta, id: 'x', status, verdicts: [], additional_locations: [] }
  if (band) {
    f.severity = { band, score: 0, factors: { exploitability: 0, reachability: 0, blast_radius: 0, data_sensitivity: 0 } }
  }
  return f
}
test('returned findings are copies: mutation cannot change status or erase a disproof', () => {
  const s = new FindingsStore()
  const { id } = s.add(base, meta)
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
  const { id } = s.add(base, meta)
  expect(() => s.recordVerdict(id, { agent: 'a', outcome: 'confirmd' as 'confirmed', reasoning: 'r' })).toThrow(/outcome/)
  expect(s.get(id)).toMatchObject({ status: 'candidate', verdicts: [] })
})
test('extra runtime properties on input are not stored', () => {
  const s = new FindingsStore()
  const sneaky = { ...base, severity: { band: 'critical' }, status: 'confirmed' } as typeof base
  const f = s.add(sneaky, meta)
  expect(f.status).toBe('candidate')
  expect(f).not.toHaveProperty('severity')
})
test('empty reachability and empty or whitespace snippets are refused', () => {
  const s = new FindingsStore()
  expect(() => s.add(base, { ...meta, reachability: '  ' })).toThrow(/reachability/)
  expect(() => s.add({ ...base, snippet: ' \n\t' }, meta)).toThrow(/snippet/)
  expect(s.list()).toHaveLength(0)
})
test('a duplicate at another line keeps its location and reachability as evidence', () => {
  const s = new FindingsStore()
  const a = s.add(base, meta)
  s.add({ ...base, line: 90 }, { ...meta, reachability: 'cron job passes env value' })
  s.add({ ...base, line: 90 }, { ...meta, reachability: 'cron job passes env value' })
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
