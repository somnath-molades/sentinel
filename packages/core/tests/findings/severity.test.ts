import { computeSeverity, type SeverityFactors } from '@sentinel/core'

const base: SeverityFactors = { exploitability: 1, reachability: 1, blast_radius: 1, data_sensitivity: 1 }

test('maximum factors are critical', () => {
  expect(computeSeverity({ exploitability:3, reachability:3, blast_radius:3, data_sensitivity:3 }))
    .toMatchObject({ band: 'critical', score: 30 })
})

test('unreachable code still scores high, not critical', () => {
  const s = computeSeverity({ exploitability:3, reachability:0, blast_radius:3, data_sensitivity:3 })
  expect(s.score).toBe(21)
  expect(s.band).toBe('high')
})

test('all-zero factors are info', () => {
  expect(computeSeverity({ exploitability:0, reachability:0, blast_radius:0, data_sensitivity:0 }).band).toBe('info')
})

test('depth tier does not appear in the computation', () => {
  // spec 4.1: the parameter type has no tier field, and a tier passed at runtime is not carried into the result
  // @ts-expect-error depth_tier is not a severity input
  const withTier = computeSeverity({ ...base, depth_tier: 'L1' })
  expect(Object.keys(withTier.factors).sort())
    .toEqual(['blast_radius','data_sensitivity','exploitability','reachability'])
  expect(Object.keys(computeSeverity(base).factors).sort())
    .toEqual(['blast_radius','data_sensitivity','exploitability','reachability'])
})

test('returns the factors that produced the band', () => {
  expect(computeSeverity({ exploitability:2, reachability:1, blast_radius:0, data_sensitivity:3 }).factors)
    .toEqual({ exploitability:2, reachability:1, blast_radius:0, data_sensitivity:3 })
})

// score = 3*(exploitability+reachability) + 2*(blast_radius+data_sensitivity)
test.each([
  [{ exploitability:3, reachability:3, blast_radius:3, data_sensitivity:0 }, 24, 'critical'],
  [{ exploitability:3, reachability:2, blast_radius:2, data_sensitivity:2 }, 23, 'high'],
  [{ exploitability:3, reachability:0, blast_radius:2, data_sensitivity:2 }, 17, 'high'],
  [{ exploitability:2, reachability:2, blast_radius:1, data_sensitivity:1 }, 16, 'medium'],
  [{ exploitability:1, reachability:1, blast_radius:1, data_sensitivity:1 }, 10, 'medium'],
  [{ exploitability:3, reachability:0, blast_radius:0, data_sensitivity:0 }, 9, 'low'],
  [{ exploitability:0, reachability:0, blast_radius:1, data_sensitivity:1 }, 4, 'low'],
  [{ exploitability:1, reachability:0, blast_radius:0, data_sensitivity:0 }, 3, 'info'],
] as const)('factors %j score %i bands as %s', (factors, score, band) => {
  expect(computeSeverity({ ...factors })).toMatchObject({ band, score })
})
