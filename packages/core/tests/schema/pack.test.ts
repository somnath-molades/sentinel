import { packSchema } from '../../src/schema/pack.js'

const base = {
  id: 'example-pack',
  name: 'Example Pack',
  source_url: 'https://example.com/repo',
  license: 'MIT',
  ingestion_mode: 'vendored',
  coverage: ['L1'],
  trust_tier: 'reviewed',
}

test('accepts a vendored pack with a stated license', () => {
  expect(packSchema.safeParse(base).success).toBe(true)
})

test('rejects a pack whose license is unstated with ingestion_mode vendored', () => {
  const r = packSchema.safeParse({ ...base, license: 'UNSTATED', ingestion_mode: 'vendored' })
  expect(r.success).toBe(false)
  if (!r.success) expect(JSON.stringify(r.error.issues)).toMatch(/vendored/)
})

test('rejects a vendored pack with no license', () => {
  const { license: _l, ...noLicense } = base
  expect(packSchema.safeParse(noLicense).success).toBe(false)
})

test('allows an unstated license when not vendored', () => {
  expect(packSchema.safeParse({ ...base, license: 'UNSTATED', ingestion_mode: 'external' }).success).toBe(true)
})
