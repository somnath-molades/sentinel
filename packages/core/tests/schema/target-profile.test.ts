import { targetProfileSchema } from '../../src/schema/target-profile.js'

const minimalProfile = {
  schema_version: 1,
  target: { kind: 'local', root: '/tmp/app' },
  generated_at: '2026-10-25T00:00:00.000Z',
  languages: [{ language: 'typescript', files: 3, bytes: 1200 }],
  frameworks: ['express'],
  entrypoints: [{ path: 'src/server.ts', kind: 'http-route' }],
  auth_surfaces: [],
  data_layer: [],
  iac: [],
  ci: [],
  client_boundary: [],
  hotspots: [{ path: 'src/server.ts', reason: 'handles requests', domains: ['web'] }],
  skipped: [{ path: 'dist/app.min.js', reason: 'minified' }],
  file_count: 4,
  truncated: false,
}

test('accepts a minimal profile', () => {
  expect(targetProfileSchema.safeParse(minimalProfile).success).toBe(true)
})

test('rejects an unknown skip reason', () => {
  const p = { ...minimalProfile, skipped: [{ path: 'a.js', reason: 'because' }] }
  expect(targetProfileSchema.safeParse(p).success).toBe(false)
})

test('rejects a missing schema_version', () => {
  const { schema_version: _omit, ...p } = minimalProfile
  expect(targetProfileSchema.safeParse(p).success).toBe(false)
})

test('accepts an empty profile for a repo with no detected stack', () => {
  const p = { ...minimalProfile, languages: [], frameworks: [], entrypoints: [], hotspots: [], skipped: [], file_count: 0 }
  expect(targetProfileSchema.safeParse(p).success).toBe(true)
})

test('rejects unknown keys at top level and nested', () => {
  expect(targetProfileSchema.safeParse({ ...minimalProfile, framworks: [] }).success).toBe(false)
  const nested = { ...minimalProfile, languages: [{ language: 'go', files: 1, bytes: 1, extra: 1 }] }
  expect(targetProfileSchema.safeParse(nested).success).toBe(false)
  const target = { ...minimalProfile, target: { kind: 'local', root: '/x', extra: 1 } }
  expect(targetProfileSchema.safeParse(target).success).toBe(false)
})

test('requires skipped and truncated so coverage gaps cannot be silently omitted', () => {
  const { skipped: _s, ...noSkipped } = minimalProfile
  const { truncated: _t, ...noTruncated } = minimalProfile
  expect(targetProfileSchema.safeParse(noSkipped).success).toBe(false)
  expect(targetProfileSchema.safeParse(noTruncated).success).toBe(false)
})

test('rejects an unknown entrypoint kind and a wrong schema_version', () => {
  expect(targetProfileSchema.safeParse({ ...minimalProfile, entrypoints: [{ path: 'a', kind: 'rpc' }] }).success).toBe(false)
  expect(targetProfileSchema.safeParse({ ...minimalProfile, schema_version: 2 }).success).toBe(false)
})
