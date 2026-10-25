import { fingerprint } from '@sentinel/core'

const base = { technique_id: 'sqli', file: 'a.ts', line: 40, snippet: 'query(a + b)' }

test('same defect at a different line fingerprints identically', () => {
  expect(fingerprint({ ...base, line: 41 })).toBe(fingerprint(base))
})
test('whitespace runs and surrounding whitespace do not change it', () => {
  expect(fingerprint({ ...base, snippet: '\t query(a  +\n  b)\n' })).toBe(fingerprint(base))
})
test('a different technique fingerprints differently', () => {
  expect(fingerprint({ ...base, technique_id: 'xss' })).not.toBe(fingerprint(base))
})
test('a different file fingerprints differently', () => {
  expect(fingerprint({ ...base, file: 'b.ts' })).not.toBe(fingerprint(base))
})
test('is 16 hex chars', () => {
  expect(fingerprint(base)).toMatch(/^[0-9a-f]{16}$/)
})
test('field boundaries cannot collide', () => {
  expect(fingerprint({ ...base, technique_id: 'a', file: 'b c' })).not.toBe(
    fingerprint({ ...base, technique_id: 'a b', file: 'c' }),
  )
})
test('token-internal whitespace is significant', () => {
  expect(fingerprint({ ...base, snippet: 'query(ab)' })).not.toBe(fingerprint({ ...base, snippet: 'query(a b)' }))
})
