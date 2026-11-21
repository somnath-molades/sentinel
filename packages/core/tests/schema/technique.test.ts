import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parseTechnique } from '../../src/schema/technique.js'

const dir = fileURLToPath(new URL('../../../../tests/fixtures/registry/', import.meta.url))
const read = (f: string): string => readFileSync(dir + f, 'utf8')

function fail(file: string, md: string) {
  const r = parseTechnique(md, file)
  if (r.ok) throw new Error('expected failure')
  return r.error
}

test('parses a valid technique entry', () => {
  const r = parseTechnique(read('valid-technique.md'), 'valid-technique.md')
  if (!r.ok) throw new Error(r.error.problem)
  expect(r.value.id).toBe('sql-injection-string-concat')
  expect(r.value.depth_tier).toBe('L1')
  expect(r.value.fix_patterns).toHaveLength(2)
  expect(r.value.defensive_use).toMatch(/bind values/)
})

test('rejects an entry with no defensive_use', () => {
  const e = fail('missing-defensive-use.md', read('missing-defensive-use.md'))
  expect(e.problem).toMatch(/defensive_use/)
  expect(e.file).toBe('missing-defensive-use.md')
})

test('rejects an entry with an empty defensive_use section', () => {
  const md = read('missing-defensive-use.md') + '\n## Defensive use\n\n   \n'
  expect(fail('x.md', md).problem).toMatch(/defensive_use/)
})

test('defensive_use in frontmatter does not satisfy the requirement', () => {
  const md = read('missing-defensive-use.md').replace('depth_tier: L1', 'depth_tier: L1\ndefensive_use: Proves a real flaw and shows the fix.')
  const e = fail('x.md', md)
  expect(e.problem).toMatch(/defensive_use.*body/)
})

test.each([
  ['frontmatter', (md: string) => md.replace('depth_tier: L1', 'depth_tier: L1\ndefensive_use: "   "')],
  ['body section', (md: string) => md + '\n## Defensive use\n\n   \n'],
])('whitespace-only defensive_use via %s is rejected', (_route, mutate) => {
  expect(fail('x.md', mutate(read('missing-defensive-use.md'))).problem).toMatch(/defensive_use/)
})

test('rejects unknown frontmatter keys, matching the published JSON Schema', () => {
  const md = read('valid-technique.md').replace('depth_tier: L1', 'depth_tier: L1\ncew: [CWE-89]')
  expect(fail('x.md', md).problem).toMatch(/cew/)
})

test('rejects unknown keys in nested objects too', () => {
  const md = read('valid-technique.md').replace('  pack: example-pack', '  pack: example-pack\n  packs: typo')
  expect(fail('x.md', md).problem).toMatch(/packs/)
})

test('rejects an entry with no fix_patterns', () => {
  const md = read('valid-technique.md').replace(/fix_patterns:[\s\S]*?references:/, 'fix_patterns: []\nreferences:')
  expect(fail('x.md', md).problem).toMatch(/fix_pattern/)
})

test('rejects an unknown depth_tier', () => {
  const md = read('valid-technique.md').replace('depth_tier: L1', 'depth_tier: L9')
  expect(fail('x.md', md).problem).toMatch(/L9/)
})

test('rejects a file with no frontmatter', () => {
  expect(fail('x.md', '# just prose\n').problem).toMatch(/frontmatter/)
})

test('malformed YAML reports the file, does not throw', () => {
  expect(() => parseTechnique(read('bad-yaml.md'), 'bad-yaml.md')).not.toThrow()
  const r = parseTechnique(read('bad-yaml.md'), 'bad-yaml.md')
  expect(r.ok).toBe(false)
  if (!r.ok) expect(r.error.file).toBe('bad-yaml.md')
})

test('an entry with no domain is rejected', () => {
  expect(fail('missing-domain.md', read('missing-domain.md')).problem).toMatch(/domain/)
})

test('an unknown domain is rejected and the message names the value and the allowed set', () => {
  const { problem } = fail('unknown-domain.md', read('unknown-domain.md'))
  expect(problem).toContain('web-security')
  expect(problem).toContain('memory-safety')
})
