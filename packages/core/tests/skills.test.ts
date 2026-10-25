import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const read = (f: string): string => readFileSync(resolve(repoRoot, f), 'utf8')
const HUNT = 'skills/sentinel-hunt/SKILL.md'
const VERIFY = 'skills/sentinel-verify/SKILL.md'

test.each([
  [HUNT, 'sentinel-hunt'],
  [VERIFY, 'sentinel-verify'],
])('%s exists with frontmatter naming it', (f, name) => {
  const m = read(f).match(/^---\nname: (.+)\ndescription: (.+)\n---\n/)
  expect(m).not.toBeNull()
  expect(m![1]).toBe(name)
  expect(m![2]!.length).toBeGreaterThan(20)
})

test('the hunter skill tells the agent to supply its own identity', () => {
  expect(read(HUNT)).toMatch(/reporting_agent/)
})

test('the hunter skill reads technique prose via registry_root and keeps the coverage wording', () => {
  const t = read(HUNT)
  expect(t).toMatch(/registry_root/)
  expect(t).toMatch(/never a filter/i)
  expect(t).toMatch(/nothing was examined[\s\S]*does not mean the domain is clean/i)
  expect(t).toMatch(/file:line/)
})

test('the verifier skill states that ambiguous is a valid answer', () => {
  expect(read(VERIFY)).toMatch(/ambiguous/i)
})

test('the verifier skill requires an id different from the reporter', () => {
  expect(read(VERIFY)).toMatch(/different|must not.*same/i)
})

test.each([HUNT, VERIFY])('%s stays thin (spec 5.2/6.3)', (f) => {
  expect(read(f).split('\n').length).toBeLessThanOrEqual(60)
})
