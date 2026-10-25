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

// Skill-to-tool drift: every backticked identifier in a skill must exist in the tool code, so a rename
// in tools.ts or server.ts cannot leave the skills confidently wrong under a green suite.
const toolsSrc = read('packages/mcp/src/tools.ts')
const serverSrc = read('packages/mcp/src/server.ts')
// Input side only: severityFactorsSchema, findingSchema, agentId and `inputs` (up to the State type).
const inputSide = toolsSrc.slice(toolsSrc.indexOf('const severityFactorsSchema'), toolsSrc.indexOf('type State'))
const TOOL_NAMES = ['plan_hunts', 'record_finding', 'verify_finding', 'profile_target']
const EXCLUDED = new Set([
  // plan_hunts OUTPUT fields: they are read by the agent, not sent, so they are not in inputs/findingSchema.
  'domain', 'path', 'techniques', 'reason', 'hotspot_paths', 'registry_root', 'registry_warning',
  // Section headings of a technique file, which are registry content, not tool fields.
  '## Detection', '## Verification',
])

test.each([HUNT, VERIFY])('%s: every backticked identifier is a real tool, input field or known output field', (f) => {
  const ids = [...new Set([...read(f).matchAll(/`([^`]+)`/g)].map((m) => m[1]!))]
  expect(ids.length).toBeGreaterThan(5)
  const unknown = ids.filter((id) => {
    if (EXCLUDED.has(id)) return false
    if (TOOL_NAMES.includes(id)) return !serverSrc.includes(`registerTool('${id}'`)
    return !new RegExp(`\\b${id}\\b`).test(inputSide)
  })
  expect(unknown).toEqual([])
})

test.each([HUNT, VERIFY])('%s limits the agent to static reading', (f) => {
  expect(read(f)).toMatch(/do not execute the target's code/i)
})

test('the hunter says where the target comes from and that the assignment has no file list', () => {
  expect(read(HUNT)).toMatch(/no file list/i)
  expect(read(HUNT)).toMatch(/profile_target/)
})

test('the verifier says the dispatcher supplies the candidate and reporter id', () => {
  expect(read(VERIFY)).toMatch(/dispatcher supplies/i)
})

test.each([HUNT, VERIFY])('%s stays thin (spec 5.2/6.3)', (f) => {
  expect(read(f).split('\n').length).toBeLessThanOrEqual(60)
})
