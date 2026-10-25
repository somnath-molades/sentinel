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
// Output side: keys of HuntAssignment and IndexedTechnique read from their type declarations, plus the
// top-level plan_hunts result keys, each required to appear in the `return ok({...})` line that builds it.
const keysOf = (src: string, decl: string): string[] => {
  const start = src.indexOf(decl)
  const body = src.slice(start, src.indexOf('\n}', start))
  return [...body.matchAll(/^\s+(\w+)\??:/gm)].map((m) => m[1]!)
}
const planSrc = read('packages/core/src/hunt/plan-hunts.ts')
const indexSrc = read('packages/core/src/registry/build-index.ts')
const okLine = toolsSrc.split('\n').find((l) => l.includes('return ok({ registry_root')) ?? ''
const TOP_LEVEL = ['assignments', 'registry_root', 'target_root', 'registry_warning'].filter((k) => new RegExp(`\\b${k}\\b`).test(okLine))
const outputSide = new Set([...keysOf(planSrc, 'export type HuntAssignment'), ...keysOf(indexSrc, 'export type IndexedTechnique'), ...TOP_LEVEL])
const EXCLUDED = new Set([
  // Section headings of a technique file: registry content, not a field of any tool input or output.
  '## Detection', '## Verification',
])

test.each([HUNT, VERIFY])('%s: every backticked identifier is a real tool, input field or known output field', (f) => {
  const ids = [...new Set([...read(f).matchAll(/`([^`]+)`/g)].map((m) => m[1]!))]
  expect(ids.length).toBeGreaterThan(5)
  const unknown = ids.filter((id) => {
    if (EXCLUDED.has(id)) return false
    if (TOOL_NAMES.includes(id)) return !serverSrc.includes(`registerTool('${id}'`)
    return !outputSide.has(id) && !new RegExp(`\\b${id}\\b`).test(inputSide)
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
