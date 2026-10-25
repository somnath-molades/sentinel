import type { LangStat, TargetProfile } from '@sentinel/core'
import { coverageGap } from '@sentinel/core'

const profile = (file_count: number, languages: LangStat[], truncated = false): TargetProfile => ({
  schema_version: 1,
  target: { kind: 'local', root: '/x' },
  generated_at: '2026-10-24T00:00:00.000Z',
  languages,
  frameworks: [],
  entrypoints: [],
  auth_surfaces: [],
  data_layer: [],
  iac: [],
  ci: [],
  client_boundary: [],
  hotspots: [],
  skipped: [],
  file_count,
  truncated,
})
const text = (g: ReturnType<typeof coverageGap>): string => g.warnings.map((w) => w.text).join(' ')
const lang = (language: string, files: number): LangStat => ({ language, files, bytes: files * 10 })

// The governing failure mode: one recognised file used to derive a stack and silence every coverage warning.
test('one recognised file beside unrecognised ones still warns, and names the unexamined share', () => {
  const g = coverageGap(profile(6, [lang('javascript', 1)]))
  expect(g.stacks).toEqual(['node'])
  expect(g.unmapped_languages).toEqual([]) // exactly why the old language-based derivation went quiet
  expect(g.files_without_language).toBe(5)
  expect(text(g)).toMatch(/Of 6 files scanned, 1 carries a language Sentinel recognises/)
  expect(text(g)).toMatch(/5 \(83%\)/)
  expect(text(g)).toMatch(/NOT a clean result/)
})

test('one recognised file among a hundred reports the share, not a clean scan', () => {
  const g = coverageGap(profile(101, [lang('python', 1)]))
  expect(text(g)).toMatch(/Of 101 files scanned, 1 carries/)
  expect(text(g)).toMatch(/100 \(99%\)/)
})

test('a fully recognised tree produces no coverage-gap warning', () => {
  expect(coverageGap(profile(3, [lang('typescript', 2), lang('python', 1)])).warnings).toEqual([])
})

test('a tree with no recognised language warns that no stack could be derived and that nothing was examined', () => {
  const g = coverageGap(profile(4, []))
  expect(g.stacks).toEqual([])
  expect(text(g)).toMatch(/No stack could be derived/)
  expect(text(g)).toMatch(/Of 4 files scanned, 0 carry/)
})

test('an empty target warns about the stack and divides by nothing', () => {
  const g = coverageGap(profile(0, []))
  expect(g.files_without_language).toBe(0)
  expect(text(g)).toMatch(/No stack could be derived/)
  expect(text(g)).not.toMatch(/NaN|Infinity/)
})

test('a present language with no stack is named as not examined', () => {
  const g = coverageGap(profile(2, [lang('rust', 1), lang('python', 1)]))
  expect(g.unmapped_languages).toEqual(['rust'])
  expect(text(g)).toMatch(/No technique stack exists for: rust/)
})

// Truncation is coverage loss like any other: the gate must not be able to pass on a scan that walked 5 of 50,000 files.
test('truncation is a coverage warning', () => {
  const g = coverageGap(profile(2, [lang('javascript', 2)], true))
  expect(text(g)).toMatch(/file limit was reached/)
  expect(g.warnings.every((w) => w.blocks)).toBe(true) // truncation blocks a gate
  expect(coverageGap(profile(2, [lang('javascript', 2)], false)).warnings).toEqual([])
})

// Which warnings block a gate: the share warning does not, because almost every repository has a README.
test('the no-stack warning blocks a gate and the unexamined-share warning does not', () => {
  expect(coverageGap(profile(6, [lang('javascript', 1)])).warnings).toEqual([{ text: expect.stringMatching(/Of 6 files scanned/), blocks: false }])
  expect(coverageGap(profile(2, [])).warnings.filter((w) => w.blocks).map((w) => w.text)).toEqual([expect.stringMatching(/No stack could be derived/)])
})
