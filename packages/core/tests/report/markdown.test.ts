import type { SkipRecord } from '@sentinel/core'
import { toMarkdown } from '@sentinel/core'
import { agreed, disputed, droppedAfterDispute, findings, profile } from './helpers.js'

test('markdown states the spread on a disputed finding', () => {
  const md = toMarkdown([disputed], profile, { mode: 'full' })
  expect(md).toMatch(/verifiers disagreed/i)
  expect(md).toContain('high')
  expect(md).toContain('low')
  expect(md).toMatch(/verifiers disagreed.*`v1` rated high.*`v2` rated low/i)
})

test('the dispute line shows in pure-reasoning mode too', () => {
  expect(toMarkdown([disputed], profile, { mode: 'pure-reasoning' })).toMatch(/verifiers disagreed/i)
})

test('an undisputed finding says nothing about disagreement', () => {
  expect(toMarkdown([agreed], profile, { mode: 'full' })).not.toMatch(/disagreed/i)
})

test('a finding dropped after a dispute is not listed and reports no disagreement', () => {
  expect(toMarkdown([droppedAfterDispute], profile, { mode: 'full' })).not.toMatch(/disagreed/i)
})

const REASONS: SkipRecord['reason'][] = ['minified', 'vendored', 'generated', 'binary', 'too-large', 'not-utf8', 'not-regular', 'unreadable', 'symlink']

test('pure-reasoning mode prints the coverage banner', () => {
  const md = toMarkdown(findings, profile, { mode: 'pure-reasoning' })
  expect(md).toMatch(/dependency CVE/i)
  expect(md).toMatch(/secret/i)
})

// A Phase 2 caller that passes warnings must not have to prepend the banner itself.
test('warnings are rendered as a banner above the report, by toMarkdown itself', () => {
  const md = toMarkdown([], profile, { mode: 'full', warnings: ['No hunter agents exist in this build.', 'Of 6 files scanned, 1 carries a language Sentinel recognises.'] })
  expect(md.split('\n')[0]).toMatch(/^> \*\*Coverage warnings \(read before trusting this report\):\*\*/)
  expect(md).toMatch(/^> - No hunter agents exist in this build\.$/m)
  expect(md).toMatch(/^> - Of 6 files scanned, 1 carries a language Sentinel recognises\.$/m)
  expect(md.indexOf('Coverage warnings')).toBeLessThan(md.indexOf('# Sentinel security report'))
})

test('no warnings means no banner', () => {
  expect(toMarkdown([], profile, { mode: 'full', warnings: [] })).not.toMatch(/Coverage warnings/)
  expect(toMarkdown([], profile, { mode: 'full' })).not.toMatch(/Coverage warnings/)
})

test('full mode prints no coverage banner', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md).not.toMatch(/dependency CVE/i)
  expect(md).not.toMatch(/pure-reasoning/i)
})

test('every finding renders both a plain and an engineer section', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md.match(/What this means/g)).toHaveLength(3) // two confirmed + one needs-review
  expect(md.match(/Technical detail/g)).toHaveLength(3)
})

test('reports skipped files and truncation so coverage is not overstated', () => {
  const md = toMarkdown(findings, { ...profile, truncated: true }, { mode: 'full' })
  expect(md).toMatch(/not scanned|truncated/i)
})

test('truncation with zero findings is not a clean report', () => {
  const md = toMarkdown([], { ...profile, truncated: true }, { mode: 'full' })
  expect(md).toMatch(/truncated/i)
  expect(md).not.toMatch(/no issues|all clear|clean/i)
})

// M1: an in-tree symlink target can carry its own skip reason, so "nothing was missed" was false.
test('the in-tree symlink text claims no completeness', () => {
  const md = toMarkdown([], { ...profile, skipped: [{ path: 'packages/shared', reason: 'symlink' }] }, { mode: 'full' })
  expect(md).not.toMatch(/nothing was missed/)
  expect(md).toMatch(/examined at its real path \(any files within it skipped for other reasons are listed separately\)/)
})

test('a profile where everything was skipped says nothing was scanned', () => {
  const md = toMarkdown([], { ...profile, file_count: 0, skipped: [{ path: 'a', reason: 'binary' }] }, { mode: 'full' })
  expect(md).toMatch(/no files were scanned/i)
})

test('a needs-review finding is never labelled confirmed', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  const split = md.indexOf('## Needs review')
  const review = md.slice(split)
  expect(split).toBeGreaterThan(-1)
  expect(review).toContain('ssrf')
  expect(md.slice(0, split)).not.toContain('ssrf')
  expect(review).toMatch(/not confirmed/i)
  expect(review).not.toMatch(/\bconfirmed (finding|issue)/i)
})

test('dropped findings are counted but not listed', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md).not.toContain('csrf')
  expect(md).toMatch(/1 .*disproved/i)
})

test('additional locations are rendered', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md).toContain('Also at')
  expect(md).toContain('line 90')
  expect(md).toContain('second sink in admin route')
})

test('all nine skip reasons render, each with its count', () => {
  const skipped = REASONS.map((reason) => ({ path: `p-${reason}`, reason }))
  const md = toMarkdown([], { ...profile, skipped }, { mode: 'full' })
  for (const r of REASONS) expect(md, r).toContain(`\`${r}\``)
  expect(md).not.toMatch(/undefined/)
})

test('symlink is rendered as declined scope, distinct from unreadable', () => {
  const md = toMarkdown([], { ...profile, skipped: [{ path: 'packages/shared', reason: 'symlink' }, { path: 'x', reason: 'unreadable' }] }, { mode: 'full' })
  const line = (r: string): string => md.split('\n').find((l) => l.includes(`\`${r}\``)) ?? ''
  expect(line('symlink')).toMatch(/outside the scanned folder/i)
  expect(line('symlink')).toMatch(/declined/i)
  expect(line('symlink')).not.toBe(line('unreadable'))
  expect(md).toContain('packages/shared')
})

test('agent-written text cannot break out of its code fence or quote', () => {
  const evil = { ...findings[0]!, snippet: 'a ``` b\n# Injected', verdicts: [{ agent: 'v', outcome: 'confirmed' as const, reasoning: 'ok\n# Fake heading' }] }
  const md = toMarkdown([evil], profile, { mode: 'full' })
  expect(md).not.toMatch(/^# Fake heading/m)
  // The snippet holds a ``` run, so its fence must be longer than that or it would close early.
  expect(md).toContain('````\na ``` b\n# Injected\n````')
})
