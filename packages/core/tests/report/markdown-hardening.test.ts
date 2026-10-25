import { toMarkdown } from '@sentinel/core'
import { findings, profile } from './helpers.js'

test('unconfirmed blocks are not written as established fact', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  const review = md.slice(md.indexOf('## Needs review'), md.indexOf('## Coverage'))
  expect(review).toContain('Possible weakness, not verified')
  expect(review).toContain('Tentative rating, only if it is real')
  expect(review).not.toMatch(/Sentinel found a weakness|Rated \*\*/)
  expect(md.slice(0, md.indexOf('## Needs review'))).toContain('Sentinel found a weakness')
})

test('candidates get their own UNVERIFIED section, never in the confirmed list', () => {
  const cand = { ...findings[0]!, id: 'x', status: 'candidate' as const, technique_id: 'idor', verdicts: [] }
  const md = toMarkdown([cand], profile, { mode: 'full' })
  expect(md).toContain('## Not yet verified')
  expect(md).toContain('[UNVERIFIED]')
  expect(md.slice(0, md.indexOf('## Not yet verified'))).not.toContain('idor')
  expect(md).toMatch(/Confirmed: 0/)
})

test('a confirmed finding with no severity lands under Unrated', () => {
  const { severity: _s, ...unrated } = findings[0]!
  const md = toMarkdown([unrated], profile, { mode: 'full' })
  expect(md).toContain('### Unrated')
  expect(md).toContain('1 unrated')
})

test('more than ten skipped paths are truncated with a count', () => {
  const skipped = Array.from({ length: 13 }, (_, i) => ({ path: `v/${i}.js`, reason: 'vendored' as const }))
  const md = toMarkdown([], { ...profile, skipped }, { mode: 'full' })
  expect(md).toContain('and 3 more')
  expect(md).toContain('13 not scanned')
})

test('the report says explanation and standards references are not yet available', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md.match(/explanation for this type of weakness is not available/g)).toHaveLength(3)
  expect(md.match(/Standards references \(CWE and others\): not available/g)).toHaveLength(3)
})

test('the summary calls out symlinks that were not followed', () => {
  const md = toMarkdown([], { ...profile, skipped: [{ path: 'packages/shared', reason: 'symlink' }] }, { mode: 'full' })
  const summary = md.slice(md.indexOf('## Summary'), md.indexOf('## Confirmed'))
  expect(summary).toMatch(/1 symlink .*NOT followed/)
})
