import type { Finding } from '../findings/store.js'
import { BAND_RANK, type Severity } from '../findings/severity.js'
import type { SkipRecord, TargetProfile } from '../schema/target-profile.js'

// Everything below that comes from agents or the filesystem is untrusted text: it is kept on
// one line, inside a code span, or inside a blockquote/fence, so it cannot forge report structure.
const oneLine = (s: string): string => s.replace(/\s+/g, ' ').trim()
const inline = (s: string): string => `\`${oneLine(s).replaceAll('`', "'")}\``
const quote = (s: string, indent = ''): string => s.split(/\r?\n/).map((l) => `${indent}> ${l}`).join('\n')
function fence(s: string): string {
  const longest = Math.max(2, ...(s.match(/`+/g) ?? []).map((m) => m.length))
  const f = '`'.repeat(longest + 1)
  return `${f}\n${s}\n${f}`
}

const BANDS = (Object.keys(BAND_RANK) as Severity['band'][]).sort((a, b) => BAND_RANK[b] - BAND_RANK[a])
const cap = (s: string): string => s[0]!.toUpperCase() + s.slice(1)

// Order matters: declined scope first, because it is the gap most likely to hide a lot of real code.
const SKIP_TEXT: Record<SkipRecord['reason'], string> = {
  symlink:
    '**Declined scope.** Shortcuts (symbolic links) that Sentinel declined to follow because they lead outside the scanned folder. What they point to was NOT examined. In a monorepo (for example `packages/shared -> ../../shared`) that can be a large share of your real code. Scan the folder they point to directly to include it.',
  'too-large': 'Files over the size limit. Not examined. Large files can hold anything, so review them by hand or split them up.',
  unreadable: 'Files Sentinel could not open or read (permissions or a read error). Not examined. Fix the access problem and scan again.',
  'not-utf8': 'Text files in an encoding Sentinel cannot read. Not examined. Convert them to UTF-8 to include them.',
  'not-regular': 'Special entries that are not ordinary files (pipes, devices, sockets). Not examined; these are not normally source code.',
  vendored: 'Third-party code copied into the project (such as `node_modules` or `vendor` folders). Not examined. Known problems in libraries need a dependency check, not this scan.',
  generated: 'Machine-generated files. Not examined. Problems in them usually come from the source they were generated from.',
  minified: 'Minified code (squashed into a few unreadable lines). Not examined. Scan the original source instead.',
  binary: 'Non-text files such as images or compiled programs. Not examined.',
}
const SKIP_ORDER = Object.keys(SKIP_TEXT) as SkipRecord['reason'][]
const MAX_PATHS = 10

const EASE = ['very hard to misuse', 'hard to misuse', 'moderately easy to misuse', 'easy to misuse']
const EXPOSURE = ['not reachable from outside', 'hard to reach from outside', 'reachable by some users', 'reachable by anyone']
const SPREAD = ['affects one small thing', 'affects one feature', 'affects much of the product', 'affects the whole product']
const DATA = ['no sensitive data involved', 'low-sensitivity data', 'private user or business data', 'secrets, credentials or payment data']

function findingBlock(f: Finding, label: string): string {
  const where = `${inline(f.file)} line ${f.line}`
  const out: string[] = [`#### ${label}${inline(f.technique_id)} in ${where}`, '']
  const s = f.severity
  out.push('**What this means**', '')
  out.push(`Sentinel found a weakness of type ${inline(f.technique_id)} in ${inline(f.file)}, near line ${f.line}.`)
  out.push(`How the risky code is reached: ${oneLine(f.reachability)}.`)
  if (s) {
    const fa = s.factors
    out.push(`Rated **${s.band}**: it is ${EASE[fa.exploitability]}, ${EXPOSURE[fa.reachability]}, ${SPREAD[fa.blast_radius]}, and involves ${DATA[fa.data_sensitivity]}.`)
  } else {
    out.push('This finding has not been given a severity rating.')
  }
  out.push('', '**Technical detail**', '')
  out.push(`- Technique: ${inline(f.technique_id)} (depth tier ${f.depth_tier})`)
  out.push(`- Location: ${where}`)
  if (s) {
    const fa = s.factors
    out.push(`- Severity: ${s.band}, score ${s.score} (exploitability ${fa.exploitability}/3, reachability ${fa.reachability}/3, blast radius ${fa.blast_radius}/3, data sensitivity ${fa.data_sensitivity}/3)`)
  }
  for (const a of f.additional_locations) out.push(`- Also at ${inline(f.file)} line ${a.line}: ${oneLine(a.reachability)}`)
  out.push(`- Finding id: ${inline(f.id)}`)
  out.push('', fence(f.snippet), '')
  if (f.verdicts.length) {
    out.push('Verification:')
    for (const v of f.verdicts) out.push(`- ${inline(v.agent)} said **${v.outcome}**:`, quote(v.reasoning, '  '))
    out.push('')
  } else {
    out.push('Verification: none recorded.', '')
  }
  return out.join('\n')
}

export function toMarkdown(findings: Finding[], profile: TargetProfile, opts: { mode: 'full' | 'pure-reasoning' }): string {
  const confirmed = findings.filter((f) => f.status === 'confirmed')
  const review = findings.filter((f) => f.status === 'needs-review')
  const unverified = findings.filter((f) => f.status === 'candidate')
  const dropped = findings.filter((f) => f.status === 'dropped').length
  const rank = (f: Finding): number => (f.severity ? BAND_RANK[f.severity.band] : -1)
  const byRank = (a: Finding, b: Finding): number => rank(b) - rank(a)

  const out: string[] = ['# Sentinel security report', '']
  out.push(`Target: ${inline(profile.target.root)} (scanned ${profile.generated_at})`, '')

  out.push('## Summary', '')
  const counts = BANDS.map((b) => [b, confirmed.filter((f) => (f.severity?.band) === b).length] as const).filter(([, n]) => n > 0)
  const unscored = confirmed.filter((f) => !f.severity).length
  out.push(`- Confirmed: ${confirmed.length}${confirmed.length ? ` (${[...counts.map(([b, n]) => `${n} ${b}`), ...(unscored ? [`${unscored} unrated`] : [])].join(', ')})` : ''}`)
  out.push(`- Needs review, NOT confirmed: ${review.length}`)
  if (unverified.length) out.push(`- Not yet verified: ${unverified.length}`)
  out.push(`- ${dropped} disproved by verification (not listed)`)
  const gaps = profile.skipped.length
  out.push(`- Coverage: ${profile.file_count} files scanned, ${gaps} not scanned${profile.truncated ? ', scan truncated' : ''}. See Coverage below.`, '')

  if (opts.mode === 'pure-reasoning') {
    out.push(
      '> **Reduced coverage: pure-reasoning mode.** This scan read the code without running any security tooling, so it did NOT check dependencies for known vulnerabilities (dependency CVE detection) and did NOT run entropy-based secret scanning for leaked keys and passwords. A report with few findings here is not a complete one.',
      '',
    )
  }

  out.push('## Confirmed findings', '')
  if (!confirmed.length) out.push('No findings were confirmed in the code that was scanned. Check the Coverage section for what was not scanned.', '')
  for (const b of [...BANDS, null]) {
    const group = confirmed.filter((f) => (f.severity?.band ?? null) === b)
    if (!group.length) continue
    out.push(`### ${b ? cap(b) : 'Unrated'}`, '')
    for (const f of group) out.push(findingBlock(f, ''))
  }

  if (review.length) {
    out.push('## Needs review', '')
    out.push('These are NOT confirmed. Verification could not settle them either way, so treat each as a lead for a person to check, not as a proven problem.', '')
    for (const f of review.sort(byRank)) out.push(findingBlock(f, '[NOT CONFIRMED] '))
  }
  if (unverified.length) {
    out.push('## Not yet verified', '')
    out.push('These were reported but never checked by verification. They are NOT confirmed.', '')
    for (const f of unverified.sort(byRank)) out.push(findingBlock(f, '[UNVERIFIED] '))
  }

  out.push('## Coverage', '')
  out.push(`- Files scanned: ${profile.file_count}`)
  if (profile.file_count === 0) out.push('- **No files were scanned.** An empty findings list means nothing was examined.')
  if (profile.truncated) out.push('- **Scan truncated:** the file limit was reached, so files beyond it were not scanned and the skipped list below may be incomplete.')
  if (!gaps) out.push('- No files were skipped.')
  for (const r of SKIP_ORDER) {
    const paths = profile.skipped.filter((s) => s.reason === r).map((s) => s.path)
    if (!paths.length) continue
    out.push(`- ${inline(r)} (${paths.length} not scanned): ${SKIP_TEXT[r]}`)
    for (const p of paths.slice(0, MAX_PATHS)) out.push(`  - ${inline(p)}`)
    if (paths.length > MAX_PATHS) out.push(`  - and ${paths.length - MAX_PATHS} more`)
  }
  out.push('')
  return out.join('\n')
}
