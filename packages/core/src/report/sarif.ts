import type { Finding } from '../findings/store.js'
import type { Severity } from '../findings/severity.js'
import type { TargetProfile } from '../schema/target-profile.js'

type SarifLocation = {
  physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } }
  message?: { text: string }
}
export type SarifResult = {
  ruleId: string
  level: 'error' | 'warning' | 'note'
  message: { text: string }
  locations: SarifLocation[]
  partialFingerprints: { sentinelFindingId: string }
  properties: { severity?: Severity; depth_tier: string }
}
export type SarifLog = {
  version: '2.1.0'
  runs: {
    tool: { driver: { name: 'Sentinel'; rules: { id: string; name: string; shortDescription: { text: string } }[] } }
    results: SarifResult[]
    // Coverage rides along so a consumer of the log alone cannot mistake "no results" for "all clear".
    properties: { coverage: { files_scanned: number; truncated: boolean; skipped: Record<string, number> } }
  }[]
}

const LEVEL: Record<Severity['band'], SarifResult['level']> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

const loc = (file: string, line: number, text?: string): SarifLocation => ({
  physicalLocation: { artifactLocation: { uri: file }, region: { startLine: Math.max(1, line) } },
  ...(text ? { message: { text } } : {}),
})

export function toSarif(findings: Finding[], profile: TargetProfile): SarifLog {
  // Only verified findings: needs-review and candidates are unverified claims, dropped ones were disproved.
  const confirmed = findings.filter((f) => f.status === 'confirmed')
  const skipped: Record<string, number> = {}
  for (const s of profile.skipped) skipped[s.reason] = (skipped[s.reason] ?? 0) + 1
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentinel',
            rules: [...new Set(confirmed.map((f) => f.technique_id))].map((id) => ({ id, name: id, shortDescription: { text: id } })),
          },
        },
        results: confirmed.map((f) => ({
          ruleId: f.technique_id,
          // An unscored confirmed finding is not downgraded to a note.
          level: f.severity ? LEVEL[f.severity.band] : 'warning',
          message: { text: `${f.technique_id} in ${f.file}: ${f.reachability}` },
          locations: [loc(f.file, f.line), ...f.additional_locations.map((a) => loc(f.file, a.line, a.reachability))],
          partialFingerprints: { sentinelFindingId: f.id },
          properties: { ...(f.severity ? { severity: f.severity } : {}), depth_tier: f.depth_tier },
        })),
        properties: { coverage: { files_scanned: profile.file_count, truncated: profile.truncated, skipped } },
      },
    ],
  }
}
