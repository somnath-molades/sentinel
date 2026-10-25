import type { DepthTier } from '../schema/technique.js'
import { fingerprint, type FindingInput } from './fingerprint.js'
import type { Severity } from './severity.js'

export type Verdict = { agent: string; outcome: 'confirmed' | 'disproved' | 'ambiguous'; reasoning: string }
export type Finding = FindingInput & {
  id: string
  status: 'candidate' | 'confirmed' | 'dropped' | 'needs-review'
  depth_tier: DepthTier
  reachability: string
  verdicts: Verdict[]
  severity?: Severity
}
export type AddMeta = { depth_tier: DepthTier; reachability: string }

// Hard verification gate (spec 6.2): disproved > ambiguous > confirmed. Recomputed from
// all verdicts, so arrival order can never matter.
function statusFrom(verdicts: Verdict[]): Finding['status'] {
  if (verdicts.some((v) => v.outcome === 'disproved')) return 'dropped'
  if (verdicts.some((v) => v.outcome === 'ambiguous')) return 'needs-review'
  if (verdicts.some((v) => v.outcome === 'confirmed')) return 'confirmed'
  return 'candidate'
}

export class FindingsStore {
  private readonly findings = new Map<string, Finding>()

  add(input: FindingInput, meta: AddMeta): Finding {
    const id = fingerprint(input)
    const existing = this.findings.get(id)
    if (existing) return existing
    const finding: Finding = { ...input, ...meta, id, status: 'candidate', verdicts: [] }
    this.findings.set(id, finding)
    return finding
  }

  recordVerdict(id: string, v: Verdict): Finding {
    const f = this.findings.get(id)
    if (!f) throw new Error(`unknown finding: ${id}`)
    f.verdicts.push(v)
    f.status = statusFrom(f.verdicts)
    return f
  }

  get(id: string): Finding | undefined {
    return this.findings.get(id)
  }

  list(filter?: { status?: Finding['status'] }): Finding[] {
    const all = [...this.findings.values()]
    return filter?.status ? all.filter((f) => f.status === filter.status) : all
  }
}

const RANK: Record<Severity['band'], number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

// Only 'confirmed' findings can fail a build: needs-review is unverified, and failing CI on an
// unverified claim is a false positive. A confirmed finding with no severity cannot be compared, so it does not trip.
export function decideExitCode(findings: Finding[], failOn: Severity['band'] | null): 0 | 1 {
  if (failOn === null) return 0
  return findings.some((f) => f.status === 'confirmed' && f.severity && RANK[f.severity.band] >= RANK[failOn]) ? 1 : 0
}
