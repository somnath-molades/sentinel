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
  // Other (line, reachability) pairs from duplicate reports, so dedupe collapses the report, not the evidence.
  additional_locations: { line: number; reachability: string }[]
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

const OUTCOMES: readonly string[] = ['confirmed', 'disproved', 'ambiguous']

// Callers are untrusted agents: the store keeps its own records and only hands out deep copies,
// so nobody can set status or erase a recorded disproof.
export class FindingsStore {
  private readonly findings = new Map<string, Finding>()

  add(input: FindingInput, meta: AddMeta): Finding {
    if (!meta.reachability.trim()) throw new Error('reachability must be a non-empty reason')
    if (!input.snippet.trim()) throw new Error('snippet must not be empty')
    const id = fingerprint(input)
    const existing = this.findings.get(id)
    if (existing) {
      const seen = (l: { line: number; reachability: string }): boolean =>
        l.line === input.line && l.reachability === meta.reachability
      if (!seen(existing) && !existing.additional_locations.some(seen)) {
        existing.additional_locations.push({ line: input.line, reachability: meta.reachability })
      }
      return structuredClone(existing)
    }
    // Explicit picks: extra runtime properties on agent JSON (e.g. a fabricated severity) are dropped.
    const finding: Finding = {
      technique_id: input.technique_id,
      file: input.file,
      line: input.line,
      snippet: input.snippet,
      depth_tier: meta.depth_tier,
      reachability: meta.reachability,
      id,
      status: 'candidate',
      verdicts: [],
      additional_locations: [],
    }
    this.findings.set(id, finding)
    return structuredClone(finding)
  }

  recordVerdict(id: string, v: Verdict): Finding {
    const f = this.findings.get(id)
    if (!f) throw new Error(`unknown finding: ${id}`)
    if (!OUTCOMES.includes(v.outcome)) throw new Error(`unknown verdict outcome: ${String(v.outcome)}`)
    f.verdicts.push({ agent: v.agent, outcome: v.outcome, reasoning: v.reasoning })
    f.status = statusFrom(f.verdicts)
    return structuredClone(f)
  }

  get(id: string): Finding | undefined {
    const f = this.findings.get(id)
    return f && structuredClone(f)
  }

  list(filter?: { status?: Finding['status'] }): Finding[] {
    const all = [...this.findings.values()]
    return structuredClone(filter?.status ? all.filter((f) => f.status === filter.status) : all)
  }
}

const RANK: Record<Severity['band'], number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

// Only 'confirmed' findings can fail a build: needs-review is unverified, and failing CI on an
// unverified claim is a false positive. A confirmed finding with no severity cannot be compared, so it does not trip.
export function decideExitCode(findings: Finding[], failOn: Severity['band'] | null): 0 | 1 {
  if (failOn === null) return 0
  return findings.some((f) => f.status === 'confirmed' && f.severity && RANK[f.severity.band] >= RANK[failOn]) ? 1 : 0
}
