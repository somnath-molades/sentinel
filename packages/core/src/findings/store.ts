import type { DepthTier } from '../schema/technique.js'
import { fingerprint, type FindingInput } from './fingerprint.js'
import { BAND_RANK, type Severity } from './severity.js'

export type Verdict = { agent: string; outcome: 'confirmed' | 'disproved' | 'ambiguous'; reasoning: string }
export type Finding = FindingInput & {
  id: string
  status: 'candidate' | 'confirmed' | 'dropped' | 'needs-review'
  depth_tier: DepthTier
  reachability: string
  verdicts: Verdict[]
  // Other (line, reachability) pairs from duplicate reports, so dedupe collapses the report, not the evidence.
  additional_locations: { line: number; reachability: string }[]
  // Every agent that reported this defect (dedupe merges reports), so none of them may verify it.
  reporting_agents: string[]
  severity?: Severity
}
// reporting_agent lives here, not on FindingInput: it must not feed the fingerprint, or dedupe would stop collapsing.
export type AddMeta = { depth_tier: DepthTier; reachability: string; reporting_agent: string }

// Hard verification gate (spec 6.2): disproved > ambiguous > confirmed. Recomputed from
// all verdicts, so arrival order can never matter.
function statusFrom(verdicts: Verdict[]): Finding['status'] {
  if (verdicts.some((v) => v.outcome === 'disproved')) return 'dropped'
  if (verdicts.some((v) => v.outcome === 'ambiguous')) return 'needs-review'
  if (verdicts.some((v) => v.outcome === 'confirmed')) return 'confirmed'
  return 'candidate'
}

// One definition for storing and checking agent ids, so spelling variants of one id are one agent.
const canonicalAgentId = (id: string): string => id.normalize('NFKC').trim().toLowerCase()

const OUTCOMES: readonly string[] = ['confirmed', 'disproved', 'ambiguous']

// Callers are untrusted agents: the store keeps its own records and only hands out deep copies,
// so nobody can set status or erase a recorded disproof.
export class FindingsStore {
  private readonly findings = new Map<string, Finding>()

  add(input: FindingInput, meta: AddMeta): Finding {
    if (!meta.reachability.trim()) throw new Error('reachability must be a non-empty reason')
    if (!input.snippet.trim()) throw new Error('snippet must not be empty')
    const reporter = canonicalAgentId(meta.reporting_agent)
    if (!reporter) throw new Error('reporting_agent must be a non-empty agent id')
    const id = fingerprint(input)
    const existing = this.findings.get(id)
    if (existing) {
      if (existing.verdicts.some((x) => canonicalAgentId(x.agent) === reporter)) {
        throw new Error(`agent ${reporter} already holds a verdict on this finding and cannot report it`)
      }
      if (!existing.reporting_agents.includes(reporter)) existing.reporting_agents.push(reporter)
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
      reporting_agents: [reporter],
    }
    this.findings.set(id, finding)
    return structuredClone(finding)
  }

  recordVerdict(id: string, v: Verdict): Finding {
    const f = this.findings.get(id)
    if (!f) throw new Error(`unknown finding: ${id}`)
    // Checked first so a self-verdict is refused whatever it claims; trimmed so padding cannot evade it.
    if (f.reporting_agents.includes(canonicalAgentId(v.agent))) throw new Error(`reporting agent cannot verify its own finding: ${v.agent}`)
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

// Only 'confirmed' findings can fail a build: needs-review is unverified, and failing CI on an
// unverified claim is a false positive. A confirmed finding with no severity cannot be compared, so it does not trip.
export function decideExitCode(findings: Finding[], failOn: Severity['band'] | null): 0 | 1 {
  if (failOn === null) return 0
  return findings.some((f) => f.status === 'confirmed' && f.severity && BAND_RANK[f.severity.band] >= BAND_RANK[failOn]) ? 1 : 0
}
