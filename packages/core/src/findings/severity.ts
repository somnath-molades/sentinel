// Severity is computed from four pinned factors. Depth tier is deliberately absent: spec 4.1 keeps
// how hard a finding was to detect independent of how severe it is.
export type SeverityFactors = {
  exploitability: 0 | 1 | 2 | 3
  reachability: 0 | 1 | 2 | 3
  blast_radius: 0 | 1 | 2 | 3
  data_sensitivity: 0 | 1 | 2 | 3
}
export type Severity = {
  band: 'critical' | 'high' | 'medium' | 'low' | 'info'
  score: number
  factors: SeverityFactors
}

export const BAND_RANK: Record<Severity['band'], number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export function computeSeverity(f: SeverityFactors): Severity {
  const score = f.exploitability * 3 + f.reachability * 3 + f.blast_radius * 2 + f.data_sensitivity * 2
  const band = score >= 24 ? 'critical' : score >= 17 ? 'high' : score >= 10 ? 'medium' : score >= 4 ? 'low' : 'info'
  // Explicit picks: a caller's extra properties do not leak into the result.
  return {
    band,
    score,
    factors: {
      exploitability: f.exploitability,
      reachability: f.reachability,
      blast_radius: f.blast_radius,
      data_sensitivity: f.data_sensitivity,
    },
  }
}
