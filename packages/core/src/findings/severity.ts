// Minimal type stub so Task 9 compiles; Task 10 adds computeSeverity here.
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
