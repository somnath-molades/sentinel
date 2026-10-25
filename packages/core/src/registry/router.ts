import type { DepthTier } from '../schema/technique.js'
import type { IndexedTechnique, RegistryIndex } from './build-index.js'
import { WILDCARD_STACK, type Domain } from './vocabulary.js'

export type TechniqueQuery = { vuln_class?: string; domain?: Domain; stack?: string; depth_tier?: DepthTier; limit?: number }

// match: 'exact' = at least one result lists the queried stack (or no stack was queried);
// 'wildcard-only' = results exist but only via `generic`, i.e. the stack itself is unknown or uncovered;
// 'none' = nothing matched. Callers must not treat 'wildcard-only' and 'none' as a clean scan.
export type TechniqueSelection = { techniques: IndexedTechnique[]; match: 'exact' | 'wildcard-only' | 'none' }

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

// Pure and deterministic. Filters on every supplied field, then ranks by specificity: exact stack
// match before wildcard (`generic`), then depth tier, then id as a total-order tiebreak.
// vuln_class is a filter, so every survivor is an exact class match. A stack absent from the
// registry matches wildcard techniques only: never everything, never nothing.
// vuln_class matching is exact: cross-cutting classes (e.g. `taint-flow`) must be queried separately.
// `limit` must be a positive integer; anything else throws, since silent truncation hides techniques.
export function selectTechniques(index: RegistryIndex, q: TechniqueQuery): TechniqueSelection {
  if (q.limit !== undefined && !(Number.isInteger(q.limit) && q.limit > 0)) {
    throw new RangeError(`limit must be a positive integer, got ${String(q.limit)}`)
  }
  const exact = (t: IndexedTechnique): boolean => q.stack !== undefined && t.stacks.includes(q.stack)
  const out = index.techniques
    .filter((t) => q.vuln_class === undefined || t.vuln_classes.includes(q.vuln_class))
    .filter((t) => q.depth_tier === undefined || t.depth_tier === q.depth_tier)
    .filter((t) => q.domain === undefined || t.domain === q.domain)
    .filter((t) => q.stack === undefined || exact(t) || t.stacks.includes(WILDCARD_STACK))
    .sort((a, b) => Number(exact(b)) - Number(exact(a)) || cmp(a.depth_tier, b.depth_tier) || cmp(a.id, b.id))
  // Computed before `limit` so truncation cannot change the coverage signal.
  const match = out.length === 0 ? 'none' : q.stack === undefined || out.some(exact) ? 'exact' : 'wildcard-only'
  return { techniques: q.limit === undefined ? out : out.slice(0, q.limit), match }
}
