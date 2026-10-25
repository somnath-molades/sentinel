import type { DepthTier } from '../schema/technique.js'
import type { IndexedTechnique, RegistryIndex } from './build-index.js'
import { WILDCARD_STACK } from './vocabulary.js'

export type TechniqueQuery = { vuln_class?: string; stack?: string; depth_tier?: DepthTier; limit?: number }

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

// Pure and deterministic. Filters on every supplied field, then ranks by specificity: exact stack
// match before wildcard (`generic`), then depth tier, then id as a total-order tiebreak.
// vuln_class is a filter, so every survivor is an exact class match. A stack absent from the
// registry matches wildcard techniques only: never everything, never nothing.
export function selectTechniques(index: RegistryIndex, q: TechniqueQuery): IndexedTechnique[] {
  const exact = (t: IndexedTechnique): boolean => q.stack !== undefined && t.stacks.includes(q.stack)
  const out = index.techniques
    .filter((t) => q.vuln_class === undefined || t.vuln_classes.includes(q.vuln_class))
    .filter((t) => q.depth_tier === undefined || t.depth_tier === q.depth_tier)
    .filter((t) => q.stack === undefined || exact(t) || t.stacks.includes(WILDCARD_STACK))
    .sort((a, b) => Number(exact(b)) - Number(exact(a)) || cmp(a.depth_tier, b.depth_tier) || cmp(a.id, b.id))
  return q.limit === undefined ? out : out.slice(0, q.limit)
}
