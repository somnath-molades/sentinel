import type { IndexedTechnique, RegistryIndex } from '../registry/build-index.js'
import { selectTechniques, type TechniqueSelection } from '../registry/router.js'
import { DOMAINS, stackForLanguage, type Domain } from '../registry/vocabulary.js'
import type { TargetProfile } from '../schema/target-profile.js'

// No file list on purpose: the hunter's scope is the profile's walked set, which the caller holds.
// hotspot_paths is PRIORITY ORDERING, never a filter: a domain with no hotspots is still hunted everywhere.
export type HuntAssignment = {
  domain: Domain
  techniques: IndexedTechnique[]
  hotspot_paths: string[]
  coverage: TechniqueSelection['match']
  reason?: string
}

// Best coverage wins: `coverage` answers "can this domain be hunted on this target at all", and one stack
// with exact techniques makes that true however many other stacks have none.
const RANK: Record<TechniqueSelection['match'], number> = { none: 0, 'wildcard-only': 1, exact: 2 }
const best = (a: TechniqueSelection['match'], b: TechniqueSelection['match']): TechniqueSelection['match'] => (RANK[b] > RANK[a] ? b : a)

// A stack no registry entry lists, so the router answers with wildcard techniques only, truthfully.
const UNKNOWN_STACK = 'unknown'

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

// Pure: no I/O, clock or randomness. Always returns one assignment per domain, in DOMAINS order,
// so an uncovered domain is visibly empty with a reason rather than silently absent.
export function planHunts(profile: TargetProfile, index: RegistryIndex): HuntAssignment[] {
  const known = new Set<string>()
  for (const l of profile.languages) {
    const s = stackForLanguage(l.language)
    if (s !== undefined) known.add(s)
  }
  // `ci` is derivable from the profile; detected CI config makes CI-stack techniques apply exactly.
  if (profile.ci.length > 0) known.add('ci')
  // Deferred: `agent-config` is not derivable yet (no profile field; recon must first detect agent/tool
  // configuration files). Until then the agentic domain reaches its techniques only via `generic` or `ci`.
  const stacks = known.size > 0 ? [...known].sort() : [UNKNOWN_STACK]

  return DOMAINS.map((domain): HuntAssignment => {
    let coverage: TechniqueSelection['match'] = 'none'
    const byId = new Map<string, IndexedTechnique>()
    for (const stack of stacks) {
      const r = selectTechniques(index, { domain, stack })
      coverage = best(coverage, r.match)
      for (const t of r.techniques) byId.set(t.id, t) // dedupe: one technique can match several stacks
    }
    // Order: listed for one of the profile's own stacks first, then depth tier, then id (total order).
    const own = (t: IndexedTechnique): number => Number(t.stacks.some((s) => known.has(s)))
    const techniques = [...byId.values()].sort((a, b) => own(b) - own(a) || cmp(a.depth_tier, b.depth_tier) || cmp(a.id, b.id))
    // Alphabetical is safe only because recon emits hotspots unranked (walk order); if recon ever ranks them, drop this sort (spec 7.1).
    const hotspot_paths =[...new Set(profile.hotspots.filter((h) => h.domains.includes(domain)).map((h) => h.path))].sort()

    if (techniques.length > 0) return { domain, techniques, hotspot_paths, coverage }
    const anywhere = selectTechniques(index, { domain }).techniques.length
    const reason =
      anywhere === 0
        ? `no technique in the registry covers the ${domain} domain`
        : `${anywhere} technique(s) exist for ${domain} but none apply to this target's stacks (${known.size > 0 ? [...known].join(', ') : 'no recognised language'})`
    return { domain, techniques, hotspot_paths, coverage, reason }
  })
}
