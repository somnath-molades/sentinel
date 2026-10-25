import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DOMAINS,
  buildIndex,
  planHunts,
  profileTarget,
  targetProfileSchema,
  type RegistryIndex,
  type TargetProfile,
} from '@sentinel/core'

const registryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../registry')
const fixture = (name: string): string => resolve(dirname(fileURLToPath(import.meta.url)), '../../../../tests/fixtures/targets', name)

// Synthetic profiles are parsed through the real schema so they cannot drift from its shape.
const synthetic = (languages: string[], hotspots: TargetProfile['hotspots'] = []): TargetProfile =>
  targetProfileSchema.parse({
    schema_version: 1,
    target: { kind: 'local', root: '/tmp/synthetic' },
    generated_at: '2026-10-25T00:00:00.000Z',
    languages: languages.map((language) => ({ language, files: 1, bytes: 1 })),
    frameworks: [],
    entrypoints: [],
    auth_surfaces: [],
    data_layer: [],
    iac: [],
    ci: [],
    client_boundary: [],
    hotspots,
    skipped: [],
    file_count: languages.length,
    truncated: false,
  })

let index: RegistryIndex
let expressProfile: TargetProfile
let cProfile: TargetProfile
const emptyProfile = synthetic([])
const nodeOnlyProfile = synthetic(['javascript'])
const noHotspotProfile = synthetic(['javascript'])

beforeAll(async () => {
  index = (await buildIndex(registryRoot)).index
  expressProfile = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') })
  cProfile = await profileTarget({ kind: 'local', root: fixture('c-memory-safety') })
})

test('returns exactly ten assignments, one per domain, always', () => {
  const a = planHunts(emptyProfile, index)
  expect(a).toHaveLength(10)
  expect(a.map((x) => x.domain).sort()).toEqual([...DOMAINS].sort())
})

test('a domain whose stack is absent is explicitly empty with a reason, never omitted', () => {
  const all = planHunts(nodeOnlyProfile, index)
  const a = all.find((x) => x.domain === 'memory-safety')
  expect(a).toBeDefined()
  expect(a!.techniques).toEqual([])
  expect(a!.coverage).not.toBe('exact')
  expect(a!.reason).toMatch(/stack|no technique/i)
  expect(all.map((x) => x.domain)).toContain('memory-safety')
})

test('a domain with no technique anywhere says so, differently from one with techniques for other stacks', () => {
  const all = planHunts(nodeOnlyProfile, index)
  const stackMiss = all.find((x) => x.domain === 'memory-safety')!.reason
  const empty = planHunts(nodeOnlyProfile, { ...index, techniques: index.techniques.filter((t) => t.domain !== 'memory-safety') })
  const none = empty.find((x) => x.domain === 'memory-safety')!.reason
  expect(stackMiss).toMatch(/none apply to this target's stacks/)
  expect(none).toMatch(/no technique in the registry/)
  expect(none).not.toEqual(stackMiss)
})

test('a domain with techniques but no hotspots still gets its techniques', () => {
  const a = planHunts(noHotspotProfile, index).find((x) => x.domain === 'injection')!
  expect(a.techniques.length).toBeGreaterThan(0)
  expect(a.hotspot_paths).toEqual([])
})

test('hotspot paths are the ones recon flagged for that domain', () => {
  // Real profiler output: src/server.js really is flagged for authorization (also asserted in the recon tests).
  const a = planHunts(expressProfile, index).find((x) => x.domain === 'authorization')!
  expect(a.hotspot_paths).toContain('src/server.js')
  expect(a.hotspot_paths).not.toContain('.env')
})

test('the injection assignment contains the cross-cutting taint entry', () => {
  const a = planHunts(expressProfile, index).find((x) => x.domain === 'injection')!
  expect(a.techniques.map((t) => t.id)).toContain('cross-file-taint-source-to-sink')
})

test('is pure: the same inputs give a deeply equal result', () => {
  expect(planHunts(expressProfile, index)).toEqual(planHunts(expressProfile, index))
})

test('several stacks: techniques are unioned without duplicates and in a fixed order', () => {
  const multi = synthetic(['javascript', 'python', 'typescript'])
  const inj = planHunts(multi, index).find((x) => x.domain === 'injection')!
  const ids = inj.techniques.map((t) => t.id)
  expect(new Set(ids).size).toBe(ids.length)
  // Same result however the profile orders its languages.
  const flipped = planHunts(synthetic(['python', 'typescript', 'javascript']), index).find((x) => x.domain === 'injection')!
  expect(flipped.techniques).toEqual(inj.techniques)
})

test('several stacks: the best coverage wins', () => {
  // memory-safety: c is exact, node alone is none; together the assignment is hunt-able, so exact.
  const mixed = planHunts(synthetic(['javascript', 'c']), index).find((x) => x.domain === 'memory-safety')!
  expect(mixed.coverage).toBe('exact')
  expect(mixed.techniques.map((t) => t.id)).toContain('unbounded-copy-into-fixed-buffer')
  // vulnerable-dependency is generic-listed AND node-listed; a go+java profile still exact via go.
  // An unknown language yields wildcard-only for a domain that has a generic entry.
  const unknownOnly = planHunts(synthetic(['cobol']), index).find((x) => x.domain === 'dependencies')!
  expect(unknownOnly.coverage).toBe('wildcard-only')
  expect(planHunts(nodeOnlyProfile, index).find((x) => x.domain === 'memory-safety')!.coverage).toBe('none')
})

// Spec 8.2 item 3. No single realistic profile has every stack, so use one declaring every language
// the registry's stacks can be derived from. Every entry must land in at least one hunter's assignment.
test('every registry entry appears in at least one assignment', () => {
  const everything = synthetic(['javascript', 'python', 'go', 'php', 'java', 'c', 'cpp'])
  const assigned = new Set(planHunts(everything, index).flatMap((a) => a.techniques.map((t) => t.id)))
  const stranded = index.techniques.map((t) => t.id).filter((id) => !assigned.has(id))
  expect(stranded).toEqual([])
})

// Spec 8.1 C row, assignment level.
test('a C target yields a non-empty memory-safety assignment containing the unbounded-copy entry', () => {
  const a = planHunts(cProfile, index).find((x) => x.domain === 'memory-safety')!
  expect(a.techniques.length).toBeGreaterThan(0)
  expect(a.techniques.map((t) => t.id)).toContain('unbounded-copy-into-fixed-buffer')
  expect(a.coverage).toBe('exact')
})
