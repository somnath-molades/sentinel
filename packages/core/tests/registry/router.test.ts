import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildIndex, selectTechniques, STACKS, type RegistryIndex } from '@sentinel/core'

const registryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../registry')
let index: RegistryIndex
beforeAll(async () => {
  index = (await buildIndex(registryRoot)).index
})

test('filters by stack', () => {
  const r = selectTechniques(index, { stack: 'node' }).techniques
  expect(r.length).toBeGreaterThan(0)
  expect(r.every((t) => t.stacks.includes('node') || t.stacks.includes('generic'))).toBe(true)
})

test('filters by vuln_class and ranks exact class matches first', () => {
  const r = selectTechniques(index, { vuln_class: 'sql-injection', stack: 'node' }).techniques
  expect(r[0]?.vuln_classes).toContain('sql-injection')
  expect(r.every((t) => t.vuln_classes.includes('sql-injection'))).toBe(true)
})

test('an unknown stack returns stack-agnostic techniques, not everything', () => {
  const r = selectTechniques(index, { stack: 'cobol' }).techniques
  expect(r.length).toBeGreaterThan(0)
  expect(r.length).toBeLessThan(index.techniques.length)
  expect(r.every((t) => t.stacks.includes('generic'))).toBe(true)
})

test('respects limit', () => {
  expect(selectTechniques(index, { limit: 3 }).techniques).toHaveLength(3)
})

test('exact stack ranks before wildcard-only, and results are deterministic', () => {
  const r = selectTechniques(index, { stack: 'go' }).techniques
  const firstWildcardOnly = r.findIndex((t) => !t.stacks.includes('go'))
  expect(r.slice(firstWildcardOnly).every((t) => !t.stacks.includes('go'))).toBe(true)
  expect(selectTechniques({ ...index, techniques: [...index.techniques].reverse() }, { stack: 'go' }).techniques).toEqual(r)
})

// The failure this router must never have: a technique that exists but no query returns.
test('every indexed technique is returned by some (stack, vuln_class) query', () => {
  for (const t of index.techniques) {
    const reachable = t.stacks.some((s) =>
      t.vuln_classes.some((c) => selectTechniques(index, { stack: s, vuln_class: c }).techniques.some((x) => x.id === t.id)),
    )
    expect(reachable, `${t.id} is unreachable`).toBe(true)
    // ...and with no filters at all.
    expect(selectTechniques(index, {}).techniques.map((x) => x.id)).toContain(t.id)
  }
})

test('every concrete stack in the vocabulary reaches at least one technique', () => {
  for (const s of STACKS) expect(selectTechniques(index, { stack: s }).techniques.length, s).toBeGreaterThan(0)
})

test('coverage signal tells exact, wildcard-only and none apart', () => {
  expect(selectTechniques(index, { stack: 'node' }).match).toBe('exact')
  expect(selectTechniques(index, { stack: 'cobol' }).match).toBe('wildcard-only')
  expect(selectTechniques(index, { vuln_class: 'no-such-class' }).match).toBe('none')
  expect(selectTechniques(index, { vuln_class: 'buffer-overflow', stack: 'cobol' }).match).toBe('none')
  expect(selectTechniques(index, { stack: 'cobol', limit: 1 }).match).toBe('wildcard-only')
})

// Pins surprising behaviour: class matching is exact, so the L2 dataflow entry is only
// found by its own cross-cutting classes, never by a concrete class such as sql-injection.
test('cross-cutting classes must be queried separately', () => {
  const ids = (c: string): string[] => selectTechniques(index, { vuln_class: c }).techniques.map((t) => t.id)
  expect(ids('taint-flow')).toContain('cross-file-taint-source-to-sink')
  expect(ids('reachability')).toContain('entrypoint-reachability-under-auth-state')
  expect(ids('sql-injection')).not.toContain('cross-file-taint-source-to-sink')
})

test('a generic stack query matches generic-listing techniques as a concrete stack', () => {
  const sel = selectTechniques(index, { stack: 'generic' })
  expect(sel.match).toBe('exact')
  expect(sel.techniques.every((t) => t.stacks.includes('generic'))).toBe(true)
})

test('limit keeps the top-ranked results in rank order', () => {
  const all = selectTechniques(index, { stack: 'go' }).techniques
  expect(selectTechniques(index, { stack: 'go', limit: 2 }).techniques).toEqual(all.slice(0, 2))
})

test('a non-positive or non-integer limit is rejected, not silently truncated', () => {
  for (const limit of [0, -1, 1.5, NaN]) expect(() => selectTechniques(index, { limit })).toThrow(RangeError)
})
