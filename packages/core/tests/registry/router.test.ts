import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildIndex, selectTechniques, STACKS, type RegistryIndex } from '@sentinel/core'

const registryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../registry')
let index: RegistryIndex
beforeAll(async () => {
  index = (await buildIndex(registryRoot)).index
})

test('filters by stack', () => {
  const r = selectTechniques(index, { stack: 'node' })
  expect(r.length).toBeGreaterThan(0)
  expect(r.every((t) => t.stacks.includes('node') || t.stacks.includes('generic'))).toBe(true)
})

test('filters by vuln_class and ranks exact class matches first', () => {
  const r = selectTechniques(index, { vuln_class: 'sql-injection', stack: 'node' })
  expect(r[0]?.vuln_classes).toContain('sql-injection')
  expect(r.every((t) => t.vuln_classes.includes('sql-injection'))).toBe(true)
})

test('an unknown stack returns stack-agnostic techniques, not everything', () => {
  const r = selectTechniques(index, { stack: 'cobol' })
  expect(r.length).toBeGreaterThan(0)
  expect(r.length).toBeLessThan(index.techniques.length)
  expect(r.every((t) => t.stacks.includes('generic'))).toBe(true)
})

test('respects limit', () => {
  expect(selectTechniques(index, { limit: 3 })).toHaveLength(3)
})

test('exact stack ranks before wildcard-only, and results are deterministic', () => {
  const r = selectTechniques(index, { stack: 'go' })
  const firstWildcardOnly = r.findIndex((t) => !t.stacks.includes('go'))
  expect(r.slice(firstWildcardOnly).every((t) => !t.stacks.includes('go'))).toBe(true)
  expect(selectTechniques({ ...index, techniques: [...index.techniques].reverse() }, { stack: 'go' })).toEqual(r)
})

// The failure this router must never have: a technique that exists but no query returns.
test('every indexed technique is returned by some (stack, vuln_class) query', () => {
  for (const t of index.techniques) {
    const reachable = t.stacks.some((s) =>
      t.vuln_classes.some((c) => selectTechniques(index, { stack: s, vuln_class: c }).some((x) => x.id === t.id)),
    )
    expect(reachable, `${t.id} is unreachable`).toBe(true)
    // ...and with no filters at all.
    expect(selectTechniques(index, {}).map((x) => x.id)).toContain(t.id)
  }
})

test('every concrete stack in the vocabulary reaches at least one technique', () => {
  for (const s of STACKS) expect(selectTechniques(index, { stack: s }).length, s).toBeGreaterThan(0)
})
