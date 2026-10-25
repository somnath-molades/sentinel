import { readdirSync, readFileSync, statSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { packSchema, parseTechnique, type PackManifest, type TechniqueEntry } from '@sentinel/core'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..')
const packsRoot = resolve(repoRoot, 'registry/packs')
const read = (f: string): string => readFileSync(f, 'utf8')

const packDirs = (): string[] =>
  readdirSync(packsRoot)
    .map((d) => join(packsRoot, d))
    .filter((d) => statSync(d).isDirectory())

const packs = (): PackManifest[] => packDirs().map((d) => packSchema.parse(parse(read(join(d, 'pack.yaml')))))

const allTechniqueFiles = (): string[] =>
  packDirs().flatMap((d) => {
    const dir = join(d, 'techniques')
    return readdirSync(dir)
      .filter((f) => f.endsWith('.md'))
      .map((f) => join(dir, f))
  })

const allTechniques = (): TechniqueEntry[] =>
  allTechniqueFiles().map((f) => {
    const r = parseTechnique(read(f), f)
    if (!r.ok) throw new Error(`${r.error.file}: ${r.error.problem}`)
    return r.value
  })

test('at least one pack exists', () => {
  expect(packDirs().length).toBeGreaterThan(0)
})

test('every pack manifest validates', () => {
  for (const dir of packDirs()) {
    const r = packSchema.safeParse(parse(read(join(dir, 'pack.yaml'))))
    expect(r.success, `${dir}: ${r.success ? '' : JSON.stringify(r.error.issues)}`).toBe(true)
  }
})

test('every technique entry validates', () => {
  const errors = allTechniqueFiles()
    .map((f) => parseTechnique(read(f), f))
    .filter((r) => !r.ok)
  expect(errors.map((e) => (e.ok ? null : e.error))).toEqual([])
})

test('registry covers L0 through L2', () => {
  const tiers = new Set(allTechniques().map((t) => t.depth_tier))
  expect([...tiers]).toEqual(expect.arrayContaining(['L0', 'L1', 'L2']))
})

test('at least 12 technique entries exist', () => {
  expect(allTechniques().length).toBeGreaterThanOrEqual(12)
})

test('technique ids are unique and match their filename', () => {
  const seen = new Map<string, string>()
  for (const f of allTechniqueFiles()) {
    const r = parseTechnique(read(f), f)
    if (!r.ok) throw new Error(r.error.problem)
    expect(f.endsWith(`/${r.value.id}.md`), `${f} should be named ${r.value.id}.md`).toBe(true)
    expect(seen.get(r.value.id), `duplicate id ${r.value.id}`).toBeUndefined()
    seen.set(r.value.id, f)
  }
})

test('every technique declares the pack it lives in', () => {
  for (const dir of packDirs()) {
    const manifest = packSchema.parse(parse(read(join(dir, 'pack.yaml'))))
    for (const f of readdirSync(join(dir, 'techniques')).filter((x) => x.endsWith('.md'))) {
      const r = parseTechnique(read(join(dir, 'techniques', f)), f)
      if (!r.ok) throw new Error(r.error.problem)
      expect(r.value.provenance.pack).toBe(manifest.id)
    }
  }
})

test("every pack's declared coverage matches its entries", () => {
  for (const dir of packDirs()) {
    const manifest = packSchema.parse(parse(read(join(dir, 'pack.yaml'))))
    const actual = new Set(
      readdirSync(join(dir, 'techniques'))
        .filter((f) => f.endsWith('.md'))
        .map((f) => {
          const r = parseTechnique(read(join(dir, 'techniques', f)), f)
          if (!r.ok) throw new Error(r.error.problem)
          return r.value.depth_tier
        }),
    )
    expect([...actual].sort()).toEqual([...manifest.coverage].sort())
  }
})

test('every vendored pack appears in NOTICE', () => {
  const notice = read(resolve(repoRoot, 'NOTICE'))
  const vendored = packs().filter((p) => p.ingestion_mode === 'vendored')
  expect(vendored.length).toBeGreaterThan(0)
  for (const p of vendored) {
    expect(notice).toContain(p.source_url)
    expect(notice).toContain(p.upstream_commit)
  }
})

test('every pack has an audit row pinning the same commit', () => {
  const audit = read(resolve(repoRoot, 'registry/AUDIT.md'))
  for (const p of packs()) {
    expect(audit).toContain(p.source_url)
    if (p.upstream_commit !== undefined) expect(audit).toContain(p.upstream_commit)
  }
})
