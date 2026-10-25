import { readdirSync, readFileSync, statSync } from 'node:fs'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { DOMAINS, packSchema, parseTechnique, type PackManifest, type TechniqueEntry } from '@sentinel/core'

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

// MIT and Apache-2.0 both require the licence text to travel with the content, so the
// NOTICE pointer must resolve to a real file holding the upstream licence.
test('every vendored pack has a NOTICE entry whose License-Text file exists', () => {
  const notice = read(resolve(repoRoot, 'NOTICE'))
  // Entry blocks only: the indented template lines are commented with a leading '#'.
  const entries = notice.split(/\n\s*\n/).filter((b) => /^Pack: /m.test(b))
  expect(entries.length).toBe(packs().filter((p) => p.ingestion_mode === 'vendored').length)
  for (const p of packs().filter((x) => x.ingestion_mode === 'vendored')) {
    const block = entries.find((b) => new RegExp(`^Pack:\\s+${p.id}$`, 'm').test(b))
    expect(block, `no NOTICE entry for pack ${p.id}`).toBeDefined()
    const licenseText = /^License-Text:\s+(\S+)$/m.exec(block ?? '')?.[1]
    expect(licenseText, `${p.id}: NOTICE entry has no License-Text field`).toBeDefined()
    expect(read(resolve(repoRoot, licenseText ?? '')).length).toBeGreaterThan(100)
    expect(block).toMatch(/^Modified:\s+(yes|no)$/m)
    expect(block).toMatch(/^Derivation:\s+(copied|inspired)$/m)
  }
})

test('every pack has an audit row pinning the same commit', () => {
  const audit = read(resolve(repoRoot, 'registry/AUDIT.md'))
  for (const p of packs()) {
    expect(audit).toContain(p.source_url)
    if (p.upstream_commit !== undefined) expect(audit).toContain(p.upstream_commit)
  }
})

test('every entry declares a domain in the vocabulary', () => {
  for (const t of allTechniques()) expect(DOMAINS).toContain(t.domain)
})

// Spec 4.3, verbatim. Pinned so a re-filed or mistyped entry fails here and names itself.
// (The "appears in exactly one assignment" form needs planHunts and belongs to Task 9.)
test('every entry carries the primary domain spec 4.3 assigns it', () => {
  expect(Object.fromEntries(allTechniques().map((t) => [t.id, t.domain]))).toEqual({
    'sql-injection-built-query-string': 'injection',
    'command-injection-shell-interpolation': 'injection',
    'reflected-xss-unescaped-output': 'injection',
    'path-traversal-unvalidated-file-path': 'injection',
    'unsafe-deserialization-untrusted-payload': 'injection',
    'cross-file-taint-source-to-sink': 'injection',
    'hardcoded-secret-in-source': 'secrets',
    'vulnerable-dependency-version': 'dependencies',
    'permissive-cors-with-credentials': 'authorization',
    'entrypoint-reachability-under-auth-state': 'authorization',
    'over-permissive-agent-tool-allowlist': 'agentic',
    'debug-mode-verbose-errors': 'configuration',
    'unbounded-copy-into-fixed-buffer': 'memory-safety',
  })
})

test('the injection domain holds the cross-cutting taint entry', () => {
  const ids = allTechniques().filter((t) => t.domain === 'injection').map((t) => t.id)
  expect(ids).toContain('cross-file-taint-source-to-sink')
})
