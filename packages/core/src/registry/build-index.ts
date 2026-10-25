import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parse } from 'yaml'
import { packSchema } from '../schema/pack.js'
import { parseTechnique } from '../schema/technique.js'
import type { SchemaError, TechniqueEntry } from '../schema/technique.js'

export type IndexedTechnique = Pick<TechniqueEntry, 'id' | 'vuln_classes' | 'depth_tier' | 'stacks'> & {
  pack: string
  /** Registry-relative, forward-slash path to the entry. */
  path: string
}
export type RegistryIndex = { schema_version: 1; built_at: string; techniques: IndexedTechnique[] }

const sorted = (xs: string[]): string[] => [...xs].sort()
const reason = (e: unknown): string => (e instanceof Error ? e.message : String(e))

// Collects errors instead of throwing: one bad entry must not hide the rest of the registry.
export async function buildIndex(registryRoot: string): Promise<{ index: RegistryIndex; errors: SchemaError[] }> {
  const techniques: IndexedTechnique[] = []
  const errors: SchemaError[] = []
  const seen = new Map<string, string>()
  const packsRoot = join(registryRoot, 'packs')
  const packDirs = (await readdir(packsRoot, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name)
  for (const packDir of sorted(packDirs)) {
    const packPath = join(packsRoot, packDir)
    const manifestFile = join(packPath, 'pack.yaml')
    let packId: string
    let files: string[]
    try {
      const m = packSchema.safeParse(parse(await readFile(manifestFile, 'utf8')))
      if (!m.success) {
        errors.push({ file: manifestFile, problem: m.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ') })
        continue
      }
      packId = m.data.id
      files = sorted((await readdir(join(packPath, 'techniques'))).filter((f) => f.endsWith('.md')))
    } catch (e) {
      errors.push({ file: packPath, problem: `cannot read pack: ${reason(e)}` })
      continue
    }
    for (const f of files) {
      const file = join(packPath, 'techniques', f)
      let text: string
      try {
        text = await readFile(file, 'utf8')
      } catch (e) {
        errors.push({ file, problem: `cannot read technique file: ${reason(e)}` })
        continue
      }
      const r = parseTechnique(text, file)
      if (!r.ok) {
        errors.push(r.error)
        continue
      }
      const t = r.value
      const dup = seen.get(t.id)
      if (dup !== undefined) {
        errors.push({ file, problem: `duplicate technique id "${t.id}" (already defined in ${dup})` })
        continue
      }
      seen.set(t.id, file)
      techniques.push({ id: t.id, vuln_classes: t.vuln_classes, depth_tier: t.depth_tier, stacks: t.stacks, pack: packId, path: `packs/${packDir}/techniques/${f}` })
    }
  }
  techniques.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  return { index: { schema_version: 1, built_at: new Date().toISOString(), techniques }, errors }
}
