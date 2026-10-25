import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { packSchema } from '@sentinel/core'
import { parse } from 'yaml'
import { loadRegistry, registryWarning } from '../context.js'
import type { Ctx } from '../context.js'

export async function packsList(registry: string | undefined, { io, defaultRegistry }: Ctx): Promise<number> {
  const root = registry ?? defaultRegistry
  const { index, errors } = await loadRegistry(root)
  const packsRoot = join(root, 'packs')
  for (const dir of (await readdir(packsRoot, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name).sort()) {
    // A pack whose manifest is invalid is already in `errors`; it is simply not listable.
    const m = packSchema.safeParse(parse(await readFile(join(packsRoot, dir, 'pack.yaml'), 'utf8').catch(() => '')))
    if (!m.success) continue
    const n = index.techniques.filter((t) => t.pack === m.data.id).length
    io.out(`${m.data.id} (${m.data.name})\n  license: ${m.data.license}\n  ingestion mode: ${m.data.ingestion_mode}\n  trust tier: ${m.data.trust_tier}\n  ${n} technique${n === 1 ? '' : 's'} loaded\n`)
  }
  if (errors.length) io.err(`warning: ${registryWarning(errors)}\n`)
  return 0
}

export async function packsAudit(registry: string | undefined, { io, defaultRegistry }: Ctx): Promise<number> {
  const { index, errors } = await loadRegistry(registry ?? defaultRegistry)
  io.out(`${index.techniques.length} techniques loaded, ${errors.length} problems\n`)
  if (errors.length) io.err(`${registryWarning(errors)}\n`)
  return errors.length ? 2 : 0
}
