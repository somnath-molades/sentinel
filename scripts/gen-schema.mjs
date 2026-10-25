// Emits registry/schema/technique.schema.json from the zod schema (run via `pnpm gen:schema`, which builds first).
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { z } from '../packages/core/node_modules/zod/index.js'
import { frontmatterSchema } from '../packages/core/dist/schema/technique.js'

const out = fileURLToPath(new URL('../registry/schema/technique.schema.json', import.meta.url))
mkdirSync(fileURLToPath(new URL('../registry/schema/', import.meta.url)), { recursive: true })
writeFileSync(out, JSON.stringify(z.toJSONSchema(frontmatterSchema), null, 2) + '\n')
