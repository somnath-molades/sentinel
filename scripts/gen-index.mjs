// Writes registry/index.json (run via `pnpm gen:index`, which builds first). Fails on any registry error.
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { buildIndex } from '../packages/core/dist/index.js'

const root = fileURLToPath(new URL('../registry', import.meta.url))
const { index, errors } = await buildIndex(root)
if (errors.length > 0) {
  console.error(errors.map((e) => `${e.file}: ${e.problem}`).join('\n'))
  process.exit(1)
}
writeFileSync(`${root}/index.json`, JSON.stringify(index, null, 2) + '\n')
