import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildIndex, parseTechnique, STACKS } from '@sentinel/core'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..')
const registryRoot = resolve(repoRoot, 'registry')
const fixture = (p: string): string => resolve(repoRoot, 'tests/fixtures', p)

test('indexes every valid technique in the real registry', async () => {
  const { index, errors } = await buildIndex(registryRoot)
  expect(errors).toEqual([])
  expect(index.techniques.length).toBeGreaterThanOrEqual(12)
})

test('one malformed entry is reported but the rest still index', async () => {
  const { index, errors } = await buildIndex(fixture('registry/one-bad-entry'))
  expect(errors).toHaveLength(1)
  expect(errors[0]?.file).toContain('missing-defensive-use')
  expect(index.techniques.map((t) => t.id)).toEqual(['sql-injection-string-concat'])
})

test('index order does not depend on filesystem order', async () => {
  const { index } = await buildIndex(registryRoot)
  const ids = index.techniques.map((t) => t.id)
  expect(ids).toEqual([...ids].sort())
})

test('the committed registry/index.json matches a fresh build (run `pnpm gen:index` if not)', async () => {
  const { index } = await buildIndex(registryRoot)
  const committed = JSON.parse(readFileSync(join(registryRoot, 'index.json'), 'utf8')) as typeof index
  // built_at is a wall-clock stamp and legitimately differs.
  expect({ ...committed, built_at: '' }).toEqual({ ...index, built_at: '' })
})

// R22: an unlisted token (e.g. `nodejs`) validates but silently never matches any query.
test('every stack string in the registry belongs to the fixed vocabulary', () => {
  const vocab: readonly string[] = STACKS
  for (const pack of readdirSync(join(registryRoot, 'packs'))) {
    const dir = join(registryRoot, 'packs', pack, 'techniques')
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.md'))) {
      const r = parseTechnique(readFileSync(join(dir, f), 'utf8'), f)
      if (!r.ok) throw new Error(r.error.problem)
      for (const s of [...r.value.stacks, ...r.value.fix_patterns.map((p) => p.stack)]) {
        expect(vocab, `${f}: unknown stack "${s}"`).toContain(s)
      }
    }
  }
})

test('an unreadable technique file is reported and the rest still index', async () => {
  // Not prefixed `sentinel-`: the clone-cleanup tests in other files assert on a listing of
  // os.tmpdir() filtered by that prefix, and a fixture left here showed up as a phantom leaked
  // clone. Removed afterwards too — leaving these behind accumulated 50 of them over the phase.
  const root = mkdtempSync(join(tmpdir(), 'idx-fixture-'))
  try {
    cpSync(fixture('registry/one-bad-entry'), root, { recursive: true })
    mkdirSync(join(root, 'packs/fixture-pack/techniques/unreadable.md')) // EISDIR on read
    const { index, errors } = await buildIndex(root)
    expect(errors.map((e) => e.file).join()).toContain('unreadable.md')
    expect(index.techniques.map((t) => t.id)).toEqual(['sql-injection-string-concat'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
