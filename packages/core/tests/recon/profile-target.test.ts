import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { profileTarget } from '../../src/recon/profile-target.js'
import { targetProfileSchema } from '../../src/schema/target-profile.js'

const fixture = (name: string): string => fileURLToPath(new URL(`../../../../tests/fixtures/targets/${name}`, import.meta.url))

test('header files are recognised, not counted as unexamined', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('c-memory-safety') })
  expect(p.skipped.some((s) => s.path.endsWith('.h'))).toBe(false)
  // An unrecognised .h is never in `skipped`; it lands in files with no language. greet.c + greet.h must both count as c.
  expect(p.languages.find((l) => l.language === 'c')?.files).toBe(2)
})

// Spec 6.4: without a safe counterpart for each planted defect, "it found the real thing"
// would pass against a tool that flags every route and every query. This is a tripwire against
// the controls being deleted, not a behaviour test — it asserts the fixture's content.
// The controls only become meaningful when a hunt asserts the safe lines are NOT reported.
test('the fixture contains both a vulnerable and a safe form of each planted class', async () => {
  const src = await readFile(join(fixture('express-vulnerable'), 'src/server.js'), 'utf8')
  expect(src).toMatch(/\.query\([^)]*\$1/) // a value bound as a parameter, not interpolated
  expect(src).toMatch(/app\.delete\([^)]*requireAuth,/) // the check is APPLIED to a route, not merely defined
  expect(src).toMatch(/jwt\.verify\(/) // and it validates the token rather than just its presence
  expect(src).toMatch(/user_id = \$2/) // the authorized route also checks ownership
  // The defects must survive: concatenated SQL and an unauthenticated destructive route.
  expect(src).toMatch(/SELECT \* FROM users WHERE name = '" \+ req\.query\.name/)
  expect(src).toMatch(/DELETE FROM users WHERE id = ' \+ req\.params\.id/)
})

test('profiles an express app', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') })
  expect(p.frameworks).toContain('express')
  expect(p.languages[0]?.language).toBe('javascript')
  expect(p.entrypoints.some((e) => e.kind === 'http-route')).toBe(true)
  expect(p.hotspots.some((h) => h.domains.includes('authorization'))).toBe(true)
  expect(targetProfileSchema.safeParse(p).success).toBe(true)
})

test('express profile covers data layer, auth, CI, secrets and routes', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') })
  expect(p.data_layer).toContain('postgres')
  expect(p.auth_surfaces).toContain('jsonwebtoken')
  expect(p.ci).toContain('github-actions')
  expect(p.entrypoints.map((e) => e.detail)).toEqual(expect.arrayContaining(['GET /users', 'DELETE /users/:id']))
  expect(p.hotspots.find((h) => h.path === '.env')?.domains).toContain('secrets')
  expect(p.hotspots.find((h) => h.path === 'src/server.js')?.domains).toEqual(expect.arrayContaining(['authorization', 'injection']))
  expect(p.hotspots.some((h) => h.path === 'src/util.js')).toBe(false)
  expect(JSON.stringify(p)).not.toContain('hunter2') // secret values never enter the profile
})

test('generated_at is ISO 8601 and coverage fields flow through', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('hostile-files') })
  expect(new Date(p.generated_at).toISOString()).toBe(p.generated_at)
  expect(p.skipped.length).toBeGreaterThan(0)
  expect(p.file_count).toBe(1)
  const t = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') }, { maxFiles: 1 })
  expect(t.truncated).toBe(true)
})

// Sentinel's own repository holds fixture manifests (tests/fixtures/targets/*); they are test data, not the project's stack.
test('manifests under fixture directories do not declare the target stack', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'sentinel-fx-'))
  try {
    await mkdir(join(root, 'tests/fixtures/app'), { recursive: true })
    await writeFile(join(root, 'tests/fixtures/app/package.json'), JSON.stringify({ dependencies: { express: '4.0.0' } }))
    await writeFile(join(root, 'package.json'), JSON.stringify({ dependencies: { fastify: '4.0.0' } }))
    const p = await profileTarget({ kind: 'local', root })
    expect(p.frameworks).toEqual(['fastify'])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

// Git cannot commit an empty directory, so this fixture is built in a temp dir; a committed one would silently not exist in a clone.
test('an empty repo profiles honestly instead of crashing', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'sentinel-empty-'))
  try {
    await mkdir(join(root, '.git'))
    const p = await profileTarget({ kind: 'local', root })
    expect(p.languages).toEqual([])
    expect(p.frameworks).toEqual([])
    expect(p.entrypoints).toEqual([])
    expect(p.hotspots).toEqual([])
    expect(p.file_count).toBe(0)
    expect(p.truncated).toBe(false)
    expect(targetProfileSchema.safeParse(p).success).toBe(true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
