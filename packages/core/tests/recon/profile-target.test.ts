import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { profileTarget } from '../../src/recon/profile-target.js'
import { targetProfileSchema } from '../../src/schema/target-profile.js'

const fixture = (name: string): string => fileURLToPath(new URL(`../../../../tests/fixtures/targets/${name}`, import.meta.url))

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
