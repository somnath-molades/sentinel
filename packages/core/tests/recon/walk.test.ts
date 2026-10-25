import { execFileSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { walkTarget } from '../../src/recon/walk.js'

const fixture = (name: string): string => fileURLToPath(new URL(`../../../../tests/fixtures/targets/${name}`, import.meta.url))

async function tmpRoot(): Promise<string> {
  return mkdtemp(join(await realpath(tmpdir()), 'sentinel-walk-'))
}

test('skips vendored, generated, minified and oversized files with reasons', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  const reasons = Object.fromEntries(r.skipped.map((s) => [basename(s.path), s.reason]))
  expect(reasons['app.min.js']).toBe('minified')
  expect(reasons['pnpm-lock.yaml']).toBe('generated')
  expect(reasons['logo.png']).toBe('binary')
  expect(reasons['huge.json']).toBe('too-large')
  expect(r.skipped.some((s) => s.path.includes('node_modules'))).toBe(true)
})

test('records every remaining skip class with its own reason', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  const reasons = Object.fromEntries(r.skipped.map((s) => [basename(s.path), s.reason]))
  expect(reasons['node_modules']).toBe('vendored')
  expect(reasons['dist']).toBe('generated')
  expect(reasons['blob.dat']).toBe('binary') // NUL byte, no telltale extension
  expect(reasons['latin1.txt']).toBe('not-utf8')
  expect(reasons['escape']).toBe('not-regular')
  expect(r.files.map((f) => f.path)).toEqual(['ok.js'])
  expect(r.truncated).toBe(false)
})

test('does not follow symlinks out of the root', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  expect(r.files.every((f) => !f.path.startsWith('/etc'))).toBe(true)
  expect(r.files.some((f) => f.path.includes('escape'))).toBe(false)
})

test('does not follow any symlink, even one that stays inside the root, and says so', async () => {
  const root = await tmpRoot()
  try {
    await writeFile(join(root, 'real.js'), 'const a = 1\n')
    await symlink(join(root, 'real.js'), join(root, 'alias.js'))
    await mkdir(join(root, 'dir'))
    await symlink(join(root, 'dir'), join(root, 'dir-alias'))
    const r = await walkTarget(root)
    expect(r.files.map((f) => f.path)).toEqual(['real.js'])
    expect(r.skipped).toEqual([
      { path: 'alias.js', reason: 'not-regular' },
      { path: 'dir-alias', reason: 'not-regular' },
    ])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a FIFO is skipped without being opened (opening would block)', async () => {
  const root = await tmpRoot()
  try {
    execFileSync('mkfifo', [join(root, 'pipe')])
    const r = await walkTarget(root)
    expect(r.files).toEqual([])
    expect(r.skipped).toEqual([{ path: 'pipe', reason: 'not-regular' }])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test.skipIf(process.getuid?.() === 0)('an unreadable file is recorded, not silently dropped', async () => {
  const root = await tmpRoot()
  try {
    await writeFile(join(root, 'secret.js'), 'x')
    await chmod(join(root, 'secret.js'), 0o000)
    const r = await walkTarget(root)
    expect(r.files).toEqual([])
    expect(r.skipped).toEqual([{ path: 'secret.js', reason: 'unreadable' }])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('sets truncated when maxFiles is hit', async () => {
  const r = await walkTarget(fixture('express-vulnerable'), { maxFiles: 2 })
  expect(r.truncated).toBe(true)
  expect(r.files).toHaveLength(2)
})

test('does not set truncated when the cap equals the file count exactly', async () => {
  const all = await walkTarget(fixture('express-vulnerable'))
  const r = await walkTarget(fixture('express-vulnerable'), { maxFiles: all.files.length })
  expect(r.truncated).toBe(false)
  expect(r.files).toHaveLength(all.files.length)
})

test('non-UTF8 file is skipped, not decoded', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  expect(r.skipped).toContainEqual({ path: 'latin1.txt', reason: 'not-utf8' })
  expect(r.files.some((f) => f.path === 'latin1.txt')).toBe(false)
})

test('a multi-byte character split by the prefix boundary is still valid UTF-8', async () => {
  const root = await tmpRoot()
  try {
    // 65535 ASCII bytes then a 3-byte char straddling the 64KiB prefix edge.
    await writeFile(join(root, 'edge.txt'), 'a\n'.repeat(32767) + 'a' + '€')
    const r = await walkTarget(root)
    expect(r.skipped).toEqual([])
    expect(r.files).toHaveLength(1)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('paths are root-relative and languages come from extension', async () => {
  const r = await walkTarget(fixture('express-vulnerable'))
  const server = r.files.find((f) => f.path === 'src/server.js')
  expect(server?.language).toBe('javascript')
  expect(r.files.find((f) => f.path === 'package.json')?.language).toBeNull()
})
