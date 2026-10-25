import { realpathSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { resolveTarget } from '../../src/scope/resolve-target.js'
import type { GhRunner } from '../../src/scope/resolve-target.js'

const fixtureDir = fileURLToPath(new URL('../../../../tests/fixtures/scope', import.meta.url))

// Stub gh: records calls, never touches the network.
function stubGh(code: number, stdout = '{"nameWithOwner":"someone/private"}') {
  const calls: string[][] = []
  const run: GhRunner = async (args) => {
    calls.push(args)
    return { code, stdout }
  }
  return { run, calls }
}

function refusal(r: Awaited<ReturnType<typeof resolveTarget>>): string {
  if (r.ok) throw new Error('expected refusal')
  return r.error.reason
}

test('accepts an existing local directory', async () => {
  const r = await resolveTarget(fixtureDir)
  if (!r.ok) throw new Error(r.error.reason)
  expect(r.value).toEqual({ kind: 'local', root: realpathSync(fixtureDir) })
})

test('accepts a trailing slash and a .. that stays inside', async () => {
  const r = await resolveTarget(join(fixtureDir, 'x', '..') + '/')
  expect(r.ok).toBe(true)
})

test('refuses a path that does not exist', async () => {
  expect((await resolveTarget('/nope/nothing')).ok).toBe(false)
})

test('refuses a file and empty input', async () => {
  expect((await resolveTarget(join(fixtureDir, 'file.txt'))).ok).toBe(false)
  expect((await resolveTarget('')).ok).toBe(false)
  expect((await resolveTarget('a\0b')).ok).toBe(false)
})

test('refuses a symlink escaping the given root', async () => {
  // fixture: <dir>/escape -> /etc
  expect(refusal(await resolveTarget(join(fixtureDir, 'escape')))).toMatch(/outside|escape/i)
  expect((await resolveTarget(join(fixtureDir, 'escape') + '/')).ok).toBe(false)
})

test('refuses a bare http(s) URL that is not a GitHub repo', async () => {
  const gh = stubGh(0)
  expect((await resolveTarget('https://example.com/app', { allowGitHub: true, gh: gh.run })).ok).toBe(false)
  expect((await resolveTarget('https://example.com/app')).ok).toBe(false)
  expect(gh.calls).toEqual([])
})

test('refuses GitHub lookalikes, credentials, ports and odd shapes without calling gh', async () => {
  const gh = stubGh(0)
  for (const u of [
    'https://github.com.evil.com/a/b',
    'https://evil.com/github.com/a/b',
    'https://github.com@evil.com/a/b',
    'https://user:pw@github.com/a/b',
    'http://github.com/a/b',
    'https://github.com:8443/a/b',
    'https://github.com/a',
    'https://github.com/a/b/c',
    'https://github.com/a/b?x=1',
    'https://github.com/-a/b',
    'https://github.com/a/..',
    'git@github.com:a/b.git',
    'ssh://git@github.com/a/b',
    'file:///etc',
    'a/b',
  ]) {
    expect([u, (await resolveTarget(u, { allowGitHub: true, gh: gh.run })).ok]).toEqual([u, false])
  }
  expect(gh.calls).toEqual([])
})

test('refuses a GitHub repo the authenticated user cannot access', async () => {
  const gh = stubGh(1)
  const r = await resolveTarget('https://github.com/someone/private', { allowGitHub: true, gh: gh.run })
  expect(refusal(r)).toMatch(/access|authoriz/i)
  expect(gh.calls).toEqual([['repo', 'view', 'someone/private', '--json', 'nameWithOwner']])
})

test('refuses when the gh runner throws or returns unexpected output', async () => {
  const boom: GhRunner = async () => {
    throw new Error('gh missing')
  }
  expect((await resolveTarget('https://github.com/a/b', { allowGitHub: true, gh: boom })).ok).toBe(false)
  const odd = stubGh(0, '{"nameWithOwner":"other/thing"}')
  expect((await resolveTarget('https://github.com/a/b', { allowGitHub: true, gh: odd.run })).ok).toBe(false)
  const junk = stubGh(0, 'not json')
  expect((await resolveTarget('https://github.com/a/b', { allowGitHub: true, gh: junk.run })).ok).toBe(false)
})

test('refuses a GitHub target when allowGitHub is not set', async () => {
  const gh = stubGh(0)
  const r = await resolveTarget('https://github.com/someone/public', { gh: gh.run })
  expect(r.ok).toBe(false)
  expect(gh.calls).toEqual([])
})

test('accepts an accessible GitHub repo, cloning via the runner into a temp dir', async () => {
  const calls: string[][] = []
  const run: GhRunner = async (args) => {
    calls.push(args)
    return { code: 0, stdout: '{"nameWithOwner":"Someone/Public"}' }
  }
  const r = await resolveTarget('https://github.com/someone/public.git/', { allowGitHub: true, gh: run })
  if (!r.ok) throw new Error(r.error.reason)
  try {
    if (r.value.kind !== 'github') throw new Error('expected github')
    expect([r.value.owner, r.value.repo]).toEqual(['someone', 'public'])
    expect(calls[1]).toEqual(['repo', 'clone', 'someone/public', r.value.root, '--', '--depth', '1'])
    expect(dirname(dirname(r.value.root))).toBe(realpathSync(tmpdir()))
  } finally {
    await rm(dirname(r.value.root), { recursive: true, force: true })
  }
})

test('refuses and leaves no temp dir when the clone fails', async () => {
  let target = ''
  const run: GhRunner = async (args) => {
    if (args[1] === 'clone') {
      target = args[3] ?? ''
      return { code: 1, stdout: '' }
    }
    return { code: 0, stdout: '{"nameWithOwner":"a/b"}' }
  }
  expect((await resolveTarget('https://github.com/a/b', { allowGitHub: true, gh: run })).ok).toBe(false)
  const { existsSync } = await import('node:fs')
  expect(target).not.toBe('')
  expect(existsSync(dirname(target))).toBe(false)
})
