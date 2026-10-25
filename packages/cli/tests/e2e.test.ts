import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, expect, test } from 'vitest'

// Real binary, clean state: a fresh working directory holds no consent record, exactly as for a new user.
const root = fileURLToPath(new URL('../../../', import.meta.url))
const bin = join(root, 'packages/cli/dist/bin.js')
const express = join(root, 'tests/fixtures/targets/express-vulnerable')

let cwd: string
beforeAll(async () => void (cwd = await mkdtemp(join(tmpdir(), 'e2e-'))))
afterAll(() => rm(cwd, { recursive: true, force: true }))

function sentinel(args: string[], stdin = ''): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [bin, ...args], { cwd, maxBuffer: 64 * 1024 * 1024 }, (e, stdout, stderr) =>
      resolve({ code: e ? (typeof e.code === 'number' ? e.code : 1) : 0, stdout, stderr }),
    )
    child.stdin?.end(stdin)
  })
}

test('scan is refused before init, then init and scan produce a report on a fixture target', async () => {
  const refused = await sentinel(['scan', express])
  expect(refused.code).toBe(2)
  expect(refused.stderr).toMatch(/Refused \(attestation\)/) // a missing build would fail differently
  expect((await sentinel(['init', express], 'yes\nno\n')).code).toBe(0)
  const { code, stdout } = await sentinel(['scan', express])
  expect(code).toBe(0)
  expect(stdout).toMatch(/## Coverage/)
  expect(stdout).toMatch(/pure-reasoning/)
  expect(stdout).toMatch(/dependency CVE/)
}, 30_000)

test('Sentinel scans itself and the pipeline completes without a threshold', async () => {
  expect((await sentinel(['init', root], 'yes\nno\n')).code).toBe(0)
  const { code, stdout } = await sentinel(['scan', root])
  expect(code).toBe(0)
  expect(stdout).toMatch(/## Coverage/)
  expect(stdout).toMatch(/No hunter agents exist in this build/) // the single most important caveat the product emits
}, 60_000)
