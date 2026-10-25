import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, test } from 'vitest'
import { run } from '../src/index.js'

const badRegistry = join(fileURLToPath(new URL('../../../', import.meta.url)), 'tests/fixtures/registry/one-bad-entry')

async function cli(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = ''
  let err = ''
  const code = await run(argv, { out: (s) => void (out += s), err: (s) => void (err += s) })
  return { code, out, err }
}

describe('packs list', () => {
  test('prints every shipped pack with its license, ingestion mode and technique count', async () => {
    const r = await cli(['packs', 'list'])
    expect(r.code).toBe(0)
    for (const id of ['defending-code', 'vbsec']) expect(r.out).toContain(id)
    expect(r.out).toMatch(/license: Apache-2\.0/)
    expect(r.out).toMatch(/ingestion mode: vendored/)
    expect(r.out).toMatch(/\d+ techniques?/)
  })

  test('still lists, but reports load errors on stderr', async () => {
    const r = await cli(['packs', 'list', '--registry', badRegistry])
    expect(r.out).toContain('fixture-pack')
    expect(r.err).toMatch(/1 registry entr/)
  })
})

describe('packs audit', () => {
  test('passes on the shipped registry', async () => {
    const r = await cli(['packs', 'audit'])
    expect(r.code).toBe(0)
    expect(r.out).toMatch(/0 problems/)
  })

  test('exits non-zero and names the file when a registry entry is malformed', async () => {
    const r = await cli(['packs', 'audit', '--registry', badRegistry])
    expect(r.code).toBe(2)
    expect(r.err).toContain('missing-defensive-use.md')
  })
})
