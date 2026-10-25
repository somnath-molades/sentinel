import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from 'vitest'
import { ConsentFileError, attestationHash, attestationRefusal, isAttested, readConsent, writeConsent } from '../../src/consent/record.js'
import type { ConsentRecord } from '../../src/consent/record.js'

const dir = (): string => mkdtempSync(join(tmpdir(), 'consent-'))
const rec = (text: string): ConsentRecord => ({
  schema_version: 1, mode: 'pure-reasoning', sentinel_version: '0.1.0', attested_at: '2026-01-01T00:00:00.000Z',
  attestation_text_hash: attestationHash(text), targets: [],
})

test('round-trips a consent record', () => {
  const d = dir()
  const r = { ...rec('a'), targets: [{ target: '/x', attested_at: '2026-01-02T00:00:00.000Z', attestation_text_hash: attestationHash('a') }] }
  writeConsent(d, r)
  expect(readConsent(d)).toEqual(r)
})

test('returns null when no record exists', () => {
  expect(readConsent(dir())).toBeNull()
})

test.each([['{not json'], ['{}'], ['[]']])('a corrupt record %j is an error naming the file, never absence', (body) => {
  const d = dir()
  mkdirSync(join(d, '.sentinel'))
  writeFileSync(join(d, '.sentinel', 'consent.json'), body)
  expect(() => readConsent(d)).toThrow(ConsentFileError)
  expect(() => readConsent(d)).toThrow(/consent\.json/)
})

test('attestationRefusal names the target and how to attest it, and passes only an attested target', () => {
  const d = dir()
  const t = { kind: 'local', root: '/a' } as const
  expect(attestationRefusal(d, t, 'txt')).toMatch(/Not attested: \/a.*sentinel init "\/a"/)
  writeConsent(d, { ...rec('txt'), targets: [{ target: '/a', attested_at: 'x', attestation_text_hash: attestationHash('txt') }] })
  expect(attestationRefusal(d, t, 'txt')).toBeNull()
  expect(attestationRefusal(d, { kind: 'local', root: '/b' }, 'txt')).toMatch(/Not attested: \/b/)
  expect(attestationRefusal(d, { kind: 'github', owner: 'O', repo: 'R', root: '/tmp/x' }, 'txt')).toMatch(/github:o\/r.*https:\/\/github\.com\/O\/R/)
})

test('the hash is a sha256 of the text, and one changed character changes it', () => {
  expect(attestationHash('text')).toHaveLength(64)
  expect(attestationHash('text')).not.toBe(attestationHash('Text'))
  expect(rec('text').attestation_text_hash).toBe(attestationHash('text'))
})

test('a target is attested only for the exact target and the exact text', () => {
  const r: ConsentRecord = { ...rec('t'), targets: [{ target: '/a', attested_at: 'x', attestation_text_hash: attestationHash('t') }] }
  expect(isAttested(r, '/a', 't')).toBe(true)
  expect(isAttested(r, '/b', 't')).toBe(false)
  expect(isAttested(r, '/a', 't2')).toBe(false)
  expect(isAttested(null, '/a', 't')).toBe(false)
})

test('writing creates the record under <root>/.sentinel', () => {
  const d = dir()
  writeConsent(d, rec('a'))
  expect(existsSync(join(d, '.sentinel', 'consent.json'))).toBe(true)
})
