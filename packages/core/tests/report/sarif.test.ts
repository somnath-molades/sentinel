import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { Ajv } from 'ajv'
import { toSarif } from '@sentinel/core'
import { confirmedCount, findings, profile } from './helpers.js'

test('emits SARIF 2.1.0 with one result per confirmed finding', () => {
  const log = toSarif(findings, profile, { mode: 'full' })
  expect(log.version).toBe('2.1.0')
  expect(log.runs[0]!.tool.driver.name).toBe('Sentinel')
  expect(log.runs[0]!.results).toHaveLength(confirmedCount)
})

test('excludes dropped and needs-review findings from results', () => {
  const ids = toSarif(findings, profile, { mode: 'full' }).runs[0]!.results.map((r) => r.ruleId)
  expect(ids).not.toContain('ssrf')
  expect(ids).not.toContain('csrf')
})

test('one rule per distinct technique, and levels follow the severity band', () => {
  const run = toSarif(findings, profile, { mode: 'full' }).runs[0]!
  expect(run.tool.driver.rules.map((r) => r.id).sort()).toEqual(['sqli', 'xss'])
  expect(run.results.map((r) => r.level)).toEqual(['error', 'note'])
})

test('every result carries a physical location with a line', () => {
  for (const r of toSarif(findings, profile, { mode: 'full' }).runs[0]!.results) {
    expect(r.locations[0]!.physicalLocation.region.startLine).toBeGreaterThan(0)
  }
})

test('additional_locations become further entries in result.locations', () => {
  const r = toSarif(findings, profile, { mode: 'full' }).runs[0]!.results[0]!
  expect(r.locations.map((l) => l.physicalLocation.region.startLine)).toEqual([40, 90])
})

test('coverage gaps travel with the log', () => {
  const log = toSarif(findings, { ...profile, truncated: true, skipped: [{ path: 'shared', reason: 'symlink' }] }, { mode: 'full' })
  expect(log.runs[0]!.properties.coverage).toMatchObject({ truncated: true, skipped: { symlink: 1 } })
})

test('validates against the SARIF 2.1.0 JSON schema', () => {
  const path = fileURLToPath(new URL('../../../../tests/fixtures/sarif-schema-2.1.0.json', import.meta.url))
  const schema = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  // The official schema is JSON Schema draft-04; ajv 8 speaks draft-07+, and the only draft-04
  // keyword it uses at the top level is `id` (now `$id`).
  schema.$id = schema.id
  delete schema.id
  delete schema.$schema
  const validate = new Ajv({ strict: false, allErrors: true, validateFormats: false }).compile(schema)
  const log = toSarif(findings, profile, { mode: 'full' })
  expect(validate(log), JSON.stringify(validate.errors)).toBe(true)
  // The validator must be able to say no.
  expect(validate({ ...log, version: '2.0.0' })).toBe(false)
  expect(validate(toSarif([], profile, { mode: 'full' }))).toBe(true)
})
