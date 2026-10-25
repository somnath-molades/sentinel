import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { Ajv } from 'ajv'
import { toSarif } from '@sentinel/core'
import { findings, profile } from './helpers.js'

test('location uris are percent-encoded and backslashes normalised', () => {
  const f = { ...findings[0]!, file: 'src\\my dir\\a#b?c%d.ts', additional_locations: [] }
  const uri = toSarif([f], profile, { mode: 'full' }).runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri
  expect(uri).toBe('src/my%20dir/a%23b%3Fc%25d.ts')
})

test('candidates are excluded from results', () => {
  const cand = { ...findings[0]!, id: 'x', status: 'candidate' as const }
  expect(toSarif([cand], profile, { mode: 'full' }).runs[0]!.results).toHaveLength(0)
})

test('the mode is recorded so an empty pure-reasoning log is not read as all clear', () => {
  const p = toSarif([], profile, { mode: 'pure-reasoning' }).runs[0]!.properties
  expect(p.mode).toBe('pure-reasoning')
  expect(p.not_checked.join(' ')).toMatch(/dependency CVE/)
  expect(p.not_checked.join(' ')).toMatch(/secret/)
  expect(toSarif([], profile, { mode: 'full' }).runs[0]!.properties.not_checked).toEqual([])
})

test('the schema rejects the errors that matter', () => {
  const path = fileURLToPath(new URL('../../../../tests/fixtures/sarif-schema-2.1.0.json', import.meta.url))
  const schema = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  schema.$id = schema.id
  delete schema.id
  delete schema.$schema
  const validate = new Ajv({ strict: false, allErrors: true, validateFormats: false }).compile(schema)
  type R = Record<string, unknown> & { locations: { physicalLocation: { region: { startLine: number } } }[] }
  const mutate = (fn: (r: R) => void): unknown => {
    const log = structuredClone(toSarif(findings, profile, { mode: 'full' })) as unknown as { runs: { results: R[] }[] }
    fn(log.runs[0]!.results[0]!)
    return log
  }
  expect(validate(mutate(() => {}))).toBe(true)
  expect(validate(mutate((r) => void delete r.message))).toBe(false)
  expect(validate(mutate((r) => void (r.locations[0]!.physicalLocation.region.startLine = 0)))).toBe(false)
  expect(validate(mutate((r) => void (r.bogus = 1)))).toBe(false)
})
