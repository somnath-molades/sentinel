import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const read = (f: string): string => readFileSync(resolve(repoRoot, f), 'utf8')

const REQUIRED = ['LICENSE', 'AUTHORIZATION.md', 'TERMS.md', 'ACCEPTABLE-USE.md', 'SECURITY.md', 'NOTICE']

test.each(REQUIRED)('%s exists and is non-trivial', (f) => {
  expect(read(f).length).toBeGreaterThan(200)
})

test('LICENSE is MIT', () => {
  expect(read('LICENSE')).toContain('MIT License')
})

test('AUTHORIZATION.md states the mechanical scope limit', () => {
  const t = read('AUTHORIZATION.md')
  expect(t).toMatch(/local (filesystem )?path/i)
  expect(t).toMatch(/refus/i)
})

test.each(REQUIRED.filter((f) => f !== 'LICENSE'))('%s opens with the not-legal-advice notice', (f) => {
  expect(read(f).slice(0, 400)).toMatch(/not legal advice[\s\S]*pending review by qualified counsel/i)
})
