import { DOMAINS, STACKS, profileTarget, stackForLanguage } from '@sentinel/core'
import { fileURLToPath } from 'node:url'

const fixture = (name: string): string => fileURLToPath(new URL(`../../../../tests/fixtures/targets/${name}`, import.meta.url))

test('every mapped language lands on a real stack token; unmapped languages map to nothing', () => {
  for (const l of ['javascript', 'typescript', 'python', 'go', 'php', 'java']) expect(STACKS).toContain(stackForLanguage(l))
  expect(stackForLanguage('TypeScript')).toBe('node')
  for (const l of ['rust', 'ruby', 'csharp', 'shell', '']) expect(stackForLanguage(l)).toBeUndefined()
})

// M2: the lookup is an object index, so a prototype member must not come back as a stack.
test('a language named after a prototype member maps to nothing', () => {
  for (const l of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) expect(stackForLanguage(l)).toBeUndefined()
})

test('DOMAINS holds exactly the ten spec values', () => {
  expect([...DOMAINS].sort()).toEqual(['agentic', 'authorization', 'configuration', 'crypto', 'dependencies', 'iac', 'injection', 'memory-safety', 'secrets', 'supply-chain'])
})

test('every hotspot domain the profiler emits is a member', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') })
  for (const h of p.hotspots) for (const d of h.domains) expect(DOMAINS).toContain(d)
})
