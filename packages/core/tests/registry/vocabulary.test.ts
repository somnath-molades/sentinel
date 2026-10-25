import { STACKS, stackForLanguage } from '@sentinel/core'

test('every mapped language lands on a real stack token; unmapped languages map to nothing', () => {
  for (const l of ['javascript', 'typescript', 'python', 'go', 'php', 'java']) expect(STACKS).toContain(stackForLanguage(l))
  expect(stackForLanguage('TypeScript')).toBe('node')
  for (const l of ['rust', 'ruby', 'csharp', 'shell', '']) expect(stackForLanguage(l)).toBeUndefined()
})

// M2: the lookup is an object index, so a prototype member must not come back as a stack.
test('a language named after a prototype member maps to nothing', () => {
  for (const l of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) expect(stackForLanguage(l)).toBeUndefined()
})
