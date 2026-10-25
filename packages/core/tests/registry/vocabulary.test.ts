import { STACKS, stackForLanguage } from '@sentinel/core'

test('every mapped language lands on a real stack token; unmapped languages map to nothing', () => {
  for (const l of ['javascript', 'typescript', 'python', 'go', 'php', 'java']) expect(STACKS).toContain(stackForLanguage(l))
  expect(stackForLanguage('TypeScript')).toBe('node')
  for (const l of ['rust', 'ruby', 'csharp', 'shell', '']) expect(stackForLanguage(l)).toBeUndefined()
})
