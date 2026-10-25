// The closed set of stack tokens a technique may use, in `stacks` and `fix_patterns[].stack`.
// Lives beside the router (its only consumer) rather than in the schema: the schema stays permissive,
// and a test (not a parse error) enforces membership, so adding a stack is one line here plus an entry.
export const STACKS = ['agent-config', 'c', 'ci', 'cpp', 'generic', 'go', 'java', 'node', 'php', 'python'] as const
// `generic` is the wildcard: a technique listing it applies to every stack.
export const WILDCARD_STACK = 'generic'

// The one domain vocabulary, shared by hotspots (profile side) and technique entries (registry side), so
// dispatch can match them. Hotspots emit a subset today; entries may use all ten. `memory-safety` and
// `configuration` exist because the original eight, chosen for marking hotspots, could not house two shipped techniques.
// A single list on purpose: two parallel lists are how Phase 1's coverage texts drifted apart.
export const DOMAINS = [
  'authorization',
  'injection',
  'secrets',
  'dependencies',
  'iac',
  'supply-chain',
  'crypto',
  'agentic',
  'memory-safety',
  'configuration',
] as const
export type Domain = (typeof DOMAINS)[number]

// profileTarget emits language names; the router speaks STACKS. This is the only bridge between them,
// so every harness wrapper shares it. A language absent here has no stack: callers must surface that, not guess.
const LANGUAGE_STACK: Record<string, (typeof STACKS)[number]> = {
  javascript: 'node',
  typescript: 'node',
  python: 'python',
  go: 'go',
  php: 'php',
  java: 'java',
}
export const KNOWN_LANGUAGES: readonly string[] = Object.keys(LANGUAGE_STACK)
// Own-property guard: a language named `__proto__` or `constructor` must be undefined here, not a prototype member.
export const stackForLanguage = (language: string): (typeof STACKS)[number] | undefined => {
  const key = language.toLowerCase()
  return Object.hasOwn(LANGUAGE_STACK, key) ? LANGUAGE_STACK[key] : undefined
}
