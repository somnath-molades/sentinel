// The closed set of stack tokens a technique may use, in `stacks` and `fix_patterns[].stack`.
// Lives beside the router (its only consumer) rather than in the schema: the schema stays permissive,
// and a test (not a parse error) enforces membership, so adding a stack is one line here plus an entry.
export const STACKS = ['agent-config', 'c', 'ci', 'cpp', 'generic', 'go', 'java', 'node', 'php', 'python'] as const
// `generic` is the wildcard: a technique listing it applies to every stack.
export const WILDCARD_STACK = 'generic'
