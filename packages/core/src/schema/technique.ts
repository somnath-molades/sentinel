import { parse } from 'yaml'
import { z } from 'zod'
import type { Result } from '../types.js'

export const DEPTH_TIERS = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5'] as const
export type DepthTier = (typeof DEPTH_TIERS)[number]

const fixPatternSchema = z.object({
  stack: z.string().min(1),
  tier: z.enum(['mechanical', 'guided', 'design-change']),
  guidance: z.string().min(1),
}).strict()
export type FixPattern = z.infer<typeof fixPatternSchema>

export const techniqueSchema = z.object({
  id: z.string().min(1),
  vuln_classes: z.array(z.string().min(1)),
  cwe: z.array(z.string()).optional(),
  depth_tier: z.enum(DEPTH_TIERS, { error: (iss) => `unknown depth_tier ${JSON.stringify(iss.input)}; expected one of ${DEPTH_TIERS.join(', ')}` }),
  stacks: z.array(z.string().min(1)),
  detection: z.string().trim().min(1),
  verification: z.string().trim().min(1),
  // Mandatory: this is what keeps the registry defensive. Do not make it optional.
  defensive_use: z.string().trim().min(1),
  fix_patterns: z.array(fixPatternSchema).min(1),
  references: z.array(z.string()),
  provenance: z.object({ pack: z.string().min(1), upstream_commit: z.string().optional() }).strict(),
})
export type TechniqueEntry = z.infer<typeof techniqueSchema>

// What the YAML frontmatter may contain: everything except the three prose fields, which must
// come from `##` body sections so reviewers read them as prose. Strict: unknown keys are errors.
export const frontmatterSchema = techniqueSchema
  .omit({ detection: true, verification: true, defensive_use: true })
  .strict()

export type SchemaError = { file: string; problem: string }

const PROSE_FIELDS = ['detection', 'verification', 'defensive_use']

// Splits the body on `## ` headings; "Defensive use" becomes the key `defensive_use`.
function proseSections(body: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const chunk of body.split(/^## /m).slice(1)) {
    const nl = chunk.indexOf('\n')
    const heading = (nl === -1 ? chunk : chunk.slice(0, nl)).trim().toLowerCase().replace(/\s+/g, '_')
    if (PROSE_FIELDS.includes(heading)) out[heading] = (nl === -1 ? '' : chunk.slice(nl + 1)).trim()
  }
  return out
}

export function parseTechnique(markdown: string, source: string): Result<TechniqueEntry, SchemaError> {
  const err = (problem: string): Result<TechniqueEntry, SchemaError> => ({ ok: false, error: { file: source, problem } })
  const m = /^---\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n([\s\S]*))?$/.exec(markdown)
  if (!m) return err('missing YAML frontmatter (file must start with a --- block)')
  let front: unknown
  try {
    front = parse(m[1] ?? '')
  } catch (e) {
    return err(`invalid YAML frontmatter: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (typeof front !== 'object' || front === null || Array.isArray(front)) return err('frontmatter must be a YAML mapping')
  const misplaced = PROSE_FIELDS.filter((k) => k in front)
  if (misplaced.length > 0) {
    return err(`${misplaced.join(', ')}: must be a "## " section in the body, not a frontmatter key`)
  }
  const f = frontmatterSchema.safeParse(front)
  if (!f.success) return err(formatIssues(f.error))
  const r = techniqueSchema.safeParse({ ...f.data, ...proseSections(m[2] ?? '') })
  if (r.success) return { ok: true, value: r.data }
  return err(formatIssues(r.error))
}

function formatIssues(e: z.ZodError): string {
  return e.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')
}
