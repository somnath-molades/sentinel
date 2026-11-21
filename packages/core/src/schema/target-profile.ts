import { z } from 'zod'
import { DOMAINS } from '../registry/vocabulary.js'
import type { ResolvedTarget } from '../scope/resolve-target.js'

// Strict throughout: a misspelled field must fail loudly, not be silently stripped.
const targetSchema: z.ZodType<ResolvedTarget> = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('local'), root: z.string().min(1) }).strict(),
  z.object({ kind: z.literal('github'), owner: z.string().min(1), repo: z.string().min(1), root: z.string().min(1) }).strict(),
])

const langStatSchema = z.object({ language: z.string().min(1), files: z.number().int().nonnegative(), bytes: z.number().int().nonnegative() }).strict()
export type LangStat = z.infer<typeof langStatSchema>

const entrypointSchema = z
  .object({ path: z.string().min(1), kind: z.enum(['http-route', 'cli', 'job', 'webhook', 'serverless']), detail: z.string().optional() })
  .strict()
export type Entrypoint = z.infer<typeof entrypointSchema>

const hotspotSchema = z.object({ path: z.string().min(1), reason: z.string().min(1), domains: z.array(z.enum(DOMAINS)) }).strict()
export type Hotspot = z.infer<typeof hotspotSchema>

// Closed on purpose: every reason must be one the report can render.
const skipRecordSchema = z
  .object({ path: z.string().min(1), reason: z.enum(['minified', 'vendored', 'generated', 'binary', 'too-large', 'not-utf8', 'symlink', 'not-regular', 'unreadable']) })
  .strict()
export type SkipRecord = z.infer<typeof skipRecordSchema>

export const targetProfileSchema = z
  .object({
    schema_version: z.literal(1),
    target: targetSchema,
    generated_at: z.iso.datetime(), // cached profiles are read back and printed in reports; reject "yesterday"
    languages: z.array(langStatSchema),
    frameworks: z.array(z.string()),
    entrypoints: z.array(entrypointSchema),
    auth_surfaces: z.array(z.string()),
    data_layer: z.array(z.string()),
    iac: z.array(z.string()),
    ci: z.array(z.string()),
    client_boundary: z.array(z.string()),
    hotspots: z.array(hotspotSchema),
    // Coverage honesty: both are required so a profile cannot omit what Sentinel did not look at.
    skipped: z.array(skipRecordSchema),
    file_count: z.number().int().nonnegative(),
    truncated: z.boolean(),
  })
  .strict()
export type TargetProfile = z.infer<typeof targetProfileSchema>
