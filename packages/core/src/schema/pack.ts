import { z } from 'zod'
import { DEPTH_TIERS } from './technique.js'

export const packSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    source_url: z.string().min(1),
    license: z.string().min(1),
    ingestion_mode: z.enum(['vendored', 'original', 'external']),
    upstream_commit: z.string().optional(),
    coverage: z.array(z.enum(DEPTH_TIERS)),
    trust_tier: z.enum(['first-party', 'reviewed', 'community']),
  })
  // Licensing control: an upstream with no LICENSE is all-rights-reserved and must never be vendored.
  .refine((p) => !(p.ingestion_mode === 'vendored' && p.license.trim().toUpperCase() === 'UNSTATED'), {
    path: ['ingestion_mode'],
    message: "ingestion_mode 'vendored' is not allowed when license is UNSTATED (all rights reserved)",
  })

export type PackManifest = z.infer<typeof packSchema>
