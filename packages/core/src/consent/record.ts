import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'

const toolRecord = z.strictObject({ name: z.string(), version: z.string(), checksum: z.string() })
// One entry per attested target (spec 9.2: re-taken for each new target). Each carries the hash of the text shown
// for it, so a changed AUTHORIZATION.md invalidates every target entry, not just the init attestation.
const targetAttestation = z.strictObject({ target: z.string().min(1), attested_at: z.string(), attestation_text_hash: z.string().length(64) })
const consentSchema = z.strictObject({
  schema_version: z.literal(1),
  mode: z.enum(['full', 'pure-reasoning']),
  sentinel_version: z.string(),
  attested_at: z.string(),
  attestation_text_hash: z.string().length(64),
  targets: z.array(targetAttestation),
  tools: z.array(toolRecord).optional(),
})

export type ToolRecord = z.infer<typeof toolRecord>
export type TargetAttestation = z.infer<typeof targetAttestation>
export type ConsentRecord = z.infer<typeof consentSchema>

const file = (root: string): string => join(root, '.sentinel', 'consent.json')

/** sha256 of the attestation text exactly as displayed. */
export const attestationHash = (shownText: string): string => createHash('sha256').update(shownText, 'utf8').digest('hex')

/** Null when absent, unreadable or malformed: fail closed, so consent is simply requested again. */
export function readConsent(root: string): ConsentRecord | null {
  try {
    const parsed = consentSchema.safeParse(JSON.parse(readFileSync(file(root), 'utf8')))
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

/** Callers pass the user's own working directory, never a scanned target (the project is read-only on targets). */
export function writeConsent(root: string, r: ConsentRecord): void {
  mkdirSync(join(root, '.sentinel'), { recursive: true })
  writeFileSync(file(root), JSON.stringify(consentSchema.parse(r), null, 2) + '\n')
}

/** True only if this exact target was attested against this exact current text. */
export const isAttested = (r: ConsentRecord | null, target: string, currentText: string): boolean =>
  r?.targets.some((t) => t.target === target && t.attestation_text_hash === attestationHash(currentText)) ?? false
