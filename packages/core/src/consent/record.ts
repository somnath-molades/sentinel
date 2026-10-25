import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import type { ResolvedTarget } from '../scope/resolve-target.js'

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

/** The consent file exists but cannot be used. It is evidence of an attestation, so it is never silently replaced. */
export class ConsentFileError extends Error {}

/** Null only when there is no record. An unreadable or invalid one throws, naming the file, for the user to resolve deliberately. */
export function readConsent(root: string): ConsentRecord | null {
  let raw: string
  try {
    raw = readFileSync(file(root), 'utf8')
  } catch (e) {
    if ((e as { code?: unknown }).code === 'ENOENT') return null
    throw new ConsentFileError(`Cannot read the consent record ${file(root)}: ${e instanceof Error ? e.message : String(e)}. Fix or remove it yourself; Sentinel will not overwrite it.`)
  }
  try {
    return consentSchema.parse(JSON.parse(raw))
  } catch {
    throw new ConsentFileError(`The consent record ${file(root)} is corrupt or not a valid consent record. It is evidence of a prior attestation, so Sentinel will not overwrite it. Inspect it, then fix or remove it yourself and run "sentinel init" again.`)
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

/** The attestation text shown to the user: the repository's AUTHORIZATION.md (same depth from src/ and dist/). */
export const loadAuthorization = (path: string = fileURLToPath(new URL('../../../../AUTHORIZATION.md', import.meta.url))): string => readFileSync(path, 'utf8')

/** Identity of an attested target: the scope lock's realpathed root for a local path, owner/repo for GitHub. */
export const targetId = (t: ResolvedTarget): string => (t.kind === 'github' ? `github:${t.owner}/${t.repo}`.toLowerCase() : t.root)

/** Null if the resolved target may be examined; otherwise the refusal to show, naming the target and how to attest it. */
export function attestationRefusal(consentRoot: string, t: ResolvedTarget, shownText: string): string | null {
  const id = targetId(t)
  if (isAttested(readConsent(consentRoot), id, shownText)) return null
  const arg = t.kind === 'github' ? `https://github.com/${t.owner}/${t.repo}` : t.root
  return `Not attested: ${id} has no consent for the current AUTHORIZATION.md. Run: sentinel init ${JSON.stringify(arg)} (from the directory that holds your .sentinel/consent.json, ${consentRoot}).`
}
