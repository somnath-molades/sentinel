import { buildIndex } from '@sentinel/core'
import type { RegistryIndex, SchemaError } from '@sentinel/core'

/** All output goes through this, so tests can capture it and stdout stays clean for piping. */
export type IO = { out: (s: string) => void; err: (s: string) => void }
export type GhRunner = (args: string[], timeoutMs: number) => Promise<{ code: number; stdout: string }>
/** huntersAvailable is false in this build (Phase 1 has no hunter agents); it exists so the --fail-on wiring can be tested. */
export type Deps = {
  gh?: GhRunner
  huntersAvailable?: boolean
  /** init only: the next typed line, or null at EOF. Default reads process.stdin. */
  readLine?: () => Promise<string | null>
  /** init only: the user's working directory, where the consent record lives. Default process.cwd(). */
  cwd?: string
  /** init only: the attestation document to show. Default is the bundled AUTHORIZATION.md. */
  authorizationPath?: string
}
export type Ctx = { io: IO; deps: Deps; defaultRegistry: string }

/** A failure with a user-facing reason. The top level prints it without a stack trace. */
export class CliError extends Error {}

export const reason = (e: unknown): string => (e instanceof Error ? e.message : String(e))

export async function loadRegistry(root: string): Promise<{ index: RegistryIndex; errors: SchemaError[] }> {
  try {
    return await buildIndex(root)
  } catch (e) {
    throw new CliError(`Cannot load the technique registry at ${root}: ${reason(e)}. Nothing can be examined without it.`)
  }
}

// buildIndex deliberately does not throw on a bad entry, so a consumer must report them: a malformed
// entry silently shrinks coverage while a selection can still say "exact".
export const registryWarning = (errors: SchemaError[]): string =>
  `${errors.length} registry entr${errors.length === 1 ? 'y' : 'ies'} failed to load and are missing from coverage:\n${errors.map((e) => `    ${e.file}: ${e.problem}`).join('\n')}`
