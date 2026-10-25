import { readFileSync, realpathSync } from 'node:fs'
import { dirname, isAbsolute, relative, sep } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { SENTINEL_CORE_VERSION, attestationHash, isAttested, readConsent, resolveTarget, writeConsent } from '@sentinel/core'
import type { ConsentRecord } from '@sentinel/core'
import type { Ctx } from '../context.js'
import { removeClone } from './scan.js'

const AUTHORIZATION = fileURLToPath(new URL('../../../../AUTHORIZATION.md', import.meta.url)) // same depth from src/ and dist/

const TOOLCHAIN = `
Toolchain consent
Sentinel's external scanning toolchain is not available in this build, so the only mode is pure-reasoning.
Type "no" to continue in pure-reasoning mode.
`
const COVERAGE_LOST = `Warning: pure-reasoning mode. Coverage given up: dependency CVE detection and entropy-based secret scanning. Reports will say so.
`

const inside = (dir: string, p: string): boolean => {
  const rel = relative(dir, p)
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel))
}

/** Exact match on the literal word: no trimming, no case folding, no abbreviation. Only a trailing CR is dropped. */
const typed = (line: string | null, word: string): boolean => line !== null && line.replace(/\r$/, '') === word

export async function init(target: string | undefined, { io, deps }: Ctx): Promise<number> {
  const cwd = realpathSync(deps.cwd ?? process.cwd()) // the record lives where the user ran init, never in a target
  const shown = readFileSync(deps.authorizationPath ?? AUTHORIZATION, 'utf8')
  const hash = attestationHash(shown)

  let id: string | null = null
  let cloneDir: string | undefined
  const rl = deps.readLine ? null : createInterface({ input: process.stdin })
  const lines = rl?.[Symbol.asyncIterator]()
  const readLine = deps.readLine ?? (async () => (await lines!.next()).value ?? null)
  const ask = async (prompt: string): Promise<string | null> => {
    io.out(prompt)
    return readLine()
  }
  try {
    if (target !== undefined) {
      const resolved = await resolveTarget(target, { allowGitHub: true, ...(deps.gh ? { gh: deps.gh } : {}) })
      if (!resolved.ok) {
        io.err(`Refused (scope lock): ${resolved.error.reason}\n`)
        return 2
      }
      const t = resolved.value
      cloneDir = t.kind === 'github' ? dirname(t.root) : undefined
      if (t.kind === 'local' && inside(t.root, cwd)) {
        io.err(`Refused: the working directory is inside the target, and the consent record must never be written into a scanned target. Run init from your own directory.\n`)
        return 2
      }
      id = t.kind === 'github' ? `github:${t.owner}/${t.repo}`.toLowerCase() : t.root
    }

    const prior = readConsent(cwd)
    const baseOk = prior?.attestation_text_hash === hash // otherwise no record, or AUTHORIZATION.md changed since it was shown
    if (baseOk && (id === null || isAttested(prior, id, shown))) {
      io.out(id === null ? 'Already attested for the current AUTHORIZATION.md.\n' : `Already attested for ${id}.\n`)
      return 0
    }

    io.out(shown.endsWith('\n') ? shown : shown + '\n')
    const answer = await ask(`\nType "yes" to attest${id === null ? '' : ` for ${id}`}: `)
    if (!typed(answer, 'yes')) {
      io.err('\nAttestation refused: the exact word "yes" was not typed. No consent was recorded.\n')
      return 2
    }
    const attested_at = new Date().toISOString()

    let base: ConsentRecord
    if (prior && baseOk) base = prior
    else {
      io.out(TOOLCHAIN)
      if (!typed(await ask('> '), 'no')) {
        io.err('\nOnly "no" is accepted in this build. No consent was recorded.\n')
        return 2
      }
      io.out(COVERAGE_LOST)
      base = { schema_version: 1, mode: 'pure-reasoning', sentinel_version: SENTINEL_CORE_VERSION, attested_at, attestation_text_hash: hash, targets: [] }
    }
    // Entries made against an older text are dropped: they no longer count anyway (isAttested compares hashes).
    const targets = base.targets.filter((t) => t.attestation_text_hash === hash && t.target !== id)
    if (id !== null) targets.push({ target: id, attested_at, attestation_text_hash: hash })
    writeConsent(cwd, { ...base, targets })
    io.out(id === null ? 'Consent recorded.\n' : `Consent recorded for ${id}.\n`)
    return 0
  } finally {
    rl?.close()
    if (cloneDir) await removeClone(cloneDir, io)
  }
}
