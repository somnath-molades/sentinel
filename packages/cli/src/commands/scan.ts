import { realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname } from 'node:path'
import { attestationRefusal, coverageGap, decideExitCode, loadAuthorization, profileTarget, resolveTarget, selectTechniques, toMarkdown, toSarif } from '@sentinel/core'
import type { Finding, Severity } from '@sentinel/core'
import { CliError, loadRegistry, reason, registryWarning } from '../context.js'
import type { Ctx } from '../context.js'

export type ScanOptions = { format: 'markdown' | 'sarif'; failOn: Severity['band'] | null; maxFiles?: number; registry?: string }

// This build runs no CVE or entropy tooling, so the report mode is a fact about it, not a choice.
const MODE = 'pure-reasoning' as const

// The clone's parent is derived from core's temp layout (<realpath tmp>/sentinel-XXXX/<repo>). Never recursively
// delete a path unless it still looks exactly like that.
export async function removeClone(dir: string, io: Ctx['io']): Promise<void> {
  if (!basename(dir).startsWith('sentinel-') || dirname(dir) !== (await realpath(tmpdir()))) {
    io.err(`warning: refused to delete ${dir}: it is not a Sentinel temporary directory. Remove it yourself if it holds a clone.\n`)
    return
  }
  await rm(dir, { recursive: true, force: true })
}

export async function scan(target: string, o: ScanOptions, { io, deps, defaultRegistry }: Ctx): Promise<number> {
  // A GitHub URL typed on the command line is the operator's own decision, so remote targets are enabled.
  const resolved = await resolveTarget(target, { allowGitHub: true, ...(deps.gh ? { gh: deps.gh } : {}) })
  if (!resolved.ok) {
    io.err(`Refused (scope lock): ${resolved.error.reason}\n`)
    return 2
  }
  const t = resolved.value
  // We own the clone (<tmp>/sentinel-XXXX/<repo>): it holds a copy of the user's source, so it goes on success and on failure.
  const cloneDir = t.kind === 'github' ? dirname(t.root) : undefined
  try {
    // Spec 9.2/9.3: no attestation for this exact target, no scan. The record is read from the user's own directory.
    const refusal = attestationRefusal(deps.cwd ?? process.cwd(), t, loadAuthorization(deps.authorizationPath))
    if (refusal) {
      io.err(`Refused (attestation): ${refusal}\n`)
      return 2
    }
    const profile = await profileTarget(t, o.maxFiles !== undefined ? { maxFiles: o.maxFiles } : {}) // t.root as resolved, never the input
    const { index, errors } = await loadRegistry(o.registry ?? defaultRegistry)

    // Everything pushed with warn() blocks a --fail-on gate: it means the gate cannot be meaningfully evaluated.
    const warnings: string[] = []
    const blockers: string[] = []
    const warn = (w: string, blocks = true): void => {
      warnings.push(w)
      if (blocks) blockers.push(w)
    }
    if (!deps.huntersAvailable) warn('No hunter agents exist in this build: techniques are selected but never applied, so zero findings means nothing was hunted. An empty report is not a clean result.')
    warn('Reduced coverage (pure-reasoning): no dependency CVE checks and no entropy-based secret scanning were run.', false)
    if (errors.length) warn(registryWarning(errors))
    if (index.techniques.length === 0) warn('The registry contains no techniques: nothing was examined.')

    // Derived in core from file counts, so one recognised file in a tree of unrecognised ones cannot silence it.
    const gap = coverageGap(profile)
    for (const w of gap.warnings) warn(w.text, w.blocks)
    const stacks = gap.stacks
    const coverage: string[] = []
    for (const stack of stacks) {
      const sel = selectTechniques(index, { stack })
      const n = sel.techniques.length
      const line = `${stack}: ${n} technique${n === 1 ? '' : 's'} (coverage: ${sel.match})`
      if (sel.match === 'none') warn(`${line}. Nothing was examined for ${stack}.`)
      else if (sel.match === 'wildcard-only') warn(`${line}. Only generic techniques exist; none targets ${stack} specifically.`)
      else coverage.push(line)
    }

    const findings: Finding[] = []
    io.err(warnings.map((w) => `warning: ${w}\n`).join('') + coverage.map((c) => `coverage: ${c}\n`).join(''))
    if (o.format === 'sarif') io.out(JSON.stringify(toSarif(findings, profile, { mode: MODE, warnings: [...warnings, ...coverage] }), null, 2) + '\n')
    else io.out(toMarkdown(findings, profile, { mode: MODE, warnings: [...warnings, ...coverage] }))
    if (o.failOn !== null && blockers.length) {
      // A gate that cannot trip must not read as a gate that passed.
      io.err(`error: --fail-on ${o.failOn} gate cannot be evaluated, so this is not a pass (exit 2):\n${blockers.map((b) => `  - ${b.replaceAll('\n', '\n    ')}`).join('\n')}\n`)
      return 2
    }
    return decideExitCode(findings, o.failOn)
  } catch (e) {
    if (e instanceof CliError) throw e
    throw new CliError(`Scan failed: ${reason(e)}${cloneDir ? ' The temporary clone was deleted.' : ''}`)
  } finally {
    if (cloneDir) await removeClone(cloneDir, io)
  }
}
