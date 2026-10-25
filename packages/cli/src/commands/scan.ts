import { rm } from 'node:fs/promises'
import { dirname } from 'node:path'
import { decideExitCode, profileTarget, resolveTarget, selectTechniques, stackForLanguage, toMarkdown, toSarif } from '@sentinel/core'
import type { Finding, Severity } from '@sentinel/core'
import { CliError, loadRegistry, reason, registryWarning } from '../context.js'
import type { Ctx } from '../context.js'

export type ScanOptions = { format: 'markdown' | 'sarif'; failOn: Severity['band'] | null; maxFiles?: number; registry?: string }

// This build runs no CVE or entropy tooling, so the report mode is a fact about it, not a choice.
const MODE = 'pure-reasoning' as const

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
    const profile = await profileTarget(t, o.maxFiles !== undefined ? { maxFiles: o.maxFiles } : {}) // t.root as resolved, never the input
    const { index, errors } = await loadRegistry(o.registry ?? defaultRegistry)

    const warnings: string[] = [
      'No hunter agents exist in this build: techniques are selected but never applied, so zero findings means nothing was hunted. An empty report is not a clean result.',
      'Reduced coverage (pure-reasoning): no dependency CVE checks and no entropy-based secret scanning were run.',
    ]
    if (errors.length) warnings.push(registryWarning(errors))
    if (index.techniques.length === 0) warnings.push('The registry contains no techniques: nothing was examined.')

    const languages = profile.languages.map((l) => l.language)
    const stacks = [...new Set(languages.flatMap((l) => stackForLanguage(l) ?? []))].sort()
    const unmapped = languages.filter((l) => stackForLanguage(l) === undefined)
    if (unmapped.length) warnings.push(`No technique stack exists for: ${unmapped.join(', ')}. Code in those languages is NOT examined by stack-specific techniques; do not read it as clean.`)
    if (stacks.length === 0) warnings.push("No stack could be derived from this target's files. Stack-specific techniques will not apply; an empty report is NOT a clean result.")
    const coverage: string[] = []
    for (const stack of stacks) {
      const sel = selectTechniques(index, { stack })
      const n = sel.techniques.length
      const line = `${stack}: ${n} technique${n === 1 ? '' : 's'} (coverage: ${sel.match})`
      if (sel.match === 'none') warnings.push(`${line}. Nothing was examined for ${stack}.`)
      else if (sel.match === 'wildcard-only') warnings.push(`${line}. Only generic techniques exist; none targets ${stack} specifically.`)
      else coverage.push(line)
    }

    const findings: Finding[] = []
    io.err(warnings.map((w) => `warning: ${w}\n`).join('') + coverage.map((c) => `coverage: ${c}\n`).join(''))
    if (o.format === 'sarif') io.out(JSON.stringify(toSarif(findings, profile, { mode: MODE }), null, 2) + '\n')
    else {
      const banner = `> **Coverage warnings (read before trusting this report):**\n${[...warnings, ...coverage].map((w) => `> - ${w.replaceAll('\n', '\n>   ')}`).join('\n')}\n\n`
      io.out(banner + toMarkdown(findings, profile, { mode: MODE }))
    }
    return decideExitCode(findings, o.failOn)
  } catch (e) {
    if (e instanceof CliError) throw e
    throw new CliError(`Scan failed: ${reason(e)}${cloneDir ? ' The temporary clone was deleted.' : ''}`)
  } finally {
    if (cloneDir) await rm(cloneDir, { recursive: true, force: true })
  }
}
