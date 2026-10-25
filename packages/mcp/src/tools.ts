import { rm } from 'node:fs/promises'
import { dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEPTH_TIERS,
  FindingsStore,
  STACKS,
  buildIndex,
  computeSeverity,
  profileTarget,
  resolveTarget,
  selectTechniques,
  toMarkdown,
  toSarif,
} from '@sentinel/core'
import type { Finding, RegistryIndex, ResolvedTarget, Severity, TargetProfile } from '@sentinel/core'
import { z } from 'zod'

// Every value in this file that came from an agent is untrusted. Handlers validate and translate; all
// domain logic (routing, dedupe, verification gate, scoring, rendering) stays in @sentinel/core.

export type GhRunner = NonNullable<NonNullable<Parameters<typeof resolveTarget>[1]>['gh']>
export type Mode = 'full' | 'pure-reasoning'
export type SessionOptions = {
  /** Directory holding `packs/`. Defaults to the repository's `registry/`. */
  registryRoot?: string
  /** Operator decision, never agent input: whether GitHub targets may be cloned. */
  allowGitHub?: boolean
  gh?: GhRunner
  /** What this server actually ran. Defaults to 'pure-reasoning': it runs no CVE or entropy tooling. */
  mode?: Mode
}
export type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean }

const ok = (body: unknown): ToolResult => ({ content: [{ type: 'text', text: JSON.stringify(body, null, 2) }] })
const fail = (message: string, extra?: Record<string, unknown>): ToolResult => ({
  content: [{ type: 'text', text: extra ? JSON.stringify({ error: message, ...extra }, null, 2) : message }],
  isError: true,
})
const reason = (e: unknown): string => (e instanceof Error ? e.message : String(e))
const nonBlank = (s: string): boolean => s.trim() !== ''

// The router's vocabulary is closed (STACKS). profileTarget emits language names; this is the seam.
// Unmapped languages are refused or flagged, never passed through: an unknown token silently matches
// only `generic` techniques, which reads as a thin scan rather than an unexamined one.
const LANGUAGE_STACK: Record<string, (typeof STACKS)[number]> = {
  javascript: 'node',
  typescript: 'node',
  python: 'python',
  go: 'go',
  php: 'php',
  java: 'java',
}
const stackFor = (language: string): string | undefined => LANGUAGE_STACK[language.toLowerCase()]

const stackEnum = z.enum(STACKS)
const factorSchema = z.literal([0, 1, 2, 3])
const severityFactorsSchema = z.strictObject({
  exploitability: factorSchema,
  reachability: factorSchema,
  blast_radius: factorSchema,
  data_sensitivity: factorSchema,
})
// file is a label in reports and SARIF URIs, so it must be a relative path inside the target.
const relPath = (p: string): boolean => nonBlank(p) && !p.includes('\0') && !isAbsolute(p) && !p.split(/[\\/]/).includes('..')
const findingSchema = z.object({
  technique_id: z.string().min(1),
  file: z.string().refine(relPath, 'file must be a relative path inside the target (no absolute path, no "..")'),
  line: z.number().int().min(1),
  snippet: z.string().refine(nonBlank, 'snippet must not be empty'),
  depth_tier: z.enum(DEPTH_TIERS),
  reachability: z.string().refine(nonBlank, 'reachability must be a non-empty reason'),
})

/** Input shapes for protocol registration. Findings and severity factors are validated per item in the handler. */
export const inputs = {
  profile_target: { target: z.string().describe('Local directory path (or a GitHub repo URL if the operator enabled it).') },
  select_techniques: {
    stack: stackEnum.optional().describe(`Stack token: ${STACKS.join(', ')}.`),
    language: z.string().optional().describe('A language name from profile_target (e.g. typescript); mapped to a stack token. Give stack or language, not both.'),
    vuln_class: z.string().optional(),
    depth_tier: z.enum(DEPTH_TIERS).optional(),
    limit: z.number().int().positive().optional(),
  },
  record_finding: { findings: z.array(z.unknown()).describe('Findings: {technique_id, file (relative), line, snippet, depth_tier, reachability}. Each is validated separately.') },
  verify_finding: {
    finding_id: z.string().min(1),
    agent: z.string().min(1),
    outcome: z.enum(['confirmed', 'disproved', 'ambiguous']),
    reasoning: z.string().min(1),
    severity_factors: z.unknown().optional().describe('Only with outcome "confirmed": {exploitability, reachability, blast_radius, data_sensitivity}, each an integer 0..3.'),
  },
  report: { format: z.enum(['markdown', 'sarif']).optional().describe('Default markdown.') },
}

type State = {
  target?: ResolvedTarget
  profile?: TargetProfile
  store: FindingsStore
  severities: Map<string, Severity>
  selections: Map<string, 'exact' | 'wildcard-only' | 'none'>
  rejected: number
}
const fresh = (): Omit<State, 'target' | 'profile'> => ({ store: new FindingsStore(), severities: new Map(), selections: new Map(), rejected: 0 })

export type Session = {
  profile_target(a: { target: string }): Promise<ToolResult>
  select_techniques(a: { stack?: string; language?: string; vuln_class?: string; depth_tier?: (typeof DEPTH_TIERS)[number]; limit?: number }): Promise<ToolResult>
  record_finding(a: { findings: unknown[] }): Promise<ToolResult>
  verify_finding(a: { finding_id: string; agent: string; outcome: 'confirmed' | 'disproved' | 'ambiguous'; reasoning: string; severity_factors?: unknown }): Promise<ToolResult>
  report(a: { format?: 'markdown' | 'sarif' }): Promise<ToolResult>
  /** Deletes the GitHub clone, if any. Safe to call repeatedly. */
  cleanup(): Promise<void>
}

export function createSession(opts: SessionOptions = {}): Session {
  const registryRoot = opts.registryRoot ?? fileURLToPath(new URL('../../../registry', import.meta.url))
  const mode: Mode = opts.mode ?? 'pure-reasoning'
  let state: State = { ...fresh() }
  let index: RegistryIndex | undefined
  let cloneDir: string | undefined

  const loadIndex = async (): Promise<RegistryIndex> => (index ??= (await buildIndex(registryRoot)).index)

  // Chained, so a second caller (e.g. onclose racing close()) waits for the delete already in flight.
  let deleting: Promise<void> = Promise.resolve()
  function cleanup(): Promise<void> {
    const d = cloneDir
    cloneDir = undefined
    if (d) deleting = deleting.then(() => rm(d, { recursive: true, force: true }))
    return deleting
  }

  // Errors return, they never cross the protocol as exceptions.
  const guard =
    <A>(fn: (a: A) => Promise<ToolResult>) =>
    async (a: A): Promise<ToolResult> => {
      try {
        return await fn(a)
      } catch (e) {
        return fail(`Internal error: ${reason(e)}`)
      }
    }

  return {
    cleanup,

    profile_target: guard(async ({ target }) => {
      await cleanup()
      state = { ...fresh() }
      const r = await resolveTarget(target, { allowGitHub: opts.allowGitHub ?? false, ...(opts.gh ? { gh: opts.gh } : {}) })
      if (!r.ok) return fail(`Target refused (scope lock): ${r.error.reason}`)
      // The clone lives in a temp dir <tmp>/sentinel-XXXX/<repo>; the caller (us) owns deleting it.
      if (r.value.kind === 'github') cloneDir = dirname(r.value.root)
      try {
        const profile = await profileTarget(r.value) // uses r.value.root as resolved; the input path is never re-resolved
        state.target = r.value
        state.profile = profile
        const langs = profile.languages.map((l) => l.language)
        const suggested = [...new Set(langs.flatMap((l) => stackFor(l) ?? []))].sort()
        const unmapped = langs.filter((l) => stackFor(l) === undefined)
        return ok({
          profile,
          stacks: {
            suggested,
            unmapped_languages: unmapped,
            ...(unmapped.length ? { warning: `No technique stack exists for: ${unmapped.join(', ')}. Code in those languages will NOT be examined by stack-specific techniques; do not report it as clean.` } : {}),
          },
        })
      } catch (e) {
        await cleanup()
        return fail(`Profiling failed: ${reason(e)}`)
      }
    }),

    select_techniques: guard(async (a) => {
      if (a.stack !== undefined && a.language !== undefined) return fail('Give either stack or language, not both.')
      let stack = a.stack
      if (a.language !== undefined) {
        stack = stackFor(a.language)
        if (stack === undefined) {
          return fail(
            `No technique stack is known for language "${a.language}". Known languages: ${Object.keys(LANGUAGE_STACK).join(', ')}. Sentinel cannot examine this code with stack-specific techniques; do not report it as clean.`,
          )
        }
      }
      if (stack !== undefined && !(STACKS as readonly string[]).includes(stack)) return fail(`Unknown stack "${stack}". Expected one of: ${STACKS.join(', ')}.`)
      const sel = selectTechniques(await loadIndex(), {
        ...(stack !== undefined ? { stack } : {}),
        ...(a.vuln_class !== undefined ? { vuln_class: a.vuln_class } : {}),
        ...(a.depth_tier !== undefined ? { depth_tier: a.depth_tier } : {}),
        ...(a.limit !== undefined ? { limit: a.limit } : {}),
      })
      state.selections.set(`${stack ?? '(any stack)'}${a.vuln_class ? ` / ${a.vuln_class}` : ''}`, sel.match)
      const what = `${stack ?? 'any stack'}${a.vuln_class ? ` / ${a.vuln_class}` : ''}`
      const warning =
        sel.match === 'none'
          ? `No techniques exist for ${what}. Nothing was examined for it: an empty result here is NOT a clean result.`
          : sel.match === 'wildcard-only'
            ? `Only generic techniques exist for ${what}; no technique targets this stack specifically. Coverage is partial, so the absence of findings is not a clean result.`
            : undefined
      return ok({ stack: stack ?? null, coverage: sel.match, ...(warning ? { warning } : {}), techniques: sel.techniques })
    }),

    record_finding: guard(async ({ findings }) => {
      const idx = await loadIndex()
      const known = new Set(idx.techniques.map((t) => t.id))
      const accepted: Finding[] = []
      const rejected: { index: number; reason: string }[] = []
      findings.forEach((raw, i) => {
        const p = findingSchema.safeParse(raw)
        if (!p.success) return rejected.push({ index: i, reason: p.error.issues.map((x) => `${x.path.join('.') || '(finding)'}: ${x.message}`).join('; ') })
        const v = p.data
        if (!known.has(v.technique_id)) return rejected.push({ index: i, reason: `technique_id: unknown technique "${v.technique_id}"` })
        try {
          accepted.push(state.store.add({ technique_id: v.technique_id, file: v.file, line: v.line, snippet: v.snippet }, { depth_tier: v.depth_tier, reachability: v.reachability }))
        } catch (e) {
          rejected.push({ index: i, reason: reason(e) }) // the store's own contract check; still per finding
        }
      })
      state.rejected += rejected.length
      const body = { accepted, rejected }
      return accepted.length === 0 && rejected.length > 0
        ? fail('Every finding in the batch was rejected; nothing was recorded.', body)
        : ok(body)
    }),

    verify_finding: guard(async (a) => {
      if (!state.store.get(a.finding_id)) return fail(`Unknown finding id "${a.finding_id}". Use an id returned by record_finding.`)
      let severity: Severity | undefined
      if (a.severity_factors !== undefined) {
        if (a.outcome !== 'confirmed') return fail('severity_factors are only accepted with outcome "confirmed".')
        const f = severityFactorsSchema.safeParse(a.severity_factors)
        if (!f.success) {
          return fail(`Invalid severity_factors: ${f.error.issues.map((x) => `${x.path.join('.') || '(root)'}: ${x.message}`).join('; ')}. Each factor must be an integer 0, 1, 2 or 3.`)
        }
        severity = computeSeverity(f.data)
      }
      const finding = state.store.recordVerdict(a.finding_id, { agent: a.agent, outcome: a.outcome, reasoning: a.reasoning })
      if (severity) state.severities.set(a.finding_id, severity)
      return ok({ finding: severity ? { ...finding, severity } : finding })
    }),

    report: guard(async ({ format }) => {
      const profile = state.profile
      if (!profile) return fail('No target has been profiled in this session. Call profile_target first.')
      const findings = state.store.list().map((f) => ({ ...f, ...(state.severities.has(f.id) ? { severity: state.severities.get(f.id) } : {}) }) as Finding)

      const warnings: string[] = []
      if (mode === 'pure-reasoning') warnings.push('Reduced coverage (pure-reasoning): no dependency CVE checks and no entropy-based secret scanning were run.')
      if (state.selections.size === 0) warnings.push('select_techniques was never called in this session: no techniques were applied, so nothing was examined. An empty report is not a clean result.')
      for (const [what, match] of state.selections) {
        if (match === 'none') warnings.push(`No techniques exist for ${what}: nothing was examined for it.`)
        else if (match === 'wildcard-only') warnings.push(`Only generic techniques exist for ${what}: partial coverage.`)
      }
      const unmapped = profile.languages.map((l) => l.language).filter((l) => stackFor(l) === undefined)
      if (unmapped.length) warnings.push(`Languages with no technique stack were not examined by stack-specific techniques: ${unmapped.join(', ')}.`)
      if (state.rejected) warnings.push(`${state.rejected} finding(s) were rejected at ingest and are NOT in this report.`)

      const body = format === 'sarif' ? toSarif(findings, profile, { mode }) : toMarkdown(findings, profile, { mode })
      const banner = warnings.length ? `> **Coverage warnings (read before trusting this report):**\n${warnings.map((w) => `> - ${w}`).join('\n')}\n\n` : ''
      const out = ok({
        format: format ?? 'markdown',
        coverage_warnings: warnings,
        findings_recorded: findings.length,
        findings_rejected: state.rejected,
        report: typeof body === 'string' ? banner + body : body,
      })
      await cleanup() // the scan is complete: do not leave a copy of the user's source in the temp dir
      return out
    }),
  }
}
