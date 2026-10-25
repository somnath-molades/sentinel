// Real-agent integration runner. ON DEMAND ONLY: NOT in CI, NOT run by `vitest`. Agent quality is measured and
// published, never asserted by a passing test (spec 8.3).
//
// This runner deliberately embeds NO agent and calls no model API. It is plumbing that takes REAL agent output
// as input and pushes it through the same MCP session boundary a real harness uses (createSession: scope lock,
// attestation, walked-set check, agent-identity gate, verification gate), then scores the result against the
// express-vulnerable fixture's known plants. The agent steps are supplied by whatever harness the operator uses.
//
// Operator sequence (from YOUR OWN directory, never inside the target; build first: tsc -b packages/core packages/mcp packages/cli):
//   1. node packages/cli/dist/bin.js init tests/fixtures/targets/express-vulnerable     (attest; writes .sentinel/ here)
//   2. node scripts/hunt-integration.mjs plan <target>
//        prints the injection assignment a hunter receives (techniques + registry paths, hotspot_paths, coverage, roots).
//   3. In your harness, dispatch a hunter with the sentinel-hunt skill (skills/sentinel-hunt/SKILL.md) on the printed
//      assignment. Save what it would pass to record_finding as candidates.json:
//        [{ "reporting_agent": "hunter-1", "technique_id": "...", "file": "src/server.js", "line": 1, "snippet": "...",
//           "depth_tier": "L1", "reachability": "..." }]
//   4. node scripts/hunt-integration.mjs run <target> --candidates candidates.json
//        feeds candidates through record_finding; prints accepted/rejected with reasons and the finding ids.
//   5. Dispatch a DIFFERENT verifier (skills/sentinel-verify/SKILL.md) per accepted finding. Save its verify_finding
//      arguments as verdicts.json, naming the finding by "finding_id" or by "candidate" (0-based index in candidates.json):
//        [{ "candidate": 0, "agent": "verifier-1", "outcome": "confirmed", "reasoning": "...", "severity_factors": {...} }]
//   6. node scripts/hunt-integration.mjs run <target> --candidates candidates.json --verdicts verdicts.json
//        prints the report, the per-candidate scorecard, and the confirmed / needs-review / disproved counts.
// Options: --consent-root <dir> (default: the current directory, where `init` wrote the consent record).
// Scoring (hit / false positive / miss) applies when the target is the express-vulnerable fixture; elsewhere it is skipped and says so.
// Exit codes: 0 ran; 2 usage, refusal, or a plant that could not be located in the fixture text (never a silent zero score).

import { readFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { createSession } from '../packages/mcp/dist/tools.js'

const die = (msg) => {
  console.error(msg)
  process.exit(2)
}
const [cmd, targetArg, ...rest] = process.argv.slice(2)
if (!['plan', 'run'].includes(cmd) || !targetArg) die('usage: hunt-integration.mjs plan|run <target> [--candidates f.json] [--verdicts f.json] [--consent-root dir]')
const opt = (name) => {
  const i = rest.indexOf(name)
  return i < 0 ? undefined : rest[i + 1] ?? die(`${name} needs a value`)
}
const readJson = (f) => {
  try {
    const v = JSON.parse(readFileSync(f, 'utf8'))
    return Array.isArray(v) ? v : die(`${f}: expected a JSON array`)
  } catch (e) {
    return die(`cannot read ${f}: ${e.message}`)
  }
}
const body = (r) => {
  try {
    return JSON.parse(r.content[0].text)
  } catch {
    return { text: r.content[0].text }
  }
}

const session = createSession({ consentRoot: resolve(opt('--consent-root') ?? process.cwd()) })
const target = resolve(targetArg)
try {
  // Same refusals the CLI gives: scope lock, then attestation. We never write consent here; the operator attests with `init`.
  const prof = await session.profile_target({ target })
  if (prof.isError) die(`Refused: ${prof.content[0].text}`)
  const plan = await session.plan_hunts()
  if (plan.isError) die(plan.content[0].text)
  const p = body(plan)
  console.log('== Injection assignment the hunter receives ==')
  console.log(JSON.stringify({ registry_root: p.registry_root, target_root: p.target_root, ...(p.registry_warning ? { registry_warning: p.registry_warning } : {}), assignment: p.assignments.find((a) => a.domain === 'injection') }, null, 2))
  console.log(`Domains with no techniques at all (nothing examined, NOT clean): ${p.assignments.filter((a) => a.techniques.length === 0).map((a) => a.domain).join(', ') || '(none)'}`)
  if (cmd === 'plan') process.exit(0)

  const candidates = readJson(opt('--candidates') ?? die('run needs --candidates'))
  const verdictsFile = opt('--verdicts')
  const verdicts = verdictsFile ? readJson(verdictsFile) : []

  // One call per candidate so each rejection maps to exactly one candidate and one reporting agent.
  const rows = []
  for (const [i, c] of candidates.entries()) {
    const { reporting_agent, ...finding } = c
    const r = await session.record_finding({ reporting_agent, findings: [finding] })
    const b = body(r)
    const a = b.accepted?.[0]
    rows.push({ i, c, id: a?.id, reason: a ? undefined : b.rejected?.[0]?.reason ?? b.text ?? 'rejected', verdict: undefined })
  }
  for (const v of verdicts) {
    const { candidate, ...args } = v
    const row = candidate === undefined ? rows.find((r) => r.id === v.finding_id) : rows[candidate]
    const finding_id = args.finding_id ?? row?.id
    if (!finding_id) {
      console.log(`verdict for candidate ${candidate ?? v.finding_id}: no accepted finding to attach it to, skipped`)
      continue
    }
    const r = await session.verify_finding({ ...args, finding_id })
    const text = r.isError ? `REFUSED: ${r.content[0].text}` : args.outcome
    if (row) row.verdict = text
    else console.log(`verdict for ${finding_id}: ${text}`)
  }

  const rep = body(await session.report({ format: 'markdown' }))
  console.log('\n== Report ==\n' + rep.report)

  // Scoring: plants are located in the fixture TEXT at runtime (a route's start line to its closing "})"), never by hard-coded line numbers.
  const scored = basename(target) === 'express-vulnerable'
  const lines = scored ? readFileSync(join(target, 'src', 'server.js'), 'utf8').split('\n') : []
  const block = (needle, kind) => {
    let s = lines.findIndex((l) => l.includes(needle))
    if (s < 0) die(`FATAL: ${kind} not found in the fixture (needle ${JSON.stringify(needle)}); the fixture changed. Refusing to score.`)
    while (s > 0 && !lines[s].startsWith('app.')) s-- // a needle inside a handler body widens to the whole route
    if (!lines[s].startsWith('app.')) die(`FATAL: the ${kind} is not inside an app.<verb> route. Refusing to score.`)
    const e = lines.findIndex((l, j) => j >= s && l === '})')
    if (e < 0) die(`FATAL: no closing "})" after the ${kind} (needle ${JSON.stringify(needle)}). Refusing to score.`)
    return { kind, from: s + 1, to: e + 1 }
  }
  const planted = scored ? [block(`WHERE name = '" +`, 'concatenated query'), block(`app.delete('/users/:id'`, 'unauthenticated destructive route')] : []
  const safe = scored ? [block('WHERE name = $1', '$1 parameterized query'), block(`app.delete('/sessions/:id', requireAuth`, 'requireAuth-guarded route')] : []
  const within = (b, c) => c.file.replace(/^\.\//, '') === 'src/server.js' && c.line >= b.from && c.line <= b.to

  console.log('== Scorecard: every candidate ==')
  for (const r of rows) console.log(`#${r.i} ${r.c.file}:${r.c.line} ${r.c.technique_id} by ${r.c.reporting_agent}: ${r.id ? `ACCEPTED (${r.id})` : `REJECTED: ${r.reason}`}${r.verdict ? `; verdict ${r.verdict}` : ''}`)
  const n = (re) => Number(re.exec(rep.report)?.[1] ?? NaN)
  console.log(`\nCounts: confirmed ${n(/- Confirmed: (\d+)/)}, needs review ${n(/- Needs review, NOT confirmed: (\d+)/)}, disproved ${n(/- (\d+) disproved by verification/)}`)

  if (!scored) console.log('Plant scoring skipped: the target is not the express-vulnerable fixture.')
  else {
    const live = rows.filter((r) => r.id)
    const hits = planted.map((b) => ({ b, by: live.filter((r) => within(b, r.c)) }))
    console.log('\nHITS (accepted candidate inside a planted block):', hits.filter((h) => h.by.length).map((h) => `${h.b.kind} lines ${h.b.from}-${h.b.to} <- #${h.by.map((r) => r.i).join(',#')}`))
    console.log('FALSE POSITIVES (accepted candidate inside a safe block):', safe.flatMap((b) => live.filter((r) => within(b, r.c)).map((r) => `#${r.i} on ${b.kind} lines ${b.from}-${b.to}${r.verdict ? ` (verdict ${r.verdict})` : ''}`)))
    console.log('MISSES (planted block with no accepted candidate):', hits.filter((h) => !h.by.length).map((h) => `${h.b.kind} lines ${h.b.from}-${h.b.to}`))
    console.log('Unscored: accepted candidates in neither a planted nor a safe block:', live.filter((r) => ![...planted, ...safe].some((b) => within(b, r.c))).map((r) => `#${r.i}`))
  }
} finally {
  await session.cleanup()
}
