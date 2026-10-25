# Sentinel Phase 2a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four blockers that stop a hunter-and-verifier layer being built correctly, then prove the topology end to end on the `injection` domain with real agents.

**Architecture:** Domain becomes the selection axis the dispatcher shards on and hunters query by. Assignment computation is a pure function in core exposed through one new MCP tool, so every harness wrapper inherits it rather than re-deriving it. Hunters and verifiers are host subagents driven by two thin skills; the security judgment stays in the technique entries, which already exist. The findings store gains agent identity and real severity state so the verification gate's central property becomes observable.

**Tech Stack:** TypeScript 5.x strict, Node 20+, pnpm workspaces, vitest, zod 4.6.7, yaml 2.9.1, commander 14.0.3, `@modelcontextprotocol/sdk` 1.31.0.

**Spec:** `docs/superpowers/specs/2026-10-25-sentinel-phase-2a-design.md` (parent: `docs/superpowers/specs/2026-10-24-project-sentinel-design.md`, binding where they conflict)

## Global Constraints

- Node engine floor `>=20.0.0`. TypeScript `strict: true`, no `any` in exported signatures.
- Dependencies pinned exactly — no `^`, no `~`. **Add none**: everything needed is present.
- License MIT. No `curl | bash` pattern; the guard scans the tree including fixtures.
- **Read-only on targets.** Nothing may write to, execute, or open a network connection to a scanned codebase.
- **Build before testing:** `node_modules/.bin/tsc -b packages/core packages/mcp packages/cli`, then `node_modules/.bin/vitest run`. Tests import `@sentinel/core` from built output; a stale build gives misleading results. CI runs build before lint for the same reason.
- Import core from its root entry only — the `exports` map permits nothing else, deliberately.
- A missing or unknown `domain` fails validation. **No default is ever assigned.**
- Hotspot paths are priority ordering, never a filter.
- An empty domain assignment and a missing one must be distinguishable **by type**, not by convention.
- Starting point: 335 tests across 27 files, all passing. Do not break any.

## Review Focus

Input classes the spec implies but no task's happy path exercises. Each has its test assigned to the task that owns the code.

1. **Two hunters report the same finding, then one verifies it.** Dedupe collapses the report; if only the first reporter's identity is kept, the second can confirm its own finding and the gate is silently defeated. (Task 6)
2. **A technique's domain is valid but its stack is not in the profile.** The assignment must come back explicitly empty with a reason, not omitted — otherwise an uncovered domain and a missing domain look identical. (Task 9)
3. **A verifier supplies severity factors on a `disproved` verdict.** The finding is dropped; the factors must not raise a band on something no longer reported. (Task 7)
4. **A hunter returns a candidate whose file is outside the walked set.** Agent output is untrusted; a path it invented or hallucinated must be refused at ingest, not written into a SARIF location. (Task 13)
5. **A domain with techniques but zero hotspot paths.** Hotspots are hints, so the hunter must still receive the full scope rather than an empty one. (Task 9)

---

## File Structure

```
packages/core/src/
  registry/
    vocabulary.ts          # MODIFY: + DOMAINS (ten), + c/cpp language mapping
    build-index.ts         # MODIFY: + domain on IndexedTechnique, domain validation errors
    router.ts              # MODIFY: + domain filter on TechniqueQuery
  schema/
    technique.ts           # MODIFY: + required domain field
    target-profile.ts      # MODIFY: hotspot domains validated against DOMAINS
  recon/
    walk.ts                # MODIFY: + .c/.cc/.cpp/.h/.hpp extensions
    profile-target.ts      # MODIFY: hotspot domains typed from DOMAINS
  findings/
    store.ts               # MODIFY: reporting agents, severity state, disputed
  hunt/
    plan-hunts.ts          # CREATE: the pure assignment computation
  report/
    markdown.ts            # MODIFY: render a disputed severity spread
    sarif.ts               # MODIFY: carry disputed in result properties

packages/mcp/src/
  tools.ts                 # MODIFY: + plan_hunts tool, delete the severity side map

skills/
  sentinel-hunt/SKILL.md   # CREATE: the hunter skill
  sentinel-verify/SKILL.md # CREATE: the verifier skill

registry/packs/*/techniques/*.md   # MODIFY: + domain on all 13
tests/fixtures/targets/express-vulnerable/   # MODIFY: negative controls
tests/fixtures/targets/c-memory-safety/      # CREATE: a C fixture
scripts/hunt-integration.mjs                 # CREATE: the on-demand real-agent run
```

Split rationale: `plan-hunts.ts` is new and gets its own directory because Phase 2b's budget model lands beside it. Everything else is a modification to a file that already owns that responsibility.

---

## Task 1: The domain vocabulary

**Files:**
- Modify: `packages/core/src/registry/vocabulary.ts`
- Modify: `packages/core/src/schema/target-profile.ts`
- Modify: `packages/core/src/recon/profile-target.ts`
- Test: `packages/core/tests/registry/vocabulary.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `DOMAINS` as a `readonly` tuple of the ten values in spec §4.1 — `authorization`, `injection`, `secrets`, `dependencies`, `iac`, `supply-chain`, `crypto`, `agentic`, `memory-safety`, `configuration` — and `type Domain = (typeof DOMAINS)[number]`. Exported from the package root.

**One constant, not two** (spec §4.1). Hotspots emit a subset today; technique entries may use all ten. Two related lists are how Phase 1's coverage texts drifted apart inside one phase.

- [ ] **Step 1: Write the failing tests**

```typescript
test('DOMAINS holds exactly the ten spec values', () => {
  expect([...DOMAINS].sort()).toEqual(['agentic','authorization','configuration','crypto','dependencies','iac','injection','memory-safety','secrets','supply-chain'])
})
test('every hotspot domain the profiler emits is a member', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('targets/express-vulnerable') })
  for (const h of p.hotspots) for (const d of h.domains) expect(DOMAINS).toContain(d)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node_modules/.bin/vitest run packages/core/tests/registry/vocabulary.test.ts`
Expected: FAIL — `DOMAINS` is not exported.

- [ ] **Step 3: Add `DOMAINS` and `Domain` to `vocabulary.ts`**

Place beside `STACKS` with a comment stating that hotspots use a subset and entries may use all ten.

- [ ] **Step 4: Type the hotspot domains against it**

`target-profile.ts:18` currently validates `domains: z.array(z.string())`. Narrow it to `z.array(z.enum(DOMAINS))`. Type the `flag(domain, reason)` parameter in `profile-target.ts` as `Domain` so a typo is a compile error rather than a string that matches no technique.

- [ ] **Step 5: Run the full suite**

Run: `node_modules/.bin/tsc -b packages/core && node_modules/.bin/vitest run`
Expected: PASS, 335 pre-existing plus the new tests.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/registry/vocabulary.ts packages/core/src/schema/target-profile.ts packages/core/src/recon/profile-target.ts packages/core/tests/registry/vocabulary.test.ts
git commit -m "feat(core): add the ten-value domain vocabulary"
```

---

## Task 2: `domain` on the technique schema

**Files:**
- Modify: `packages/core/src/schema/technique.ts`
- Modify: `packages/core/src/registry/build-index.ts`
- Modify: `registry/schema/technique.schema.json` (regenerated)
- Test: `packages/core/tests/schema/technique.test.ts`, `packages/core/tests/registry/build-index.test.ts`

**Interfaces:**
- Consumes: `DOMAINS`, `Domain` (Task 1).
- Produces: `TechniqueEntry.domain: Domain`, required and single-valued. `IndexedTechnique` gains `domain` — its `Pick` list becomes `'id' | 'vuln_classes' | 'depth_tier' | 'stacks' | 'domain'`.

- [ ] **Step 1: Write the failing tests**

```typescript
test('an entry with no domain is rejected', () => {
  const r = parseTechnique(read('missing-domain.md'), 'missing-domain.md')
  expect(r.ok).toBe(false)
  expect(r.error.problem).toMatch(/domain/)
})
test('an unknown domain is rejected and the message names the value and the allowed set', () => {
  const r = parseTechnique(read('unknown-domain.md'), 'unknown-domain.md')
  expect(r.ok).toBe(false)
  expect(r.error.problem).toContain('web-security')      // the offending value
  expect(r.error.problem).toContain('memory-safety')     // part of the allowed set
})
test('buildIndex names the entry id and the file path for a bad domain', async () => {
  const { errors } = await buildIndex(fixture('registry/bad-domain'))
  expect(errors[0]!.file).toContain('unknown-domain.md')
  expect(errors[0]!.problem).toMatch(/domain/)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL — the fixtures do not exist and `domain` is not in the schema.

- [ ] **Step 3: Create the two fixtures**

`tests/fixtures/registry/missing-domain.md` and `unknown-domain.md`: copies of `valid-technique.md` with the field absent, and with `domain: web-security`. Also a `registry/bad-domain` pack holding the unknown-domain entry beside one valid entry.

- [ ] **Step 4: Add the field and the error text**

`domain: z.enum(DOMAINS)` in `techniqueSchema`. The error must carry the offending value and the allowed set — a contributor must be able to fix the entry from the message without reading Sentinel's source (spec §4.4).

- [ ] **Step 5: Add `domain` to `IndexedTechnique` and regenerate the JSON schema**

Run: `node_modules/.bin/tsc -b packages/core && node scripts/gen-schema.mjs`

- [ ] **Step 6: Run the suite — expect the thirteen real entries to FAIL**

Run: `node_modules/.bin/vitest run`
Expected: the registry validation tests fail because no entry declares a domain yet. That is correct; Task 3 fixes it. Do not weaken the schema to make them pass.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/schema/technique.ts packages/core/src/registry/build-index.ts registry/schema/technique.schema.json tests/fixtures/registry packages/core/tests
git commit -m "feat(core): require a domain on every technique entry"
```

---

## Task 3: Map all thirteen entries

**Files:**
- Modify: all 13 files under `registry/packs/*/techniques/`
- Modify: `registry/index.json` (regenerated)
- Test: `packages/core/tests/registry/packs-validate.test.ts`

**Interfaces:**
- Consumes: Task 2's schema.
- Produces: a registry where every entry declares a domain, and the invariant that every entry routes somewhere.

Use spec §4.3's table verbatim. `injection` takes six entries; `over-permissive-agent-tool-allowlist` takes `agentic`, which spec §9.1 records as arguable rather than settled.

- [ ] **Step 1: Write the failing tests**

```typescript
test('every entry declares a domain in the vocabulary', () => {
  for (const t of allTechniques()) expect(DOMAINS).toContain(t.domain)
})
test('every entry routes to exactly one domain assignment', () => {
  // The silent-miss guard: an entry that routes nowhere fails here rather than disappearing.
  const byDomain = new Map<string, number>()
  for (const t of allTechniques()) byDomain.set(t.domain, (byDomain.get(t.domain) ?? 0) + 1)
  expect([...byDomain.values()].reduce((a, b) => a + b, 0)).toBe(allTechniques().length)
})
test('the injection domain holds the cross-cutting taint entry', () => {
  const ids = allTechniques().filter((t) => t.domain === 'injection').map((t) => t.id)
  expect(ids).toContain('cross-file-taint-source-to-sink')
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL — entries have no domain.

- [ ] **Step 3: Add one `domain` line to each of the thirteen entries**

Per spec §4.3. Nothing else in any entry changes.

- [ ] **Step 4: Regenerate the committed index**

Run: `node scripts/gen-index.mjs`

- [ ] **Step 5: Run the full suite**

Expected: PASS, including Task 2's tests which were failing by design.

- [ ] **Step 6: Commit**

```bash
git add registry/
git commit -m "feat(registry): assign a primary domain to all thirteen entries"
```

---

## Task 4: Domain filtering in the router

**Files:**
- Modify: `packages/core/src/registry/router.ts`
- Test: `packages/core/tests/registry/router.test.ts`

**Interfaces:**
- Consumes: `IndexedTechnique.domain` (Task 2).
- Produces: `TechniqueQuery` gains `domain?: Domain`. `selectTechniques` filters on it alongside `vuln_class`, `depth_tier` and `stack`. The `match` signal's meaning is unchanged.

- [ ] **Step 1: Write the failing tests**

```typescript
test('a domain query returns only that domain', () => {
  const r = selectTechniques(index, { domain: 'injection' })
  expect(r.techniques.every((t) => t.domain === 'injection')).toBe(true)
})
test('a domain query reaches the cross-cutting entry a class query cannot', () => {
  const byDomain = selectTechniques(index, { domain: 'injection' }).techniques.map((t) => t.id)
  const byClass = selectTechniques(index, { vuln_class: 'sql-injection' }).techniques.map((t) => t.id)
  expect(byDomain).toContain('cross-file-taint-source-to-sink')
  expect(byClass).not.toContain('cross-file-taint-source-to-sink')  // spec 7.3: documented, not fixed
})
test('domain and stack compose', () => {
  const r = selectTechniques(index, { domain: 'memory-safety', stack: 'c' })
  expect(r.techniques.map((t) => t.id)).toContain('unbounded-copy-into-fixed-buffer')
  expect(r.match).toBe('exact')
})
test('a domain with no entries for the queried stack reports none', () => {
  expect(selectTechniques(index, { domain: 'crypto', stack: 'node' }).match).toBe('none')
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL — `domain` is not a query field.

- [ ] **Step 3: Add the filter**

One more `.filter` in the existing chain. Ranking is unchanged.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/registry/router.ts packages/core/tests/registry/router.test.ts
git commit -m "feat(core): select techniques by domain"
```

---

## Task 5: Make C and C++ reachable

**Files:**
- Modify: `packages/core/src/recon/walk.ts`
- Modify: `packages/core/src/registry/vocabulary.ts`
- Create: `tests/fixtures/targets/c-memory-safety/`
- Test: `packages/core/tests/recon/profile-target.test.ts`, `packages/core/tests/registry/vocabulary.test.ts`

**Interfaces:**
- Consumes: `STACKS` (already holds `c` and `cpp`).
- Produces: `.c`, `.cc`, `.cpp`, `.h`, `.hpp` recognised as languages; `stackForLanguage('c')` and `('cpp')` resolve.

**Two changes, not one** (spec §3.4). The extension table alone leaves the language-to-stack map without `c` or `cpp`, so no stack is derived and the result is identical. The spec's own self-review caught this.

- [ ] **Step 1: Write the failing tests**

```typescript
test('a C project yields a c stack', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('targets/c-memory-safety') })
  expect(p.languages.map((l) => l.language)).toContain('c')
  expect(stackForLanguage('c')).toBe('c')
})
test('header files are recognised, not counted as unexamined', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('targets/c-memory-safety') })
  expect(p.skipped.some((s) => s.path.endsWith('.h'))).toBe(false)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL — no `c` language is produced.

- [ ] **Step 3: Create the fixture**

A small C program with an unbounded copy into a fixed buffer, a header, and one safe bounded copy as a negative control. No fetch-piped-to-interpreter strings anywhere — the guard scans fixtures.

- [ ] **Step 4: Add the extensions and the two language mappings**

- [ ] **Step 5: Run the full suite**

Expected: PASS. Note the coverage-share warning on the C fixture should now be small rather than total.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/recon/walk.ts packages/core/src/registry/vocabulary.ts tests/fixtures/targets/c-memory-safety packages/core/tests
git commit -m "feat(core): recognise C and C++ so the memory-safety domain can fire"
```

---

## Task 6: Agent identity and self-confirmation refusal

**Files:**
- Modify: `packages/core/src/findings/store.ts`
- Test: `packages/core/tests/findings/store.test.ts`

**Interfaces:**
- Consumes: `AddMeta`, `Verdict`, `Finding` (existing).
- Produces: `AddMeta` gains `reporting_agent: string`, required and rejected when blank after trimming. `Finding` gains `reporting_agents: string[]`. `recordVerdict` throws when the verdict's agent appears in that array.

**Deviation from the spec, with reasoning.** Spec §3.1 says a finding carries *the* reporting agent and a verdict from that id is refused — singular. Reading the store showed that is not sufficient: dedupe collapses two reports of the same defect into one finding, so if only the first reporter is recorded, **the second reporter can verify its own finding** and the gate is silently defeated. The store therefore keeps a set of reporting agents and refuses a verdict from any of them.

`reporting_agent` goes on `AddMeta`, **not** on `FindingInput`: `FindingInput` is the fingerprint's input, and putting agent identity there would make two hunters' identical findings fingerprint differently and stop collapsing — the opposite of what dedupe is for.

- [ ] **Step 1: Write the failing tests**

```typescript
test('add requires a non-blank reporting agent', () => {
  expect(() => s.add(base, { ...meta, reporting_agent: '  ' })).toThrow()
})
test('the reporting agent cannot confirm its own finding', () => {
  const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
  expect(() => s.recordVerdict(f.id, { agent: 'hunter-1', outcome: 'confirmed', reasoning: 'r' })).toThrow()
})
test('a different agent can confirm it', () => {
  const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
  expect(s.recordVerdict(f.id, { agent: 'verifier-1', outcome: 'confirmed', reasoning: 'r' }).status).toBe('confirmed')
})
// Review Focus 1 — the dedupe hole the spec did not anticipate.
test('a second reporter of a deduped finding also cannot confirm it', () => {
  const f = s.add(base, { ...meta, reporting_agent: 'hunter-1' })
  s.add({ ...base, line: 41 }, { ...meta, reporting_agent: 'hunter-2' })
  expect(s.get(f.id)!.reporting_agents.sort()).toEqual(['hunter-1', 'hunter-2'])
  expect(() => s.recordVerdict(f.id, { agent: 'hunter-2', outcome: 'confirmed', reasoning: 'r' })).toThrow()
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement**

`add` appends the reporter to `reporting_agents` when the fingerprint already exists, without duplicating. `recordVerdict` checks membership before validating the outcome, so a self-confirmation is refused regardless of what it claims.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/findings/store.ts packages/core/tests/findings/store.test.ts
git commit -m "feat(core): record reporting agents and refuse self-confirmation"
```

---

## Task 7: Severity in the store

**Files:**
- Modify: `packages/core/src/findings/store.ts`
- Modify: `packages/mcp/src/tools.ts`
- Test: `packages/core/tests/findings/store.test.ts`, `packages/mcp/tests/tools.test.ts`

**Interfaces:**
- Consumes: `Severity`, `SeverityFactors`, `BAND_RANK`, `computeSeverity`.
- Produces: `Verdict` gains `factors?: SeverityFactors`. `Finding` gains `severity_disputed: boolean` and `severity_by_agent: { agent: string; severity: Severity }[]`; `severity` becomes the highest band among them. `decideExitCode` is unchanged.

Spec §3.2. This deletes the MCP server's parallel `Map` and retires Phase 1's "last verdict that supplied factors wins", recorded at the time as arbitrary.

- [ ] **Step 1: Write the failing tests**

```typescript
const HIGH = { exploitability: 3, reachability: 3, blast_radius: 2, data_sensitivity: 2 } // 21 → high
const LOW  = { exploitability: 1, reachability: 0, blast_radius: 0, data_sensitivity: 0 } // 3  → info
const MAX_FACTORS = { exploitability: 3, reachability: 3, blast_radius: 3, data_sensitivity: 3 }

test('a single verifier sets the severity', () => {
  s.recordVerdict(id, { agent: 'v1', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  expect(s.get(id)!.severity!.band).toBe('high')
})
test('the highest band wins across verifiers', () => {
  s.recordVerdict(id, { agent: 'v1', outcome: 'confirmed', reasoning: 'r', factors: LOW })
  s.recordVerdict(id, { agent: 'v2', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  expect(s.get(id)!.severity!.band).toBe('high')
})
test('differing verifiers set severity_disputed and keep both', () => {
  s.recordVerdict(id, { agent: 'v1', outcome: 'confirmed', reasoning: 'r', factors: LOW })
  s.recordVerdict(id, { agent: 'v2', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  const f = s.get(id)!
  expect(f.severity_disputed).toBe(true)
  expect(f.severity_by_agent.map((x) => x.agent).sort()).toEqual(['v1', 'v2'])
})
test('agreeing verifiers are not disputed', () => {
  s.recordVerdict(id, { agent: 'v1', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  s.recordVerdict(id, { agent: 'v2', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  expect(s.get(id)!.severity_disputed).toBe(false)
})
// Review Focus 3.
test('factors on a disproved verdict do not raise the band of a dropped finding', () => {
  s.recordVerdict(id, { agent: 'v1', outcome: 'disproved', reasoning: 'r', factors: MAX_FACTORS })
  const f = s.get(id)!
  expect(f.status).toBe('dropped')
  expect(f.severity).toBeUndefined()
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement in the store**

Only a non-`disproved` verdict's factors contribute. Derive `severity` from the highest `BAND_RANK` among contributors; `severity_disputed` is true when two contributors differ in band.

- [ ] **Step 4: Delete the MCP side map**

Remove the session `Map`, the report-time splice, and `severity_overwritten`. `verify_finding` returns the store's own `severity`, `severity_disputed` and `severity_by_agent`.

- [ ] **Step 5: Run the full suite**

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/findings/store.ts packages/mcp/src/tools.ts packages/core/tests packages/mcp/tests
git commit -m "feat(core): severity lives in the store, highest band wins, disagreement recorded"
```

---

## Task 8: Reporters show a disputed spread

**Files:**
- Modify: `packages/core/src/report/markdown.ts`
- Modify: `packages/core/src/report/sarif.ts`
- Test: `packages/core/tests/report/markdown.test.ts`, `packages/core/tests/report/sarif.test.ts`

**Interfaces:**
- Consumes: `Finding.severity_disputed`, `Finding.severity_by_agent` (Task 7).
- Produces: no signature change.

- [ ] **Step 1: Write the failing tests**

```typescript
test('markdown states the spread on a disputed finding', () => {
  const md = toMarkdown([disputed], profile, { mode: 'full' })
  expect(md).toMatch(/verifiers disagreed/i)
  expect(md).toContain('high')
  expect(md).toContain('low')
})
test('an undisputed finding says nothing about disagreement', () => {
  expect(toMarkdown([agreed], profile, { mode: 'full' })).not.toMatch(/disagreed/i)
})
test('SARIF carries the dispute on the result', () => {
  expect(toSarif([disputed], profile, { mode: 'full' }).runs[0]!.results[0]!.properties!.severity_disputed).toBe(true)
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement**

Markdown: one line in the engineer-voice section naming each verifier's band. SARIF: `severity_disputed` and the per-agent bands in the existing result `properties`.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/report packages/core/tests/report
git commit -m "feat(core): report a disputed severity rather than hiding it"
```

---

## Task 9: `planHunts` — the assignment computation

**Files:**
- Create: `packages/core/src/hunt/plan-hunts.ts`
- Test: `packages/core/tests/hunt/plan-hunts.test.ts`

**Interfaces:**
- Consumes: `TargetProfile`, `RegistryIndex`, `DOMAINS`, `selectTechniques`, `stackForLanguage`.
- Produces:
  - `planHunts(profile: TargetProfile, index: RegistryIndex): HuntAssignment[]`
  - `type HuntAssignment = { domain: Domain; techniques: IndexedTechnique[]; hotspot_paths: string[]; coverage: TechniqueSelection['match']; reason?: string }`
- Pure: no I/O, no state. Exported from the package root.

**All ten domains are always returned** (spec §7.2). A domain with nothing to do comes back with an empty `techniques` array and a `reason`. It is never omitted — an uncovered domain and a missing domain must not look alike.

**No file list** (spec §5.1): the hunter's scope is the profile's walked set, which the caller already holds. Inlining it would duplicate every path ten times across the protocol boundary. Only `hotspot_paths` differs per domain.

- [ ] **Step 1: Write the failing tests**

```typescript
test('returns exactly ten assignments, one per domain, always', () => {
  const a = planHunts(emptyProfile, index)
  expect(a).toHaveLength(10)
  expect(a.map((x) => x.domain).sort()).toEqual([...DOMAINS].sort())
})
// Review Focus 2, and spec 8.2 item 5: empty and missing must differ BY TYPE.
test('a domain whose stack is absent is explicitly empty with a reason, never omitted', () => {
  const all = planHunts(nodeOnlyProfile, index)
  const a = all.find((x) => x.domain === 'memory-safety')
  expect(a).toBeDefined()              // present, not omitted
  expect(a!.techniques).toEqual([])
  expect(a!.coverage).not.toBe('exact')
  expect(a!.reason).toMatch(/stack|no technique/i)
  // The return type is a complete ten-element array, so "missing" is unrepresentable
  // rather than merely discouraged. An optional-key shape would fail this.
  expect(all.map((x) => x.domain)).toContain('memory-safety')
})
// Review Focus 5.
test('a domain with techniques but no hotspots still gets its techniques', () => {
  const a = planHunts(noHotspotProfile, index).find((x) => x.domain === 'injection')!
  expect(a.techniques.length).toBeGreaterThan(0)
  expect(a.hotspot_paths).toEqual([])
})
test('hotspot paths are the ones recon flagged for that domain', () => {
  const a = planHunts(expressProfile, index).find((x) => x.domain === 'authorization')!
  expect(a.hotspot_paths).toContain('src/server.js')
})
test('the injection assignment contains the cross-cutting taint entry', () => {
  const a = planHunts(expressProfile, index).find((x) => x.domain === 'injection')!
  expect(a.techniques.map((t) => t.id)).toContain('cross-file-taint-source-to-sink')
})
test('is pure — the same inputs give a deeply equal result', () => {
  expect(planHunts(expressProfile, index)).toEqual(planHunts(expressProfile, index))
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `planHunts`**

For each of the ten domains: derive the profile's stacks through `stackForLanguage`, call `selectTechniques` per stack and union the results, collect hotspot paths whose `domains` include this domain, and set `reason` when `techniques` is empty.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/hunt packages/core/tests/hunt
git commit -m "feat(core): compute hunt assignments for all ten domains"
```

---

## Task 10: The `plan_hunts` MCP tool

**Files:**
- Modify: `packages/mcp/src/tools.ts`
- Modify: `packages/mcp/src/server.ts`
- Test: `packages/mcp/tests/tools.test.ts`

**Interfaces:**
- Consumes: `planHunts` (Task 9).
- Produces: a sixth registered tool, `plan_hunts`, taking no arguments and returning the assignments for the currently profiled target. A thin translation with no domain logic, like the other five.

Named `plan_hunts`, not `plan_shards` — the latter stays free for Phase 2b's budget model (spec §5).

- [ ] **Step 1: Write the failing tests**

```typescript
test('registers exactly the Phase 2a tool set', async () => {
  expect((await listTools()).map((t) => t.name).sort())
    .toEqual(['plan_hunts','profile_target','record_finding','report','select_techniques','verify_finding'])
})
test('plan_hunts before any profile is a tool error, not a throw', async () => {
  const r = await callRaw('plan_hunts', {})
  expect(r.isError).toBe(true)
  expect(r.content[0]!.text).toMatch(/profile/i)
})
test('plan_hunts returns ten assignments after profiling', async () => {
  await call('profile_target', { target: dir })
  expect(json(await call('plan_hunts', {})).assignments).toHaveLength(10)
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Register the tool**

Reuse the existing `guard` wrapper so a refusal returns rather than throwing across the protocol.

- [ ] **Step 4: Run the full suite**

- [ ] **Step 5: Commit**

```bash
git add packages/mcp/src packages/mcp/tests
git commit -m "feat(mcp): expose plan_hunts"
```

---

## Task 11: Fixture negative controls

**Files:**
- Modify: `tests/fixtures/targets/express-vulnerable/`
- Test: `packages/core/tests/recon/profile-target.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: a fixture where a true positive is distinguishable from indiscriminate flagging.

Phase 1's review found this fixture has no negative control: every route lacks authorization, so an assertion that a route hotspot was flagged would pass against a fully-authorized application (spec §6.4). For a slice whose claim is "it found the real thing", that is disqualifying.

- [ ] **Step 1: Write the failing test**

```typescript
test('the fixture contains both a vulnerable and a safe form of each planted class', async () => {
  const src = await readFile(join(fixture('targets/express-vulnerable'), 'src/server.js'), 'utf8')
  expect(src).toMatch(/\$\d|\?\s*\]/)          // a parameterized query
  expect(src).toMatch(/requireAuth|isAuthed/)  // an authorization check on at least one route
})
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Add the negative controls**

A parameterized query beside the concatenated one, and an authorized route beside the unauthorized one. Keep the planted defects exactly as they are — later tasks assert on them.

- [ ] **Step 4: Run the full suite**

Expected: PASS. If an existing hotspot assertion now fails, that is this task finding a real over-flagging bug — fix the detector, not the fixture.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/targets/express-vulnerable packages/core/tests/recon/profile-target.test.ts
git commit -m "test: give the express fixture negative controls"
```

---

## Task 12: The hunter and verifier skills

**Files:**
- Create: `skills/sentinel-hunt/SKILL.md`
- Create: `skills/sentinel-verify/SKILL.md`
- Test: `packages/core/tests/skills.test.ts`

**Interfaces:**
- Consumes: the tool names from Task 10.
- Produces: two markdown skills the host harness reads.

Both are **thin** (spec §6.3). The security judgment lives in the technique entries' `detection` and `verification` prose, which already exists and was reviewed in Phase 1. The skills carry the loop, not the knowledge.

- [ ] **Step 1: Write the failing tests**

```typescript
test('both skills exist with frontmatter naming them', () => { /* name + description present */ })
test('the hunter skill tells the agent to supply its own identity', () => {
  expect(read('skills/sentinel-hunt/SKILL.md')).toMatch(/reporting_agent/)
})
test('the verifier skill states that ambiguous is a valid answer', () => {
  expect(read('skills/sentinel-verify/SKILL.md')).toMatch(/ambiguous/i)
})
test('the verifier skill requires an id different from the reporter', () => {
  expect(read('skills/sentinel-verify/SKILL.md')).toMatch(/different|must not.*same/i)
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Write the two skills**

Hunter: call `plan_hunts`, take your domain's assignment, read the techniques' `detection` prose, prioritise `hotspot_paths` but scan the whole set, record candidates with `file:line`, an explicit reachability claim, and your own `reporting_agent`. Verifier: read the candidate and the technique's `verification` prose, attempt to **disprove** it, answer `confirmed`, `disproved` or `ambiguous`, supply severity factors only when confirming, and use an id that is not the reporter's.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add skills packages/core/tests/skills.test.ts
git commit -m "feat(skills): add the hunter and verifier skills"
```

---

## Task 13: The stubbed-agent loop

**Files:**
- Test: `packages/mcp/tests/hunt-loop.test.ts`

**Interfaces:**
- Consumes: every tool from Task 10, the store from Tasks 6 and 7.
- Produces: no product code — this task proves the plumbing with canned agent output and claims nothing about judgment.

- [ ] **Step 1: Write the failing tests**

```typescript
test('a canned hunter candidate, verified by a different agent, reaches the report as confirmed', async () => {
  const { id } = json(await call('record_finding', { findings: [F], reporting_agent: 'hunter-1' })).accepted[0]
  await call('verify_finding', { id, agent: 'verifier-1', outcome: 'confirmed', reasoning: 'r', factors: HIGH })
  const md = json(await call('report', { format: 'markdown' })).body
  expect(md).toContain(F.technique_id)
  expect(md).toMatch(/## Confirmed/)
})
test('a disproved candidate never appears as confirmed in either output', async () => {
  await call('verify_finding', { id, agent: 'verifier-1', outcome: 'disproved', reasoning: 'r' })
  const r = json(await call('report', { format: 'sarif' }))
  expect(r.log.runs[0].results).toEqual([])
  expect(r.body ?? '').not.toMatch(/## Confirmed findings\n\n- /)
})
test('an ambiguous verdict lands in needs-review and is labelled not confirmed', async () => {
  await call('verify_finding', { id, agent: 'verifier-1', outcome: 'ambiguous', reasoning: 'r' })
  const md = json(await call('report', { format: 'markdown' })).body
  expect(md).toMatch(/Needs review/i)
  expect(md).toMatch(/NOT CONFIRMED/)
})
test('a self-confirmation attempt is refused at the tool boundary as a tool error', async () => {
  const r = await callRaw('verify_finding', { id, agent: 'hunter-1', outcome: 'confirmed', reasoning: 'r' })
  expect(r.isError).toBe(true)
})
// Review Focus 4 — agent output is untrusted.
test('a candidate whose file is outside the walked set is refused at ingest', async () => {
  const r = await callRaw('record_finding', { findings: [{ ...F, file: '../../etc/passwd' }] })
  expect(r.isError).toBe(true)
})
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement the ingest path check**

`record_finding` already rejects absolute paths, `..` segments and NUL bytes. Add membership in the profile's walked file set, so a path the agent invented cannot become a SARIF location.

- [ ] **Step 4: Run the full suite**

- [ ] **Step 5: Commit**

```bash
git add packages/mcp
git commit -m "test: prove the hunt loop end to end with stubbed agents"
```

---

## Task 14: The real-agent run and the phase gate

**Files:**
- Create: `scripts/hunt-integration.mjs`
- Modify: `SELF-SCAN.md`
- Modify: `docs/PHASE-1-DEFERRED.md` (mark I5 and the severity and agent-identity items closed)
- Test: `packages/cli/tests/e2e.test.ts`

**Interfaces:**
- Consumes: everything.
- Produces: an on-demand integration runner, and an honest record of what the agents actually found.

**Not in CI** (spec §8.3). Agent quality is measured and published, never asserted by a passing test.

- [ ] **Step 1: Write the failing end-to-end test**

```typescript
test('plan_hunts reaches the CLI pipeline and the injection assignment is non-empty', async () => { /* real binary */ })
test('the report still states that detection is limited to one domain', async () => {
  expect(out).toMatch(/injection/i)
})
```

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Write the integration runner**

Takes a target, runs attest → profile → `plan_hunts` → one real hunter → one real verifier → report, and prints found / missed / false positives against the fixture's known plants.

- [ ] **Step 4: Run it against the express fixture and record the result**

- [ ] **Step 5: Update `SELF-SCAN.md`**

Replace "this scan cannot find anything" with what is now true: one domain has detection, nine do not, and here is what the real-agent run found and missed. If the hunter missed the planted vulnerability, **say so** — that is the phase's most important finding either way.

- [ ] **Step 6: Run the full suite and the guard**

- [ ] **Step 7: Commit**

```bash
git add scripts/hunt-integration.mjs SELF-SCAN.md docs/PHASE-1-DEFERRED.md packages/cli/tests/e2e.test.ts
git commit -m "feat: add the real-agent integration run and record what it found"
```

---

## Done when

- `pnpm test` green; every task's tests present.
- All thirteen entries declare a domain; no entry routes nowhere.
- `planHunts` returns ten assignments on every profile, with empty ones carrying a reason.
- A self-confirmation is refused, including by a second reporter of a deduped finding.
- Severity lives in the store; the MCP side map is gone; a disputed finding shows its spread in both outputs.
- A C project yields a `c` stack and a non-empty `memory-safety` assignment.
- `SELF-SCAN.md` states honestly what the real-agent run found and missed.

## Deferred to later phases

Phase 2b: the chain agent, `plan_shards` and the budget model, the nine remaining domains as proven paths. Phase 2c: the explain-and-fix layer and the fix queue. Phase 2d: the Claude Code wrapper. Still open from Phase 1: token-level fingerprinting, the `derivation` pack field, upstream do-not-report lists, `readlink` symlink classification, and the re-triage of `docs/PHASE-1-DEFERRED.md` recommended in spec §9.3.
