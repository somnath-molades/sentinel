# Sentinel Phase 0–1 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Sentinel's harness-agnostic core — a standalone CLI and MCP server that resolves an authorized target, profiles it, routes security techniques from a validated registry, stores and dedupes findings, scores severity, and emits SARIF plus a plain-language report.

**Architecture:** A pnpm workspace with three packages. `@sentinel/core` holds all domain logic with no I/O framework coupling: schemas, scope lock, recon, registry index and router, findings store, severity, reporter. `@sentinel/mcp` is a thin MCP server exposing core as tools. `@sentinel/cli` is a thin command wrapper. Security knowledge lives in `registry/` as markdown and YAML, validated in CI, never compiled in. No agents in this plan — Phase 1 builds the plumbing agents will run on in Phase 2.

**Tech Stack:** TypeScript 5.x (strict), Node 20+, pnpm workspaces, vitest, zod (runtime schemas), yaml, commander (CLI), @modelcontextprotocol/sdk (MCP). Git and GitHub access via `git` and `gh` subprocesses — no SDK wrappers.

**Spec:** `docs/superpowers/specs/2026-10-24-project-sentinel-design.md`

## Global Constraints

- License: MIT. Every package `package.json` declares `"license": "MIT"`.
- Node engine floor: `>=20.0.0`. TypeScript `strict: true`, no `any` in exported signatures.
- No `curl | bash` and no network install in any script, ever (spec §8.2). CI greps for it.
- Read-only on targets. No package in this plan may write to, execute, or open a network connection to a target codebase (spec §1 non-goals).
- Every technique entry requires non-empty `defensive_use`, `detection`, and at least one `fix_pattern` (spec §5.2). Enforced by schema, not convention.
- Unstated upstream license means all rights reserved: do not vendor (spec §5.3).
- Scope lock is enforced in code, not documentation: a local path or a `gh`-accessible repo, nothing else (spec §9.3).
- Severity is computed, never inherited from depth tier (spec §4.1).
- No finding is reported as confirmed without a `file:line` and a reachability reason (spec §1 success criterion 2).
- Dependencies are pinned exactly (no `^`, no `~`) in every `package.json`.

## Review Focus

Input classes the spec implies but no task's happy-path tests exercise. Each has its test added to the task that owns the code.

1. **A target path that escapes the intended root** — symlink, `../`, or absolute path outside the resolved root. A user expects refusal, not a scan of their home directory. (Task 4)
2. **A repository with nothing recognizable in it** — empty, binary-only, or a language Sentinel has no profiler for. A user expects an honest empty profile and a clear message, not a crash or a fabricated stack. (Task 7)
3. **A hand-edited or malformed registry file** — bad YAML, missing `defensive_use`, unknown depth tier. A user expects the offending file named with a usable error, and the rest of the registry still working. (Task 3, Task 8)
4. **Near-duplicate findings** — the same defect reported by two hunters at line 40 and line 41, or after reformatting. A user expects one finding, not two. (Task 9)
5. **Files that are hostile to reading** — minified bundles, vendored directories, generated lockfiles, non-UTF8 bytes, multi-megabyte single files. A user expects these skipped with a reason, not a scan that stalls or burns the whole budget on `dist/`. (Task 7)

---

## File Structure

```
sentinel/
  package.json                       # workspace root, scripts, pinned devDeps
  pnpm-workspace.yaml
  tsconfig.base.json
  vitest.config.ts
  packages/
    core/
      src/
        types.ts                     # shared domain types, no logic
        schema/technique.ts          # zod schema + TechniqueEntry type
        schema/pack.ts               # zod schema + PackManifest type
        schema/target-profile.ts     # zod schema + TargetProfile type
        scope/resolve-target.ts      # scope lock
        recon/profile-target.ts      # orchestrates detectors
        recon/detect-stack.ts        # language + framework detection
        recon/walk.ts                # file enumeration + skip rules
        registry/build-index.ts      # packs -> index.json
        registry/router.ts           # select_techniques
        findings/fingerprint.ts      # stable finding identity
        findings/store.ts            # in-memory store + dedupe
        findings/severity.ts         # severity computation
        report/sarif.ts              # SARIF 2.1.0 emitter
        report/markdown.ts           # plain-language report
      tests/                         # mirrors src/
    mcp/
      src/server.ts                  # MCP tool registration
      src/tools.ts                   # tool handlers -> core calls
    cli/
      src/index.ts                   # commander wiring
      src/commands/{scan,packs,init}.ts
  registry/
    schema/technique.schema.json     # generated from zod, for editors + CI
    packs/<pack-id>/pack.yaml
    packs/<pack-id>/techniques/*.md
    AUDIT.md                         # license audit of upstream sources
    index.json                       # generated, committed
  tests/fixtures/
    targets/                         # deliberately vulnerable fixture repos
    registry/                        # valid + malformed registry fixtures
  .github/workflows/ci.yml
  AUTHORIZATION.md TERMS.md ACCEPTABLE-USE.md SECURITY.md NOTICE LICENSE
```

Split rationale: `core` has one responsibility per file and no framework imports, so every rule in it is unit-testable without spawning a server. `mcp` and `cli` are deliberately thin — they translate and nothing else, which is what keeps the core harness-agnostic by construction rather than by claim.

---

# Phase 0 — Foundation

## Task 1: Workspace skeleton and CI

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `vitest.config.ts`, `.gitignore`, `.github/workflows/ci.yml`
- Create: `packages/core/package.json`, `packages/core/tsconfig.json`, `packages/core/src/types.ts`
- Test: `packages/core/tests/smoke.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: workspace scripts `pnpm test`, `pnpm build`, `pnpm lint`, `pnpm check:no-remote-install`. Package name `@sentinel/core`, exports from `packages/core/src/index.ts`.

- [ ] **Step 1: Write the failing test**

```typescript
// packages/core/tests/smoke.test.ts
import { SENTINEL_CORE_VERSION } from '../src/index.js'

test('core package exports its version', () => {
  expect(SENTINEL_CORE_VERSION).toMatch(/^\d+\.\d+\.\d+$/)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/core/tests/smoke.test.ts`
Expected: FAIL — cannot resolve `../src/index.js`

- [ ] **Step 3: Create the workspace**

Root `package.json`: `"private": true`, `"packageManager": "pnpm@9.x"` (exact version), `"engines": { "node": ">=20.0.0" }`, scripts `test` (vitest run), `build` (tsc -b), `lint`, and `check:no-remote-install` (greps the tree for `curl` piped to a shell and exits non-zero on a hit). `tsconfig.base.json`: `strict: true`, `target: ES2022`, `module: NodeNext`, `declaration: true`. All devDependencies pinned exactly.

- [ ] **Step 4: Implement `SENTINEL_CORE_VERSION` in `packages/core/src/index.ts`**

Export the constant as a string literal matching `packages/core/package.json` version (`0.1.0`).

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm vitest run packages/core/tests/smoke.test.ts`
Expected: PASS

- [ ] **Step 6: Add CI workflow**

`.github/workflows/ci.yml` runs on `push` and `pull_request`: setup Node 20, `pnpm install --frozen-lockfile`, then `pnpm lint`, `pnpm build`, `pnpm test`, `pnpm check:no-remote-install`. Every job must pass for merge.

- [ ] **Step 7: Run the full suite**

Run: `pnpm lint && pnpm build && pnpm test && pnpm check:no-remote-install`
Expected: all pass

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: initialize pnpm workspace with core package and CI"
```

---

## Task 2: Legal documents

**Files:**
- Create: `LICENSE`, `AUTHORIZATION.md`, `TERMS.md`, `ACCEPTABLE-USE.md`, `SECURITY.md`, `NOTICE`
- Test: `packages/core/tests/legal-docs.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `AUTHORIZATION.md` is read verbatim by the `init` attestation prompt in Task 14. `NOTICE` is appended to by every vendored pack in Task 5.

- [ ] **Step 1: Write the failing test**

```typescript
// packages/core/tests/legal-docs.test.ts
const REQUIRED = ['LICENSE','AUTHORIZATION.md','TERMS.md','ACCEPTABLE-USE.md','SECURITY.md','NOTICE']

test.each(REQUIRED)('%s exists and is non-trivial', (f) => {
  expect(readFileSync(resolve(repoRoot, f), 'utf8').length).toBeGreaterThan(200)
})

test('LICENSE is MIT', () => {
  expect(readFileSync(resolve(repoRoot,'LICENSE'),'utf8')).toContain('MIT License')
})

test('AUTHORIZATION.md states the mechanical scope limit', () => {
  const t = readFileSync(resolve(repoRoot,'AUTHORIZATION.md'),'utf8')
  expect(t).toMatch(/local (filesystem )?path/i)
  expect(t).toMatch(/refus/i)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/core/tests/legal-docs.test.ts`
Expected: FAIL — files do not exist

- [ ] **Step 3: Write the documents**

Content per spec §9. `AUTHORIZATION.md`: what the user attests, that the attestation is recorded with a timestamp, and that scope is enforced in code — a local path or a `gh`-accessible repo, everything else refused. `TERMS.md`: MIT warranty disclaimer plus an explicit misuse-and-liability clause placing responsibility for authorization on the user. `ACCEPTABLE-USE.md`: defensive use on code you own or are authorized to assess; no unauthorized targets; no weaponized payloads. `SECURITY.md`: how to report a vulnerability in Sentinel itself, and the response commitment. `NOTICE`: attribution header, empty list to be filled by Task 5.

Each document opens with a line stating it is not legal advice and is pending review by qualified counsel (spec §9.5 makes that review a launch blocker).

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm vitest run packages/core/tests/legal-docs.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: add license, authorization, terms, acceptable use and security policy"
```

---

## Task 3: Technique and pack schemas

**Files:**
- Create: `packages/core/src/schema/technique.ts`, `packages/core/src/schema/pack.ts`
- Create: `tests/fixtures/registry/valid-technique.md`, `tests/fixtures/registry/missing-defensive-use.md`, `tests/fixtures/registry/bad-yaml.md`
- Test: `packages/core/tests/schema/technique.test.ts`, `packages/core/tests/schema/pack.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `DEPTH_TIERS = ['L0','L1','L2','L3','L4','L5'] as const`
  - `techniqueSchema: ZodType<TechniqueEntry>`
  - `type TechniqueEntry = { id: string; vuln_classes: string[]; cwe?: string[]; depth_tier: DepthTier; stacks: string[]; detection: string; verification: string; defensive_use: string; fix_patterns: FixPattern[]; references: string[]; provenance: { pack: string; upstream_commit?: string } }`
  - `type FixPattern = { stack: string; tier: 'mechanical'|'guided'|'design-change'; guidance: string }`
  - `parseTechnique(markdown: string, source: string): Result<TechniqueEntry, SchemaError>`
  - `packSchema: ZodType<PackManifest>`
  - `type PackManifest = { id: string; name: string; source_url: string; license: string; ingestion_mode: 'vendored'|'original'|'external'; upstream_commit?: string; coverage: DepthTier[]; trust_tier: 'first-party'|'reviewed'|'community' }`
  - `type SchemaError = { file: string; problem: string }`

Technique entries are markdown with YAML frontmatter: frontmatter carries every field except the prose ones, and `detection`, `verification`, `defensive_use` come from `##`-headed body sections so they stay readable and PR-reviewable.

- [ ] **Step 1: Write the failing tests**

```typescript
// technique.test.ts
test('parses a valid technique entry', () => {
  const r = parseTechnique(read('valid-technique.md'), 'valid-technique.md')
  expect(r.ok).toBe(true)
  expect(r.value.id).toBe('sql-injection-string-concat')
  expect(r.value.depth_tier).toBe('L1')
  expect(r.value.fix_patterns).toHaveLength(2)
})

test('rejects an entry with no defensive_use', () => {
  const r = parseTechnique(read('missing-defensive-use.md'), 'missing-defensive-use.md')
  expect(r.ok).toBe(false)
  expect(r.error.problem).toMatch(/defensive_use/)
  expect(r.error.file).toBe('missing-defensive-use.md')
})

test('rejects an entry with no fix_patterns', () => { /* asserts /fix_pattern/ in error */ })
test('rejects an unknown depth_tier', () => { /* asserts the tier value appears in the error */ })

test('malformed YAML reports the file, does not throw', () => {
  expect(() => parseTechnique(read('bad-yaml.md'), 'bad-yaml.md')).not.toThrow()
  expect(parseTechnique(read('bad-yaml.md'), 'bad-yaml.md').ok).toBe(false)
})

// pack.test.ts
test('rejects a pack whose license is unstated with ingestion_mode vendored', () => {
  const r = packSchema.safeParse({ ...base, license: 'UNSTATED', ingestion_mode: 'vendored' })
  expect(r.success).toBe(false)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm vitest run packages/core/tests/schema`
Expected: FAIL — modules not found

- [ ] **Step 3: Write the three fixture files**

`valid-technique.md` covers SQL injection via string concatenation: `depth_tier: L1`, stacks `node`/`python`, two fix patterns (one `mechanical` for parameterized queries, one `guided` for an ORM migration). The other two fixtures are deliberate corruptions of it.

- [ ] **Step 4: Implement the schemas**

`techniqueSchema` in `schema/technique.ts` with zod; `parseTechnique` splits frontmatter from body, parses YAML, lifts the three prose sections from `##` headings, and returns a `Result` — never throws. `packSchema` in `schema/pack.ts` adds a refinement rejecting `ingestion_mode: 'vendored'` when `license` is `UNSTATED` or absent (spec §5.3).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm vitest run packages/core/tests/schema`
Expected: PASS

- [ ] **Step 6: Generate the JSON Schema for editors and CI**

Add script `pnpm gen:schema` emitting `registry/schema/technique.schema.json` from the zod schema. Commit the generated file.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): add technique and pack schemas with mandatory defensive_use"
```

---

## Task 4: Scope lock

**Files:**
- Create: `packages/core/src/scope/resolve-target.ts`
- Test: `packages/core/tests/scope/resolve-target.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `resolveTarget(input: string, opts?: { allowGitHub?: boolean }): Promise<Result<ResolvedTarget, ScopeRefusal>>`, `type ResolvedTarget = { kind: 'local'; root: string } | { kind: 'github'; owner: string; repo: string; root: string }`, `type ScopeRefusal = { reason: string }`

This is the spec's §9.3 legal position expressed as code, so it fails closed: anything not provably in scope is refused.

- [ ] **Step 1: Write the failing tests**

```typescript
test('accepts an existing local directory', async () => {
  const r = await resolveTarget(fixtureDir)
  expect(r.ok).toBe(true)
  expect(r.value).toEqual({ kind: 'local', root: realpathSync(fixtureDir) })
})

test('refuses a path that does not exist', async () => {
  expect((await resolveTarget('/nope/nothing')).ok).toBe(false)
})

test('refuses a symlink escaping the given root', async () => {
  // fixture: <dir>/escape -> /etc
  const r = await resolveTarget(join(fixtureDir, 'escape'))
  expect(r.ok).toBe(false)
  expect(r.error.reason).toMatch(/outside|escape/i)
})

test('refuses a bare http(s) URL that is not a GitHub repo', async () => {
  expect((await resolveTarget('https://example.com/app')).ok).toBe(false)
})

test('refuses a GitHub repo the authenticated user cannot access', async () => {
  // gh probe stubbed to exit non-zero
  const r = await resolveTarget('https://github.com/someone/private', { allowGitHub: true })
  expect(r.ok).toBe(false)
  expect(r.error.reason).toMatch(/access|authoriz/i)
})

test('refuses a GitHub target when allowGitHub is not set', async () => { /* default-deny */ })
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm vitest run packages/core/tests/scope`
Expected: FAIL — module not found

- [ ] **Step 3: Implement `resolveTarget`**

Local branch: `realpath` the input, confirm it is a directory, and reject when the resolved path is not contained by the resolved root it was given. GitHub branch: accept only `github.com/<owner>/<repo>` forms, then probe access with `gh repo view <owner>/<repo> --json nameWithOwner`; a non-zero exit is a refusal. Clone target to a temp directory for reading. Default-deny: unknown shapes return a refusal, never a best guess. Inject the `gh` runner as an optional parameter so tests stub it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm vitest run packages/core/tests/scope`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): enforce target scope lock, default-deny"
```

---

## Task 5: Upstream license audit and two validated packs

**Files:**
- Create: `registry/AUDIT.md`
- Create: `registry/packs/<pack-a>/pack.yaml` + `techniques/*.md`
- Create: `registry/packs/<pack-b>/pack.yaml` + `techniques/*.md`
- Modify: `NOTICE`
- Test: `packages/core/tests/registry/packs-validate.test.ts`

**Interfaces:**
- Consumes: `packSchema`, `parseTechnique` (Task 3).
- Produces: at least 12 real technique entries covering L0–L2, which Task 8's router tests and Task 6's profile work read as fixtures.

This is the task that proves the schema survives contact with real upstream material. Pick the two packs for *dissimilarity* — one skill-shaped markdown repo, one tool-shaped repo — because a schema that fits two similar sources teaches nothing.

- [ ] **Step 1: Audit all eleven upstream sources**

For each source in spec §5.4, record in `registry/AUDIT.md`: name, URL, resolved license (verified by reading the repository's own `LICENSE`, not inferred from a README badge), the commit audited, date, coverage areas, and assigned `ingestion_mode` per spec §5.3. A source with no `LICENSE` file is recorded as `UNSTATED` and assigned `original` — do not vendor.

- [ ] **Step 2: Write the failing test**

```typescript
test('every pack manifest validates', () => {
  for (const dir of packDirs()) {
    expect(packSchema.safeParse(loadYaml(join(dir,'pack.yaml'))).success).toBe(true)
  }
})

test('every technique entry validates', () => {
  const errors = allTechniqueFiles().map(f => parseTechnique(read(f), f)).filter(r => !r.ok)
  expect(errors.map(e => e.error)).toEqual([])
})

test('registry covers L0 through L2', () => {
  const tiers = new Set(allTechniques().map(t => t.depth_tier))
  expect([...tiers]).toEqual(expect.arrayContaining(['L0','L1','L2']))
})

test('at least 12 technique entries exist', () => {
  expect(allTechniques().length).toBeGreaterThanOrEqual(12)
})

test('every vendored pack appears in NOTICE', () => {
  const notice = read('NOTICE')
  for (const p of packs().filter(p => p.ingestion_mode === 'vendored')) {
    expect(notice).toContain(p.source_url)
  }
})
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pnpm vitest run packages/core/tests/registry/packs-validate.test.ts`
Expected: FAIL — no packs present

- [ ] **Step 4: Normalize the two chosen packs by hand**

By hand, deliberately — the `ingest-pack` skill is Phase 3, and writing these manually is how we learn what that skill must do. Record every friction point in `registry/AUDIT.md` under a "Normalizer requirements" heading; that section is the input to the Phase 3 plan.

For `original`-mode sources write the technique from the public vulnerability class, citing the repository as inspiration under `references`. Do not copy its text.

- [ ] **Step 5: Update NOTICE**

One entry per vendored pack: source URL, license, upstream commit.

- [ ] **Step 6: Run test to verify it passes**

Run: `pnpm vitest run packages/core/tests/registry/packs-validate.test.ts`
Expected: PASS

- [ ] **Step 7: Wire pack validation into CI**

Add the registry validation test to the `pnpm test` path so a malformed PR to `registry/` fails CI.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(registry): audit upstream sources and add two validated packs"
```

---

## Task 6: Target profile schema

**Files:**
- Create: `packages/core/src/schema/target-profile.ts`
- Test: `packages/core/tests/schema/target-profile.test.ts`

**Interfaces:**
- Consumes: `DEPTH_TIERS` (Task 3), `ResolvedTarget` (Task 4).
- Produces: `targetProfileSchema`, and `type TargetProfile = { schema_version: 1; target: ResolvedTarget; generated_at: string; languages: LangStat[]; frameworks: string[]; entrypoints: Entrypoint[]; auth_surfaces: string[]; data_layer: string[]; iac: string[]; ci: string[]; client_boundary: string[]; hotspots: Hotspot[]; skipped: SkipRecord[]; file_count: number; truncated: boolean }`
- `type LangStat = { language: string; files: number; bytes: number }`
- `type Entrypoint = { path: string; kind: 'http-route'|'cli'|'job'|'webhook'|'serverless'; detail?: string }`
- `type Hotspot = { path: string; reason: string; domains: string[] }`
- `type SkipRecord = { path: string; reason: 'minified'|'vendored'|'generated'|'binary'|'too-large'|'not-utf8' }`

`skipped` and `truncated` are on the profile, not hidden in logs: a user must be able to see what Sentinel did not look at. Omitting that is how a scanner quietly lies about its coverage.

- [ ] **Step 1: Write the failing test**

```typescript
test('accepts a minimal profile', () => {
  expect(targetProfileSchema.safeParse(minimalProfile).success).toBe(true)
})
test('rejects an unknown skip reason', () => { /* 'because' is not in the enum */ })
test('rejects a missing schema_version', () => { /* ... */ })
test('accepts an empty profile for a repo with no detected stack', () => {
  expect(targetProfileSchema.safeParse({ ...minimalProfile, languages: [], frameworks: [], entrypoints: [] }).success).toBe(true)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm vitest run packages/core/tests/schema/target-profile.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement `targetProfileSchema`**

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): add target profile schema with explicit skip accounting"
```

---

# Phase 1 — Core

## Task 7: Recon — walk and profile

**Files:**
- Create: `packages/core/src/recon/walk.ts`, `packages/core/src/recon/detect-stack.ts`, `packages/core/src/recon/profile-target.ts`
- Create: `tests/fixtures/targets/express-vulnerable/`, `tests/fixtures/targets/empty-repo/`, `tests/fixtures/targets/hostile-files/`
- Test: `packages/core/tests/recon/walk.test.ts`, `packages/core/tests/recon/profile-target.test.ts`

**Interfaces:**
- Consumes: `ResolvedTarget` (Task 4), `TargetProfile` (Task 6).
- Produces: `walkTarget(root: string, opts?: WalkOptions): Promise<{ files: FileRecord[]; skipped: SkipRecord[]; truncated: boolean }>`, `type FileRecord = { path: string; bytes: number; language: string | null }`, `type WalkOptions = { maxFiles?: number; maxFileBytes?: number }` (defaults 10000 and 1_048_576), `profileTarget(target: ResolvedTarget, opts?: WalkOptions): Promise<TargetProfile>`

The fixture targets created here are the first deposit in the vulnerable-fixture corpus the spec names as its most important test asset (§14). Every later task adds to them.

- [ ] **Step 1: Write the failing tests**

```typescript
// walk.test.ts
test('skips vendored, generated, minified and oversized files with reasons', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  const reasons = Object.fromEntries(r.skipped.map(s => [basename(s.path), s.reason]))
  expect(reasons['app.min.js']).toBe('minified')
  expect(reasons['pnpm-lock.yaml']).toBe('generated')
  expect(reasons['logo.png']).toBe('binary')
  expect(reasons['huge.json']).toBe('too-large')
  expect(r.skipped.some(s => s.path.includes('node_modules'))).toBe(true)
})

test('does not follow symlinks out of the root', async () => {
  const r = await walkTarget(fixture('hostile-files'))
  expect(r.files.every(f => !f.path.startsWith('/etc'))).toBe(true)
})

test('sets truncated when maxFiles is hit', async () => {
  const r = await walkTarget(fixture('express-vulnerable'), { maxFiles: 2 })
  expect(r.truncated).toBe(true)
  expect(r.files).toHaveLength(2)
})

test('non-UTF8 file is skipped, not decoded', async () => { /* reason 'not-utf8' */ })

// profile-target.test.ts
test('profiles an express app', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('express-vulnerable') })
  expect(p.frameworks).toContain('express')
  expect(p.languages[0].language).toBe('javascript')
  expect(p.entrypoints.some(e => e.kind === 'http-route')).toBe(true)
  expect(p.hotspots.some(h => h.domains.includes('authorization'))).toBe(true)
})

test('an empty repo profiles honestly instead of crashing', async () => {
  const p = await profileTarget({ kind: 'local', root: fixture('empty-repo') })
  expect(p.languages).toEqual([])
  expect(p.frameworks).toEqual([])
  expect(p.entrypoints).toEqual([])
  expect(p.file_count).toBe(0)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm vitest run packages/core/tests/recon`
Expected: FAIL

- [ ] **Step 3: Build the three fixture targets**

`express-vulnerable`: a small Express app with a concatenated SQL query, a route with no authorization check, and a committed `.env`. `empty-repo`: a directory with only `.git`. `hostile-files`: one file per skip reason, plus a symlink to `/etc`.

- [ ] **Step 4: Implement `walkTarget`**

Skip classification order matters — check path patterns (`node_modules`, `vendor`, `dist`, lockfiles) before reading bytes, so hostile files are never opened. Minified detection: average line length over a threshold on a bounded prefix read. Never follow a symlink whose realpath leaves the root. Stop at `maxFiles` and set `truncated`.

- [ ] **Step 5: Implement `detectStack` and `profileTarget`**

`detectStack` reads manifest files (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `composer.json`, `Gemfile`) and maps declared dependencies to framework names via a table. `profileTarget` composes walk plus detect, derives entrypoints from framework-specific route patterns, and marks hotspots where a file touches auth, data access, or a trust boundary. Return an honest empty profile when nothing is detected — never guess a stack.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pnpm vitest run packages/core/tests/recon`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): add target recon with explicit skip and truncation accounting"
```

---

## Task 8: Registry index and router

**Files:**
- Create: `packages/core/src/registry/build-index.ts`, `packages/core/src/registry/router.ts`
- Test: `packages/core/tests/registry/build-index.test.ts`, `packages/core/tests/registry/router.test.ts`

**Interfaces:**
- Consumes: `TechniqueEntry`, `PackManifest` (Task 3), real packs (Task 5).
- Produces: `buildIndex(registryRoot: string): Promise<{ index: RegistryIndex; errors: SchemaError[] }>`, `type RegistryIndex = { schema_version: 1; built_at: string; techniques: IndexedTechnique[] }`, `type IndexedTechnique = Pick<TechniqueEntry,'id'|'vuln_classes'|'depth_tier'|'stacks'> & { pack: string; path: string }`, `selectTechniques(index: RegistryIndex, q: TechniqueQuery): IndexedTechnique[]`, `type TechniqueQuery = { vuln_class?: string; stack?: string; depth_tier?: DepthTier; limit?: number }`

Ranking is keyword, class and stack filtering only — deliberately not embeddings (spec §5.6), so a user can always see exactly why a technique fired.

- [ ] **Step 1: Write the failing tests**

```typescript
// build-index.test.ts
test('indexes every valid technique in the real registry', async () => {
  const { index, errors } = await buildIndex(registryRoot)
  expect(errors).toEqual([])
  expect(index.techniques.length).toBeGreaterThanOrEqual(12)
})

test('one malformed entry is reported but the rest still index', async () => {
  const { index, errors } = await buildIndex(fixture('registry/one-bad-entry'))
  expect(errors).toHaveLength(1)
  expect(errors[0].file).toContain('missing-defensive-use')
  expect(index.techniques.length).toBeGreaterThan(0)
})

// router.test.ts
test('filters by stack', () => {
  const r = selectTechniques(index, { stack: 'node' })
  expect(r.every(t => t.stacks.includes('node') || t.stacks.includes('*'))).toBe(true)
})

test('filters by vuln_class and ranks exact class matches first', () => {
  const r = selectTechniques(index, { vuln_class: 'sql-injection', stack: 'node' })
  expect(r[0].vuln_classes).toContain('sql-injection')
})

test('an unknown stack returns stack-agnostic techniques, not everything', () => {
  const r = selectTechniques(index, { stack: 'cobol' })
  expect(r.every(t => t.stacks.includes('*'))).toBe(true)
})

test('respects limit', () => {
  expect(selectTechniques(index, { limit: 3 })).toHaveLength(3)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL — modules not found

- [ ] **Step 3: Create the `one-bad-entry` registry fixture**

A valid pack containing one valid technique and one copy of `missing-defensive-use.md`.

- [ ] **Step 4: Implement `buildIndex`**

Walk `registry/packs/*/`, validate each manifest and entry, collect `SchemaError`s rather than throwing, and index only what validated. Add script `pnpm gen:index` writing `registry/index.json`; CI asserts the committed index matches a fresh build.

- [ ] **Step 5: Implement `selectTechniques`**

Filter on the supplied fields, treat `*` as a stack wildcard, and sort by match specificity: exact `vuln_class` hit, then exact stack hit, then wildcard. Pure function over the index — no file I/O.

- [ ] **Step 6: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): add registry index builder and deterministic technique router"
```

---

## Task 9: Findings store, fingerprint and dedupe

**Files:**
- Create: `packages/core/src/findings/fingerprint.ts`, `packages/core/src/findings/store.ts`
- Test: `packages/core/tests/findings/fingerprint.test.ts`, `packages/core/tests/findings/store.test.ts`

**Interfaces:**
- Consumes: `DepthTier` (Task 3); the `Severity` type from `findings/severity.ts` (Task 10) as a type-only forward reference, which `tsc` resolves within the package regardless of task order.
- Produces:
  - `fingerprint(f: FindingInput): string` — sha256 hex, 16 chars
  - `type FindingInput = { technique_id: string; file: string; line: number; snippet: string }`
  - `type Finding = FindingInput & { id: string; status: 'candidate'|'confirmed'|'dropped'|'needs-review'; depth_tier: DepthTier; reachability: string; verdicts: Verdict[]; severity?: Severity }`
  - `type Verdict = { agent: string; outcome: 'confirmed'|'disproved'|'ambiguous'; reasoning: string }`
  - `class FindingsStore` with `add(input, meta): Finding`, `recordVerdict(id, v: Verdict): Finding`, `get(id)`, `list(filter?: { status?: Finding['status'] }): Finding[]`

Fingerprint deliberately excludes the line number and normalizes whitespace, so reformatting a file does not resurrect a closed finding and two hunters reporting the same defect one line apart collapse into one.

- [ ] **Step 1: Write the failing tests**

```typescript
// fingerprint.test.ts
test('same defect at a different line fingerprints identically', () => {
  expect(fingerprint({ ...base, line: 40 })).toBe(fingerprint({ ...base, line: 41 }))
})
test('whitespace and indentation changes do not change the fingerprint', () => {
  expect(fingerprint({ ...base, snippet: '  query( a + b )' })).toBe(fingerprint({ ...base, snippet: 'query(a+b)' }))
})
test('a different technique on the same line fingerprints differently', () => { /* ... */ })
test('a different file fingerprints differently', () => { /* ... */ })

// store.test.ts
test('adding the same defect twice yields one finding', () => {
  const s = new FindingsStore()
  const a = s.add(base, meta); const b = s.add({ ...base, line: 41 }, meta)
  expect(b.id).toBe(a.id)
  expect(s.list()).toHaveLength(1)
})

test('a finding starts as candidate', () => { expect(s.add(base, meta).status).toBe('candidate') })

test('a confirming verdict promotes to confirmed', () => {
  expect(s.recordVerdict(id, { agent:'v1', outcome:'confirmed', reasoning:'r' }).status).toBe('confirmed')
})

test('a disproving verdict drops the finding', () => { /* status 'dropped' */ })

test('an ambiguous verdict yields needs-review, never confirmed', () => {
  expect(s.recordVerdict(id, { agent:'v1', outcome:'ambiguous', reasoning:'r' }).status).toBe('needs-review')
})

test('a disproving verdict after a confirming one wins', () => {
  // spec: verification is a hard gate, so any disproof drops it
  s.recordVerdict(id, { agent:'v1', outcome:'confirmed', reasoning:'r' })
  expect(s.recordVerdict(id, { agent:'v2', outcome:'disproved', reasoning:'r' }).status).toBe('dropped')
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL

- [ ] **Step 3: Implement `fingerprint`**

sha256 over `technique_id` + `\0` + `file` + `\0` + the snippet with all whitespace runs collapsed and leading/trailing whitespace removed. Truncate the hex digest to 16 characters.

- [ ] **Step 4: Implement `FindingsStore`**

A `Map` keyed by fingerprint. `add` returns the existing finding when the fingerprint is already present, appending nothing. `recordVerdict` applies the precedence `disproved > ambiguous > confirmed`, which is the spec's hard gate (§6.2) expressed as a rule.

- [ ] **Step 5: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): add findings store with reformat-stable fingerprint dedupe"
```

---

## Task 10: Severity computation

**Files:**
- Create: `packages/core/src/findings/severity.ts`
- Test: `packages/core/tests/findings/severity.test.ts`

**Interfaces:**
- Consumes: `Finding` (Task 9).
- Produces: `computeSeverity(f: SeverityFactors): Severity`, `type SeverityFactors = { exploitability: 0|1|2|3; reachability: 0|1|2|3; blast_radius: 0|1|2|3; data_sensitivity: 0|1|2|3 }`, `type Severity = { band: 'critical'|'high'|'medium'|'low'|'info'; score: number; factors: SeverityFactors }`

Weights and bands are pinned here so severity is reproducible and arguable, not a model's mood: `score = exploitability*3 + reachability*3 + blast_radius*2 + data_sensitivity*2` (max 30). Bands: `>=24` critical, `>=17` high, `>=10` medium, `>=4` low, else info.

- [ ] **Step 1: Write the failing tests**

```typescript
test('maximum factors are critical', () => {
  expect(computeSeverity({ exploitability:3, reachability:3, blast_radius:3, data_sensitivity:3 }))
    .toMatchObject({ band: 'critical', score: 30 })
})

test('unreachable code caps out below high', () => {
  const s = computeSeverity({ exploitability:3, reachability:0, blast_radius:3, data_sensitivity:3 })
  expect(s.score).toBe(21)
  expect(s.band).toBe('high')
})

test('all-zero factors are info', () => {
  expect(computeSeverity({ exploitability:0, reachability:0, blast_radius:0, data_sensitivity:0 }).band).toBe('info')
})

test('depth tier does not appear in the computation', () => {
  // asserts computeSeverity's parameter type has no tier field — spec §4.1
  expect(Object.keys(computeSeverity(base).factors).sort())
    .toEqual(['blast_radius','data_sensitivity','exploitability','reachability'])
})

test.each([[24,'critical'],[23,'high'],[17,'high'],[16,'medium'],[10,'medium'],[9,'low'],[4,'low'],[3,'info']])(
  'score %i bands as %s', (score, band) => { /* factor sets chosen to hit each boundary exactly */ })
```

- [ ] **Step 2: Run test to verify it fails**

Expected: FAIL

- [ ] **Step 3: Implement `computeSeverity`**

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(core): add reproducible severity scoring independent of depth tier"
```

---

## Task 11: Reporter — SARIF and markdown

**Files:**
- Create: `packages/core/src/report/sarif.ts`, `packages/core/src/report/markdown.ts`
- Test: `packages/core/tests/report/sarif.test.ts`, `packages/core/tests/report/markdown.test.ts`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `TargetProfile`.
- Produces: `toSarif(findings: Finding[], profile: TargetProfile): SarifLog`, `toMarkdown(findings: Finding[], profile: TargetProfile, opts: { mode: 'full'|'pure-reasoning' }): string`

- [ ] **Step 1: Write the failing tests**

```typescript
// sarif.test.ts
test('emits SARIF 2.1.0 with one result per confirmed finding', () => {
  const log = toSarif(findings, profile)
  expect(log.version).toBe('2.1.0')
  expect(log.runs[0].results).toHaveLength(confirmedCount)
})

test('excludes dropped and needs-review findings from results', () => { /* ... */ })

test('every result carries a physical location with a line', () => {
  for (const r of toSarif(findings, profile).runs[0].results) {
    expect(r.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0)
  }
})

test('validates against the SARIF 2.1.0 JSON schema', () => { /* ajv against vendored schema */ })

// markdown.test.ts
test('pure-reasoning mode prints the coverage banner', () => {
  const md = toMarkdown(findings, profile, { mode: 'pure-reasoning' })
  expect(md).toMatch(/dependency CVE/i)
  expect(md).toMatch(/secret/i)
})

test('full mode prints no coverage banner', () => { /* ... */ })

test('every finding renders both a plain and an engineer section', () => {
  const md = toMarkdown(findings, profile, { mode: 'full' })
  expect(md).toContain('What this means')
  expect(md).toContain('Technical detail')
})

test('reports skipped files and truncation so coverage is not overstated', () => {
  const md = toMarkdown(findings, { ...profile, truncated: true }, { mode: 'full' })
  expect(md).toMatch(/not scanned|truncated/i)
})

test('a needs-review finding is never labelled confirmed', () => { /* ... */ })
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL

- [ ] **Step 3: Implement `toSarif`**

SARIF 2.1.0. One `run` with `tool.driver.name: 'Sentinel'`, one `rule` per distinct technique, one `result` per confirmed finding with `ruleId`, `level` mapped from the severity band, `message`, and a `physicalLocation` carrying `startLine`. Vendor the SARIF JSON schema into `tests/fixtures/` for the validation test.

- [ ] **Step 4: Implement `toMarkdown`**

Order: summary counts by band, then the pure-reasoning banner when that mode is set (spec §8), then findings grouped by band, each with a `What this means` plain section and a `Technical detail` section, then a coverage section listing skip reasons with counts and the truncation flag.

- [ ] **Step 5: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(core): add SARIF and plain-language reporters with honest coverage reporting"
```

---

## Task 12: MCP server

**Files:**
- Create: `packages/mcp/package.json`, `packages/mcp/tsconfig.json`, `packages/mcp/src/server.ts`, `packages/mcp/src/tools.ts`
- Test: `packages/mcp/tests/tools.test.ts`

**Interfaces:**
- Consumes: every exported function from `@sentinel/core`.
- Produces: an MCP server over stdio registering the Phase-1 subset of spec §3.3: `profile_target`, `select_techniques`, `record_finding`, `verify_finding`, `report`. The deferred tools (`plan_shards`, `detect_chains`, `explain_finding`, `emit_fix_prompt`, `scan_self`) belong to Phase 2 and are not registered here.

Handlers translate and nothing else — no domain logic in this package. That is what keeps the core reusable by the Codex and Cursor wrappers without change.

- [ ] **Step 1: Write the failing tests**

```typescript
test('registers exactly the Phase 1 tool set', async () => {
  expect((await listTools()).map(t => t.name).sort())
    .toEqual(['profile_target','record_finding','report','select_techniques','verify_finding'])
})

test('profile_target refuses an out-of-scope target with a usable message', async () => {
  const r = await callTool('profile_target', { target: '/etc' })
  expect(r.isError).toBe(true)
  expect(r.content[0].text).toMatch(/scope|refus/i)
})

test('record_finding then report round-trips a confirmed finding', async () => { /* ... */ })

test('a handler contains no domain logic', () => {
  // asserts tools.ts imports its computation from @sentinel/core
  expect(read('packages/mcp/src/tools.ts')).toMatch(/@sentinel\/core/)
})
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL

- [ ] **Step 3: Implement the server and handlers**

Use `@modelcontextprotocol/sdk` over stdio. Each tool declares a zod input schema reusing the core schemas rather than redeclaring shapes. Errors return `isError: true` with the refusal reason — never a thrown exception across the protocol boundary. Session-scoped `FindingsStore` instance.

- [ ] **Step 4: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(mcp): expose Phase 1 core tools over MCP stdio"
```

---

## Task 13: CLI

**Files:**
- Create: `packages/cli/package.json`, `packages/cli/tsconfig.json`, `packages/cli/src/index.ts`, `packages/cli/src/commands/scan.ts`, `packages/cli/src/commands/packs.ts`
- Test: `packages/cli/tests/scan.test.ts`, `packages/cli/tests/packs.test.ts`

**Interfaces:**
- Consumes: `@sentinel/core`.
- Produces: binary `sentinel` with `scan <target> [--format sarif|markdown] [--fail-on <band>] [--max-files <n>]`, `packs list`, `packs audit`.

The CLI working before any plugin exists is what proves harness-agnosticism by construction (spec §13.1).

- [ ] **Step 1: Write the failing tests**

```typescript
test('scan on the express fixture prints a markdown report', async () => {
  const { stdout, code } = await run(['scan', fixture('express-vulnerable')])
  expect(code).toBe(0)
  expect(stdout).toContain('What this means')
})

test('scan --format sarif emits valid JSON with version 2.1.0', async () => {
  const { stdout } = await run(['scan', fixture('express-vulnerable'), '--format', 'sarif'])
  expect(JSON.parse(stdout).version).toBe('2.1.0')
})

test('scan refuses an out-of-scope target with a non-zero exit', async () => {
  const { code, stderr } = await run(['scan', '/etc'])
  expect(code).not.toBe(0)
  expect(stderr).toMatch(/scope|refus/i)
})

test('--fail-on high exits non-zero when a high finding exists', async () => { /* ... */ })
test('--fail-on high exits zero when only low findings exist', async () => { /* ... */ })

test('packs list prints every pack with its license and ingestion mode', async () => {
  const { stdout } = await run(['packs', 'list'])
  expect(stdout).toMatch(/ingestion mode|vendored|original/i)
})

test('packs audit exits non-zero when a registry file is malformed', async () => { /* against the one-bad-entry fixture */ })
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL

- [ ] **Step 3: Implement the commands**

`commander`. `scan` resolves the target, profiles it, builds the index, and reports — in Phase 1 there are no hunter agents, so findings come only from what callers record through the API; the command's job is the pipeline and the exit code. Exit codes: `0` clean or below threshold, `1` at or above `--fail-on`, `2` refusal or error.

- [ ] **Step 4: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(cli): add standalone sentinel scan and packs commands"
```

---

## Task 14: Init, attestation and consent record

**Files:**
- Create: `packages/cli/src/commands/init.ts`, `packages/core/src/consent/record.ts`
- Test: `packages/core/tests/consent/record.test.ts`, `packages/cli/tests/init.test.ts`

**Interfaces:**
- Consumes: `AUTHORIZATION.md` (Task 2).
- Produces: `readConsent(root: string): ConsentRecord | null`, `writeConsent(root: string, r: ConsentRecord): void`, `type ConsentRecord = { schema_version: 1; mode: 'full'|'pure-reasoning'; sentinel_version: string; attested_at: string; attestation_text_hash: string; tools?: ToolRecord[] }`, `type ToolRecord = { name: string; version: string; checksum: string }`

Phase 1 writes `mode: 'pure-reasoning'` only. Toolchain install is Phase 3; this task builds the record and the typed gate it will populate, so the consent model exists before anything depends on it.

- [ ] **Step 1: Write the failing tests**

```typescript
// record.test.ts
test('round-trips a consent record', () => { /* write then read equals */ })
test('returns null when no record exists', () => { expect(readConsent(emptyDir)).toBeNull() })
test('records the hash of the attestation text that was shown', () => {
  expect(writeThenRead().attestation_text_hash).toHaveLength(64)
})

// init.test.ts
test('typing anything other than the required word refuses and writes no record', async () => {
  const { code } = await run(['init'], { stdin: 'y\n' })   // 'y' is not 'yes'
  expect(code).not.toBe(0)
  expect(readConsent(cwd)).toBeNull()
})

test('typing the required word records pure-reasoning mode', async () => {
  await run(['init'], { stdin: 'yes\nno\n' })
  expect(readConsent(cwd)).toMatchObject({ mode: 'pure-reasoning' })
})

test('declining the toolchain prints the coverage warning', async () => {
  const { stdout } = await run(['init'], { stdin: 'yes\nno\n' })
  expect(stdout).toMatch(/dependency CVE/i)
})

test('re-running init when the attestation text has changed re-prompts', async () => { /* hash mismatch */ })
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: FAIL

- [ ] **Step 3: Implement `readConsent` / `writeConsent`**

`.sentinel/consent.json`. Store a sha256 of the attestation text actually displayed, so a changed `AUTHORIZATION.md` invalidates the old consent (spec §8.1).

- [ ] **Step 4: Implement `init`**

Display `AUTHORIZATION.md` verbatim, require the typed word `yes` — a bare keypress or `y` is a refusal, per spec §8. Then present the toolchain prompt; in Phase 1 only `no` is accepted and it prints the named coverage loss. Write the record.

- [ ] **Step 5: Run tests to verify they pass**

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(cli): add init with typed attestation and consent record"
```

---

## Task 15: Phase gate — end-to-end verification

**Files:**
- Create: `packages/cli/tests/e2e.test.ts`
- Create: `SELF-SCAN.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: everything.
- Produces: a green end-to-end path and the self-scan document the spec requires (§10).

- [ ] **Step 1: Write the failing end-to-end test**

```typescript
test('init then scan produces a report on a fixture target', async () => {
  await run(['init'], { stdin: 'yes\nno\n' })
  const { code, stdout } = await run(['scan', fixture('express-vulnerable')])
  expect(code).toBe(0)
  expect(stdout).toMatch(/not scanned|coverage/i)
  expect(stdout).toMatch(/pure-reasoning|dependency CVE/i)
})

test('scan works on Sentinel itself without crashing', async () => {
  expect((await run(['scan', repoRoot])).code).toBeLessThanOrEqual(1)
})
```

- [ ] **Step 2: Run test to verify it fails**

Expected: FAIL

- [ ] **Step 3: Fix whatever the end-to-end path reveals**

Integration gaps found here are real defects, not test problems. Fix the code.

- [ ] **Step 4: Write `SELF-SCAN.md`**

Current state of Sentinel scanned by Sentinel: date, commit, Sentinel version, mode, findings by band, and open items. Report honestly — a security tool claiming zero findings is its least believable claim (spec §10).

- [ ] **Step 5: Add the self-scan step to CI**

`sentinel scan . --fail-on high` runs on every pull request. In Phase 1 there are no hunter agents, so this gate asserts the pipeline runs clean; it becomes a real finding gate in Phase 2.

- [ ] **Step 6: Run the full suite**

Run: `pnpm lint && pnpm build && pnpm test && pnpm check:no-remote-install`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "test: add end-to-end phase gate and self-scan report"
```

---

## Non-code Phase 0 prerequisite

Spec §16 open question 1: secure the GitHub organisation, npm package scope `@sentinel`, and domain before Task 1 is announced publicly. Not testable, not blocking local work, but it gets harder every day it waits and it is the cheapest item in the whole plan.

## Done when

- `pnpm test` green; every task's tests present.
- `sentinel init` then `sentinel scan <path>` produces a markdown report and valid SARIF.
- `sentinel scan /etc` is refused with a non-zero exit.
- `registry/` holds two real packs, 12+ validated techniques covering L0–L2, and `AUDIT.md` classifies all eleven upstream sources with verified licenses.
- `NOTICE` attributes every vendored pack.
- `SELF-SCAN.md` exists and is honest.
- CI enforces lint, build, test, no-remote-install, index freshness, and registry validation.

## Deferred to later plans

Phase 2: hunter, verifier, chain, explainer and fixer agents; the Claude Code wrapper; fix queue; `plan_shards` budget model. Phase 3: `ingest-pack` normalizer skill, remaining nine packs, L3–L5, toolchain install. Phase 4: GitHub Action, SARIF upload, launch. Phase 5: Codex and Cursor manifests, loopback dynamic probing.
