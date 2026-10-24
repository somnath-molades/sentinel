# Project Sentinel — Design Specification

- **Date:** 2026-10-24
- **Status:** Approved design, pending implementation plan
- **License:** MIT
- **Repository:** public GitHub (org to be secured in Phase 0)

---

## 1. Purpose

Sentinel is a security guard for code you own. It installs as a plugin into an
LLM coding harness, fans out a large number of subagents across a codebase,
finds vulnerabilities from trivial to critical, explains each one in language a
non-specialist understands, selects a fix appropriate to the project's actual
stack and direction, and emits a prompt the host harness executes to apply that
fix.

Sentinel is not a scanner. A scanner reports patterns. Sentinel reasons about
reachability, compounding risk, and the specific product it is looking at, and
it refuses to report a finding it cannot defend.

### Who it is for

Developers and small teams shipping fast — often with AI assistance — who
produce working software faster than they can reason about its security. They
are not ethical hackers. They need to know what is wrong, why it matters for
their product, and what to do about it.

### Success criteria

1. A user installs Sentinel and gets a defensible, prioritised finding list on
   their own repository without configuring anything.
2. Every reported finding carries a `file:line` and a stated reason it is
   reachable. False-positive rate low enough that users trust the output.
3. Plain-language explanations are understandable by someone with no security
   background.
4. Adding a new upstream technique source is a single skill invocation, not a
   code change.
5. Sentinel's own CI scans Sentinel at full depth and blocks merges on its own
   findings.
6. Scope is enforced mechanically: Sentinel cannot be pointed at a target the
   user has not demonstrated access to.

### Non-goals for v1

- No execution or probing of the target application. Read-only analysis only.
- No remote or deployed-target testing.
- No hosted service, dashboard, or account system.
- No automatic code modification without explicit user action.

---

## 2. Constraints

| Constraint | Source |
|---|---|
| Harness-agnostic core; per-harness wrappers are thin | User decision |
| Architecture in the Superpowers shape: markdown skills, progressive disclosure, hard gates, subagent fan-out | User decision |
| Installable from GitHub, also installable inside Claude | User decision |
| Toolchain installs only on typed consent; refusal degrades to pure-reasoning mode with a warning | User decision |
| Targets: local path or a GitHub repository the user owns | User decision |
| Read-only in v1; dynamic probing deferred to Phase 5 | User decision |
| MIT licensed, fully open | User decision |
| Upstream technique sources are referenced through a registry, never merged into the codebase | User decision |
| Sentinel must be clean against itself | User decision |
| First-mover speed: public launch in roughly two weeks | User decision |

---

## 3. Architecture

### 3.1 Shape

One MCP server holds state and exposes tools. All domain knowledge lives in
versioned markdown. Each harness gets a thin wrapper that is mostly a manifest.

```
┌─────────────────────────────────────────────────┐
│  Harness wrappers (thin)                        │
│  Claude Code plugin · Codex AGENTS.md · Cursor  │
└────────────────────┬────────────────────────────┘
                     │ MCP
┌────────────────────▼────────────────────────────┐
│  sentinel-mcp                                   │
│  findings store · dedupe · router · budget      │
│  recon cache · reporter                         │
└────────────────────┬────────────────────────────┘
                     │ reads
┌────────────────────▼────────────────────────────┐
│  registry/  (markdown, versioned, contributable)│
│  packs → techniques → fix patterns              │
└─────────────────────────────────────────────────┘
```

MCP is the only interface all target harnesses already speak, so
harness-agnosticism costs one manifest per harness rather than a port. Keeping
knowledge in markdown means a contributor can add a vulnerability class by
opening a pull request against a text file.

### 3.2 Why not the alternatives

- **Standalone CLI with prompt wrappers** — portable and simple, but reduces the
  LLM to a formatter over a fixed pipeline, losing the per-codebase reasoning
  that distinguishes Sentinel from a scanner. Contributors would need to write
  code.
- **Pure skill pack, no server** — fastest to demo, but subagent contexts cannot
  see each other, so there is no shared findings store, no dedupe, no
  cross-file reasoning, and nothing to run in CI.

### 3.3 MCP tool surface

| Tool | Responsibility |
|---|---|
| `profile_target` | Build and cache `target-profile.json` |
| `select_techniques` | Route `(vuln_class, stack, depth_tier)` to ranked technique entries |
| `plan_shards` | Split work by domain and hotspot within a token budget |
| `record_finding` | Store a candidate finding, assign a fingerprint, dedupe |
| `verify_finding` | Record a verifier verdict against a candidate |
| `detect_chains` | Find compounding sets across confirmed findings |
| `explain_finding` | Render the two-voice explanation |
| `emit_fix_prompt` | Produce a harness-executable fix prompt |
| `report` | Emit SARIF, markdown, and the fix queue |
| `scan_self` | Run Sentinel against Sentinel |

---

## 4. Coverage model

**Depth** is how hard Sentinel must look. **Severity** is how much a finding
matters. The two are computed independently. All six depth tiers run on every
scan.

| Tier | Coverage |
|---|---|
| **L0 Surface** | Committed secrets, dependency CVEs, end-of-life runtimes, exposed `.env`, over-permissive CI token scopes, debug flags in production config, wildcard CORS, missing security headers |
| **L1 Pattern** | Injection sinks (SQL, NoSQL, command, template, LDAP), XSS, path traversal, SSRF, unsafe deserialization, weak crypto, insecure randomness, open redirect, XXE, ReDoS |
| **L2 Dataflow** | Taint propagation from source to sink across files and modules; reachability — whether the path is callable from a real entrypoint, and under which authentication state |
| **L3 Logic & authorization** | IDOR, missing object-level authorization, broken multi-tenancy including row-level-security misconfiguration, mass-assignment privilege escalation, TOCTOU on money or quota, missing idempotency, unverified webhook signatures, JWT algorithm confusion, password-reset token reuse |
| **L4 Architecture** | Trust-boundary violations, secrets reachable from the client bundle, absent service-to-service authentication, infrastructure-as-code exposing storage publicly, poisonable queues and workers, missing rate limits on authentication endpoints, no audit trail on privileged actions |
| **L5 Supply chain & agentic** | Lockfile integrity, typosquatted dependencies, `postinstall` scripts, GitHub Actions pinned by tag rather than SHA, `pull_request_target` misuse, prompt injection in LLM features, missing tool-call authorization in agentic code, exposed MCP servers |

### 4.1 Severity

```
severity = f(exploitability, reachability, blast_radius, data_sensitivity)
```

Depth tier does not imply severity. A credential committed three years ago and
since gitignored is L0 and critical. A theoretical ReDoS in a developer script
is L1 and informational.

### 4.2 Chain aggregation

A dedicated chain agent reads all confirmed findings and promotes compounding
sets into a single higher-severity finding with the chain made explicit.

Example: `verbose error messages` + `user enumeration on login` +
`no rate limit on authentication` is reported as one HIGH finding named
"credential stuffing path", showing all three links, rather than three LOW
findings a user scrolls past.

This is the mechanism behind the requirement that small issues which pile up
into bigger issues are surfaced as the bigger issue.

---

## 5. Technique registry

Upstream sources are **normalized into a registry Sentinel queries**, never
merged into Sentinel's code. This is what makes adding source number twelve an
afternoon rather than a refactor.

### 5.1 Capability pack

One directory per upstream source:

```
registry/packs/<pack-id>/
  pack.yaml          # name, source URL, license, upstream commit, coverage, trust tier
  techniques/*.md    # normalized technique entries
```

### 5.2 Technique entry schema

| Field | Notes |
|---|---|
| `id` | Stable, unique |
| `vuln_classes[]` | Mapped to CWE where one exists |
| `depth_tier` | L0–L5 |
| `stacks[]` | Languages, frameworks, platforms it applies to |
| `detection` | What to look for in source |
| `verification` | How to prove it is real, statically |
| `defensive_use` | **Mandatory.** What it proves, how to verify by reading code, what the fix is |
| `fix_patterns[]` | Keyed by stack |
| `references[]` | Upstream and standards citations |
| `provenance` | Pack identifier plus upstream commit |

`defensive_use` is where offensive techniques are re-pointed. A technique
without defensive framing fails ingest. This turns the project's legal boundary
from a README paragraph into a schema constraint.

### 5.3 License-aware ingestion

| Upstream license | Mode |
|---|---|
| Permissive (MIT, Apache-2.0, BSD) | Vendor content with attribution and `NOTICE`; pin upstream commit |
| Unstated — therefore all rights reserved | **Do not vendor.** Write an original entry covering the same technique, citing the repository as inspiration |
| Copyleft or otherwise restrictive | Keep out of tree; fetch on user request during install |

### 5.4 Initial sources

Audited in Phase 0 and sorted into the modes above. License status for every
entry below is currently **unverified** and must be confirmed before ingest.

1. Claude Cybersecurity — Agrici Daniel
2. VBsec — Tanviet12
3. OS skills — Agna
4. Coast Security (skill)
5. Agent Guard — Go Plus Security
6. Bug Hunter — Codex Star69
7. CC Safety Net — Kenryu42
8. Defending Code — Anthropic
9. Trail of Bits skills — Trail of Bits
10. Security audit — Cloudflare
11. Claude Red

### 5.5 Normalizer

`sentinel:ingest-pack` is itself a skill. Given a repository URL it reads the
source, proposes technique entries, flags the license, and presents them for
human review before commit. Adding sources twelve through forty is running this
skill, not writing code.

### 5.6 Router

`select_techniques(vuln_class, stack, depth_tier)` returns ranked entries from
`registry/index.json`, built from pack metadata.

v1 uses keyword, class, and stack filtering — deliberately not embeddings. No
infrastructure, deterministic results, debuggable, and a user can see exactly
why a technique fired. Embeddings become worthwhile around five hundred
techniques.

### 5.7 Surfaces

`sentinel packs list | add <url> | audit`, mirrored as harness slash commands.

---

## 6. Agent topology

```
sentinel:scan (orchestrator — plans and budgets, analyzes nothing)
  └─ recon ──────────────► target-profile.json (cached)
  └─ dispatcher ─────────► shards
       ├─ hunter × N      (per domain × hotspot, read-only)
       ├─ verifier × M    (adversarial, fresh context)
       ├─ chain agent
       ├─ explainer + fixer
       └─ reporter ──────► SARIF + markdown + fix queue
```

### 6.1 Roles

- **Orchestrator** plans and budgets. It performs no analysis itself.
- **Recon** runs once per target and is cached: languages, frameworks,
  entrypoints, routes, authentication middleware, data access layer,
  infrastructure-as-code, CI configuration, client/server boundary. Everything
  downstream reads this rather than re-deriving it, which accounts for most of
  the token saving in a scan.
- **Dispatcher** shards two ways: by domain (authorization, injection, secrets,
  dependencies, infrastructure-as-code, supply chain, crypto, LLM and agentic
  code) and by hotspot (files recon marked as trust boundaries). Fan-out width
  is driven by the token budget, so both a monorepo and a side project
  complete.
- **Hunters** receive only the technique entries the router selected for their
  domain. Each returns candidates with `file:line` and an explicit reachability
  claim.
- **Verifiers** run in fresh context and attempt to disprove each candidate.
  Survives → confirmed. Disproved → dropped. Ambiguous → `needs-review`, never
  reported as confirmed.
- **Chain agent** detects compounding sets per section 4.2.
- **Explainer and fixer** produce the two-voice output and the fix queue.
- **Reporter** emits SARIF, markdown, and the fix queue.

### 6.2 Verification as a hard gate

Hunters are optimistic by design; recall is their job. Verifiers are the
credibility layer. Running them in separate contexts is what prevents a hunter
from marking its own work. Nothing reaches a report as confirmed without
surviving verification.

### 6.3 Shared state

The findings store lives in the MCP server, with fingerprint-based dedupe,
because subagent contexts cannot observe each other. This is the primary reason
a server-less design was rejected.

---

## 7. Explain and fix layer

### 7.1 Two voices, one record

- **Plain** — what this is, what someone could do with it, what it means for
  this specific product, expressed in the product's own nouns.
- **Engineer** — CWE, OWASP category, severity vector, `file:line`, taint path,
  and the verifier's reasoning.

### 7.2 Fix selection

The fixer reads `target-profile.json` plus the product's direction — README,
roadmap, recent commit history — so the suggestion fits where the project is
going rather than being a generic snippet.

| Tier | Meaning |
|---|---|
| **Mechanical** | Pin an Action to a SHA, bump a dependency, add a header. Safe to batch-apply. |
| **Guided** | Requires one decision from the user, such as which authentication model or which tenant key. |
| **Design change** | Cannot be patched. Sentinel states this rather than fabricating a fix. |

### 7.3 Fix queue

Each queue item carries a harness-executable prompt. `sentinel fix <id>` hands
that prompt to the host harness. Sentinel never edits files without explicit
user action.

### 7.4 Closing a fix

A finding closes only when the verifier that originally confirmed it can no
longer confirm it. Re-verification is per-finding, not a full rescan.

---

## 8. Consent and install

`sentinel init` asks two questions. Both require typed input; neither accepts a
single keypress.

1. **Authorization attestation** — the user confirms the target is theirs or
   that they are authorized to assess it. Typed, timestamped, recorded.
2. **Toolchain consent** — the complete tool list is displayed with purpose,
   license, version, checksum, download size, and source. Typing `yes` installs
   them. Typing `no` prints a warning, and Sentinel runs in **pure-reasoning
   mode**: every report it produces then carries a banner naming the coverage
   given up, specifically dependency CVE detection and entropy-based secret
   scanning.

### 8.1 Consent record

`.sentinel/consent.json` stores mode, Sentinel version, and timestamp. The user
is re-prompted whenever the tool list changes.

### 8.2 Install hygiene

Tools are pinned by version **and** checksum and fetched from their own release
artifacts. Sentinel contains no `curl | bash` anywhere — it would flag that
pattern in someone else's repository.

---

## 9. Legal layer

### 9.1 Documents

`AUTHORIZATION.md`, `TERMS.md`, `ACCEPTABLE-USE.md`, `SECURITY.md`, `NOTICE`.

### 9.2 Attestation

Taken at `init` and re-taken for each new target.

### 9.3 Scope lock — enforced in code

v1 accepts a local filesystem path, or a GitHub repository the authenticated
`gh` user can access. Any other target is refused.

Mechanical enforcement, not a README promise. This is the project's strongest
legal position: misuse requires defeating the tool rather than ignoring a
disclaimer.

### 9.4 Payload policy

No weaponized proof-of-concept payloads in the repository. Technique entries
carry detection and fix guidance only.

### 9.5 Liability

MIT already disclaims warranty. Added on top: an explicit misuse-and-liability
clause stating the user is responsible for ensuring authorization and that the
project is not liable for unauthorized use, plus attribution for all vendored
upstream content.

**Legal review by a qualified lawyer is a launch blocker, not an optional
step.** The clauses in this specification are a drafting starting point and
have not been reviewed.

---

## 10. Self-scan loop

`sentinel scan --self` runs in Sentinel's own CI on every pull request at full
depth. Its findings block merge.

`SELF-SCAN.md` is published and kept current, including open items. A security
tool claiming zero findings is the least believable claim it could make, so the
document reports honestly.

This also serves as the project's primary credibility argument.

---

## 11. CI surface

- GitHub Action.
- SARIF uploaded to GitHub Code Scanning, so findings appear in the interface
  teams already use.
- Pull request comment listing confirmed findings and chains.
- Exit code driven by a user-configured severity threshold.

This is the mechanism by which Sentinel spreads from individual installs into
teams.

---

## 12. Repository layout

```
sentinel/
  packages/
    mcp/                  # sentinel-mcp server
    cli/                  # sentinel CLI (wraps the server)
  registry/
    packs/<pack-id>/
    index.json
    schema/technique.schema.json
  harnesses/
    claude-code/          # plugin: skills, agents, commands, hooks
    codex/                # AGENTS.md + MCP entry
    cursor/               # rules + MCP entry
  skills/                 # scan, ingest-pack, explain, fix, self-scan
  docs/
    superpowers/specs/
  .github/workflows/      # self-scan gate, release
  AUTHORIZATION.md  TERMS.md  ACCEPTABLE-USE.md  SECURITY.md  NOTICE  LICENSE
```

---

## 13. Phased pipeline

Approximately two weeks of focused work to public launch. Every phase ends in
something demonstrable.

| Phase | Days | Deliverable |
|---|---|---|
| **0 — Foundation** | 1–2 | License audit of all eleven sources, sorted into ingestion modes. Technique schema validated against two real packs. `target-profile.json` schema. Repository skeleton, MIT, legal drafts. Name secured: GitHub organisation, npm, domain. |
| **1 — Core** | 3–6 | `sentinel-mcp`: findings store, fingerprint dedupe, technique router, recon, reporter. Pure-reasoning mode. L0–L2 coverage. CLI works standalone. |
| **2 — First plugin** | 7–9 | Claude Code wrapper: skills, agents, slash commands. Hunter, verifier, and chain agents live. Explain and fix layer, fix queue. **First end-to-end demo on a live repository. Earliest installable build.** |
| **3 — Registry and depth** | 10–12 | All eleven packs ingested. L3–L5 coverage. Consent flow and toolchain install. Optional scanners wired as evidence sources. |
| **4 — Launch** | 13–14 | GitHub Action, SARIF, self-scan merge gate, documentation, `SELF-SCAN.md`, legal review closed. Public release. |
| **5 — Spread** | post-launch | Codex and Cursor manifests. Packs twelve and beyond. Loopback-only dynamic probing. |

### 13.1 Ordering rationale

The CLI works before any plugin exists, so harness-agnosticism is proven by
construction rather than asserted. The Claude Code wrapper comes first because
it is the richest host — if the topology works anywhere it works there, and the
thinner hosts cannot teach us anything the rich one will not.

---

## 14. Testing strategy

| Layer | Approach |
|---|---|
| Technique entries | Schema validation in CI; every entry must have non-empty `defensive_use`, `detection`, and at least one `fix_pattern` |
| Router | Fixture-based: given a class and stack, assert the expected techniques rank in the returned set |
| Findings store | Unit tests on fingerprinting and dedupe, including near-duplicate cases |
| Hunters and verifiers | A corpus of deliberately vulnerable fixture repositories per depth tier, with a known expected finding set. Measured on recall and false-positive rate. |
| Chain agent | Fixtures containing known chains; assert promotion occurs and the chain is reported |
| Scope lock | Negative tests: non-owned repository URLs and out-of-scope targets must be refused |
| Consent flow | Tests that refusal produces pure-reasoning mode and the report banner |
| Self-scan | Sentinel runs against Sentinel in CI; findings block merge |

The vulnerable-fixture corpus is the project's most important test asset. It is
what converts "we think the agents are good" into a measured recall and
false-positive number, and it must exist before Phase 3 adds depth.

---

## 15. Risks

| Risk | Mitigation |
|---|---|
| Token cost of wide fan-out makes scans too expensive to run | Budget model in the orchestrator is load-bearing; recon caching; router narrows technique context per hunter |
| False positives destroy credibility | Verifiers as a hard gate in fresh context; `needs-review` bucket; measured false-positive rate against the fixture corpus |
| Phase 3 slips — eleven upstream repositories with inconsistent structure | Normalizer skill validated against two real packs in Phase 0 before committing to the phase estimate |
| Upstream licensing exposure | Phase 0 audit; do-not-vendor default for unstated licenses; `NOTICE` and provenance on every entry |
| Reputational exposure from auto-installed toolchain | Typed consent with full disclosure; checksum pinning; pure-reasoning fallback always available |
| Offensive capability misuse | Mechanical scope lock; mandatory `defensive_use`; no payloads in repository; attestation per target |
| A competitor ships first | Phase ordering front-loads a demonstrable end-to-end scan at day nine |

---

## 16. Open questions

1. GitHub organisation, npm package name, and domain — not yet secured.
2. Which two upstream packs are used to validate the technique schema in
   Phase 0.
3. Token budget defaults per repository size tier.
4. Whether the Claude Code wrapper ships through the plugin directory, direct
   GitHub install, or both at launch.
