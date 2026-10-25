# Project Sentinel — Phase 2a Design Specification

- **Date:** 2026-10-25
- **Status:** Approved design, pending implementation plan
- **Parent spec:** `docs/superpowers/specs/2026-10-24-project-sentinel-design.md` (binding authority)
- **Builds on:** Phase 1, merged as `54b6585`

---

## 1. Purpose

Phase 2a is the first time Sentinel finds a real vulnerability, with the verification gate observably working.

Phase 1 built the core, an MCP server and a CLI, and deliberately contained no detection: nothing in it can produce a finding. Phase 2a closes the blockers that stop a detection layer being built correctly, then proves the hunter-and-verifier topology on **one domain** before seven more are built on top of it.

### 1.1 Why a slice rather than the whole engine

The parent spec's §6 topology has never been exercised. Building all ten domains, the chain agent and the budget model before a single hunter has run would discover a topology flaw with ten domains already depending on it. Phase 1's lesson was that a correct implementation of an incomplete decomposition is the failure this process is weakest against; a vertical slice is the cheapest way to test a decomposition.

### 1.2 Success criteria

1. Sentinel reports a genuine finding on a target with a known planted vulnerability.
2. A verifier can disprove a false candidate, and that candidate never reaches a report as confirmed.
3. An agent attempting to confirm its own finding is refused.
4. The deterministic layer — assignment computation, store rules, domain filtering — is fully tested **without invoking a single agent**.
5. Every technique entry in the registry routes to exactly one domain assignment; an entry that routes nowhere fails the test suite.

### 1.3 Non-goals

Out of scope, each deferred to a named later phase:

- The chain agent and the `plan_shards` budget model — Phase 2b.
- The nine domains other than `injection` as *proven* paths. Their assignments are computed and dispatched (see §7.2), but only `injection` has an exercised hunter and verifier in this phase.
- The explain-and-fix layer and the fix queue — Phase 2c.
- The Claude Code plugin wrapper — Phase 2d.
- The MCP server's own worker-pool fan-out. Phase 2a uses host subagents only (§3.1).

---

## 2. Decisions

Recorded during design review, with the reasoning that produced them.

| Decision | Choice | Why |
|---|---|---|
| Who invokes hunters and verifiers | **Host subagents.** Sentinel ships skills plus its MCP tools; the harness's own agent primitive fans out | No API key, no inference cost borne by Sentinel, and "fresh context" is inherited rather than constructed. Cost: the standalone CLI cannot hunt until the worker pool exists |
| How a hunter selects techniques | **By domain**, a new required field on technique entries | This is what parent spec §6.1 specifies. It gives the dispatcher its sharding key and fixes the cross-cutting miss as a side effect, without inventing a taxonomy |
| Hunter/verifier separation | **Record the reporting agent's id; refuse a verdict from that id** | The threat is accident and drift — an orchestrator reusing an id, a refactor collapsing roles — not a subagent lying about its identity. Server-issued tokens defend against a threat this design does not have |
| Multi-verifier severity | **Highest band wins; disagreement recorded and reported** | The actionable number never under-states risk, and disagreement between verifiers is information about confidence that collapsing to one number would discard |
| Domain cardinality | **One required primary domain per entry** | Simplest model that works. Multiple domains revisited only on the evidence in §9.2 |
| Domain vocabulary size | **Ten values** | Eight could not house two shipped techniques (§4.2) |
| Where orchestration logic lives | **In core, behind a tool** — not in skill prose | Phase 1's whole-branch review found the coverage logic duplicated across two consumers with its texts already drifted after one phase. Prose is the least testable place to put logic that decides what gets examined |

---

## 3. Foundations

Four changes to core. The first three are recorded Phase 1 blockers; the fourth is required to make the tenth domain mean anything (§4.3).

### 3.1 Agent identity

`AddMeta` gains a required `reporting_agent: string`, and `Finding` gains `reporting_agents: string[]`. `Verdict` already carries `agent`.

**Corrected during implementation.** This section first said `FindingInput` gains the field and that a finding carries one reporting agent, singular. Both were wrong, and the plan's Task 6 carries the reasoning:

- The field belongs on `AddMeta`, not `FindingInput`, because `FindingInput` is the fingerprint's input. Agent identity there would make two hunters' identical findings fingerprint differently and stop collapsing — the opposite of what dedupe is for.
- A finding keeps a **set** of reporters, not one. Dedupe collapses two reports of the same defect into one finding, so recording only the first reporter would let the second verify its own finding and defeat the gate silently.

`recordVerdict` **refuses** when the verdict's agent appears in the finding's `reporting_agents`. Ids are canonicalised (NFKC, trimmed, lowercased) on both sides, so padding or case variation cannot evade the gate. The refusal uses the store's existing throw, because a self-confirmation is a contract violation by the orchestrator rather than bad data from a target.

`add` also refuses a reporter that already holds a verdict on that finding, closing the same hole from the other direction once reporters and verifiers share a pool.

The `record_finding` tool carries `reporting_agent` as a **call-level** parameter, mapped onto each finding's `AddMeta` by the handler: one agent submits one batch, and a batch carrying several reporters would mean one subagent claiming several identities.

This is what makes parent spec §6.2's separation claim observable. Today the claim holds only because the topology is expected to arrange it, and nothing can detect otherwise.

### 3.2 Severity in the store

`Finding.severity` becomes real state rather than a side map that the MCP server splices in at report time.

The store keeps every verifier's factor set with its agent id, derives the reported band from the **highest**, and sets `severity_disputed` when two verifiers differ. Both reporters show the spread on a disputed finding.

This deletes the parallel `Map` in the MCP server and retires Phase 1's de facto rule — "last verdict that supplied factors wins" — which was recorded at the time as arbitrary rather than designed.

### 3.3 Domain on technique entries

`domain` joins the technique schema: required, single-valued, validated against the vocabulary in §4.1.

The router gains domain filtering alongside its existing class and stack filters. Classes remain for precise queries; their exact-match behaviour is unchanged and is documented rather than altered (§7.3).

### 3.4 C and C++ must become reachable

Two changes, not one. The self-review of this spec caught the second.

1. The **walker's extension table** gains `.c`, `.cc`, `.cpp`, `.h` and `.hpp`, so those files are recognised as languages rather than counted as unexamined.
2. The **language-to-stack map** gains `c` and `cpp`. It currently holds only `javascript`, `typescript`, `python`, `go`, `php` and `java` — so even with the extensions recognised, no stack token would be derived and the result would be identical.

Without both, the tenth domain is decorative. The router selects on domain **and** stack; `unbounded-copy-into-fixed-buffer` declares stacks `c, cpp`; and a real C project would yield a selection of wildcard-only or none. A `memory-safety` hunter would be dispatched and handed nothing — a domain that exists, a technique that has a home, and no path by which it can ever fire.

The stack vocabulary itself already contains `c` and `cpp`, pinned in Phase 1, so no change is needed there.

This is Phase 1's deferred item I5, included here because the alternative is reproducing the silent-miss failure one level up.

---

## 4. The domain vocabulary

### 4.1 Ten values, one constant

`authorization`, `injection`, `secrets`, `dependencies`, `iac`, `supply-chain`, `crypto`, `agentic`, `memory-safety`, `configuration`.

**One constant in core, not two.** Hotspots emit a subset (the first eight) today; technique entries may use all ten. Two related lists are how Phase 1's coverage texts drifted apart within a single phase, so there is one list, and hotspots simply do not produce the newer two yet.

### 4.2 Why eight was not enough

The eight-value list was pinned in Phase 1 for marking hotspots — trust boundaries in a profile — not for covering the technique space. Two shipped entries had no home:

- `debug-mode-verbose-errors` is a configuration and information-disclosure flaw.
- `unbounded-copy-into-fixed-buffer` is memory safety.

Shoehorning either into an unrelated domain would mean no hunter is looking for it. Extending the vocabulary is the honest fix.

### 4.3 Primary domain for all thirteen entries

| Entry | Domain | Note |
|---|---|---|
| `sql-injection-built-query-string` | `injection` | |
| `command-injection-shell-interpolation` | `injection` | |
| `reflected-xss-unescaped-output` | `injection` | |
| `path-traversal-unvalidated-file-path` | `injection` | Input-validation family |
| `unsafe-deserialization-untrusted-payload` | `injection` | Untrusted input reaching execution |
| `cross-file-taint-source-to-sink` | `injection` | The L2 entry whose unreachability motivated domain routing |
| `hardcoded-secret-in-source` | `secrets` | |
| `vulnerable-dependency-version` | `dependencies` | |
| `permissive-cors-with-credentials` | `authorization` | An access-control flaw, not configuration |
| `entrypoint-reachability-under-auth-state` | `authorization` | |
| `over-permissive-agent-tool-allowlist` | `agentic` | **Arguable.** Also authorization. Chosen `agentic` because the failure is specific to agent tool configuration, and an authorization hunter reasoning about routes and middleware would not know what to do with it |
| `debug-mode-verbose-errors` | `configuration` | Required §4.2's extension |
| `unbounded-copy-into-fixed-buffer` | `memory-safety` | Required §4.2's extension and §3.4 |

`injection` holds six of thirteen. Lopsided, and expected: it is the best-covered class family in the registry today.

### 4.4 Validation behaviour

A missing or unknown `domain` **fails validation**. No default is assigned, silently or otherwise.

`buildIndex` reports the offending **entry id and file path**, and for an unknown value also reports the value found and the allowed set. The error is actionable without reading Sentinel's source — a contributor must be able to fix their entry from the message alone.

Rationale for required rather than optional: an entry with no domain would never appear in any domain assignment. It would sit in the registry, pass every other validation, and never fire, with no error anywhere. That is the silent-miss pattern this project exists to avoid, so the schema forces the choice at authoring time and CI catches it rather than a user never seeing a finding.

---

## 5. `plan_hunts`

A new MCP tool returning hunter assignments.

**Named `plan_hunts`, not `plan_shards`**, leaving the latter free for Phase 2b's budget model. The two may merge later; naming them apart now is cheaper than pre-building a budget model into the slice meant to test the topology.

### 5.1 Shape

The computation is a **pure function in core** over `(TargetProfile, RegistryIndex)`. The tool is a thin translation, consistent with the other five.

Each assignment carries:

| Field | Meaning |
|---|---|
| `domain` | one of the ten |
| `techniques` | the entries the router selected for that domain and the profile's stacks |
| `hotspot_paths` | paths recon flagged for this domain — **priority ordering, not a filter** (§7.1) |
| `coverage` | the router's signal: `exact`, `wildcard-only` or `none` |
| `reason` | present when `techniques` is empty, saying why |

An assignment does **not** carry the file list. The hunter's scope is the profile's walked file set, which the caller already holds — inlining it would duplicate every path ten times, once per domain, in a payload crossing the protocol boundary. Only `hotspot_paths` is carried, because it differs per domain.

### 5.2 Why it is in core rather than a skill

Shard computation in core is unit-testable and shared by every harness wrapper, so the later Cursor and Codex paths inherit it rather than re-deriving it. It also makes this phase's central claim checkable without running an agent: that an `injection` assignment contains the deep taint technique.

The skill shrinks to roughly *call this, dispatch what it returns, verify each candidate under a different agent id*.

---

## 6. The vertical slice

### 6.1 Domain: `injection`

Chosen because it carries six entries including `cross-file-taint-source-to-sink`, so the slice **exercises** the cross-cutting fix rather than asserting it; and because `express-vulnerable` already contains a planted concatenated SQL query, giving a known-answer target.

### 6.2 Flow

```
attest → scan → plan_hunts
       → harness dispatches one injection hunter
       → hunter records candidates (reporting_agent = its own id)
       → harness dispatches a verifier with a DIFFERENT id
       → verifier returns confirmed | disproved | ambiguous
       → report
```

### 6.3 Two skills, both thin

- **Hunter:** here are your techniques and files; return candidates with `file:line` and an explicit reachability claim.
- **Verifier:** try to disprove this candidate; `ambiguous` is a valid and expected answer, not a failure.

Judgment lives in the technique entries' `detection` and `verification` prose, which already exists and was reviewed in Phase 1. The skills carry the loop, not the security knowledge.

### 6.4 The fixture needs a negative control

Phase 1's review found `express-vulnerable` has none: every route lacks authorization, so an assertion that a route hotspot was flagged would pass against a fully-authorized application.

For a slice whose entire claim is "it found the real thing", that is disqualifying. The fixture gains a parameterized query alongside the concatenated one, and an authorized route alongside the unauthorized one. That is what makes *found it* distinguishable from *flags everything*.

---

## 7. Coverage limitations

Stated rather than discovered later. Each is a case where a technique could be applied to nothing.

### 7.1 Hotspots are hints, not filters

An assignment carries the **full walked file set**, with hotspot paths as priority ordering.

If hotspots filtered the paths, a hunter would only ever see trust-boundary files and would miss the same vulnerability class everywhere else in the repository. An earlier draft of this design made that mistake; it is recorded here so a later change does not reintroduce it as an optimisation.

### 7.2 All ten domains are dispatched every scan

A domain with no techniques or no matching stack appears as an **explicitly empty assignment with a reason**, never as an omitted key.

Gating dispatch on what the profile flagged would mean a domain the profile missed never runs at all, so a technique would be silently never applied. The cost is fan-out width on small projects, which is precisely what Phase 2b's budget model exists to bound. This phase accepts the cost and records it.

An empty assignment and a missing assignment must be distinguishable **by type**, not by convention (§8.2).

### 7.3 Class queries still do not reach cross-cutting techniques

Domain routing fixes the hunter's path. The router's **class** filter is unchanged: a `sql-injection` class query still does not return `cross-file-taint-source-to-sink`, because class matching remains exact and no taxonomy was invented.

This is documented and tested as known behaviour rather than hidden. Hunters select by domain, so the slice is unaffected; a caller querying by class must still ask for cross-cutting classes alongside concrete ones.

---

## 8. Testing strategy

The layer's core is non-deterministic. The strategy is to make the deterministic part large, and to measure the rest honestly rather than assert it.

### 8.1 Deterministic, in CI, no agents invoked

| Target | Assertion |
|---|---|
| `plan_hunts` as a pure function | assignment contents for a given profile and index |
| Domain filtering | an `injection` selection contains the L2 taint entry |
| Self-confirmation | same agent id recording then confirming is refused |
| Severity merge | highest band wins; differing verifiers set `disputed`; the spread survives into both reports |
| Stubbed agents | the full loop with canned candidates — proves the plumbing, claims nothing about judgment |
| C/C++ detection | a C fixture yields a `c` stack and a non-empty `memory-safety` assignment |

### 8.2 Regression tests

Each pins a failure this design is specifically shaped to prevent.

1. **Missing domain** — an entry without one fails validation; the error names the entry id and file path.
2. **Unknown domain** — fails the same way; the error names the offending value and the allowed set.
3. **Silently omitted entry** — every entry in the registry appears in exactly one domain assignment. An entry routing nowhere fails the suite rather than disappearing.
4. **Cross-domain technique** — an `injection` assignment contains the taint entry; a `sql-injection` *class* query does not (§7.3's documented behaviour).
5. **Empty versus missing assignment** — a domain with zero techniques appears with an empty list and a reason; asserting a missing key fails.

### 8.3 Non-deterministic, not in CI

One real-agent integration run against the planted fixture, invoked on demand, with its outcome — found, missed, false positives — recorded in `SELF-SCAN.md`.

Agent quality is **measured and published, never asserted by a passing test**. A green CI run will never mean the hunter is good, and the self-scan document is where that distinction is made legible.

---

## 9. Open questions and revisit triggers

### 9.1 Unresolved

- **`over-permissive-agent-tool-allowlist`'s domain.** Assigned `agentic`; genuinely arguable against `authorization`. Revisit if an authorization hunter turns out to be the one that finds this class in practice.

### 9.2 Revisit multiple domains per entry on evidence

The trigger: **a real finding missed because its technique's primary domain was not the one hunting.** If that happens twice, multiple domains earn their complexity.

The cost at that point is not only the schema: a technique in two domains fires in two hunters' assignments, so the same finding can be reported by two different agents, and dedupe must then collapse across reporters — which interacts with §3.1's agent identity.

### 9.3 Carried from Phase 1, still open

Not addressed here, and not blocking this phase: token-level fingerprinting before finding persistence exists; the `derivation` field on the pack schema; upstream do-not-report lists; `readlink`-based symlink classification; the scope lock's refusal of a symlinked project root; and the remaining entries in `docs/PHASE-1-DEFERRED.md`.

Phase 1's two merge blockers both came from that list rated Minor, having been sorted by how irritating each was to a developer rather than by what it was coupled to. **The list deserves re-triage against "what does this touch" before Phase 2b plans against it.**
