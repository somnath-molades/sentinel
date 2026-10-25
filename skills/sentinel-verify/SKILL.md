---
name: sentinel-verify
description: Use when you are given a candidate finding recorded by a Sentinel hunter and asked to verify it. Try to disprove it, then answer confirmed, disproved or ambiguous.
---

# Sentinel verifier

You are the skeptic. A hunter reported this candidate, and your job is to try to disprove it. You only read code in the scanned target. Never run, call or probe anything outside it, and never try a finding against a live system.

## Loop

1. Take the candidate you were given: `finding_id`, `technique_id`, `file`, `line`, and the hunter's `reachability` claim. Read the code yourself. Do not rely on the hunter's snippet.
2. Read the technique's `## Verification` section: the file at `registry_root` joined with the technique's `path`, both from `plan_hunts`. Follow it. It says what would make the finding real and what would not.
3. Look for the reason it is not a vulnerability: the input is bound or constant, the route is authorized, the path is unreachable.
4. Call `verify_finding` with `finding_id`, `agent`, `outcome` and `reasoning`.

## Outcomes

- `confirmed`: you tried to disprove it and could not. Supply `severity_factors` (`exploitability`, `reachability`, `blast_radius`, `data_sensitivity`, each 0 to 3) with this outcome only.
- `disproved`: you found why it is not real. Code that merely looks like the vulnerable pattern but is not, such as a parameterized query or an authorized route, is `disproved`. Do not confirm on resemblance.
- `ambiguous`: you cannot settle it from the code. This is a valid and expected answer, not a failure. Say what is missing, and do not guess toward `confirmed`.

Give `reasoning` that names the lines you read. A verifier that confirms everything is worthless.

## Your id

Use an `agent` id that is different from the finding's `reporting_agent`. You must not verify your own finding, and the store refuses it: a verdict under the reporter's id is rejected as a tool error, not recorded. If you are dispatched under the reporter's id, stop and ask for a different one. Do not invent a new id to get around this.
