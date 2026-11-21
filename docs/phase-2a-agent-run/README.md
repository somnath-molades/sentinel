# Phase 2a real-agent run — archived input

The two JSON files beside this one are the actual output of the Phase 2a real-agent
run recorded in `SELF-SCAN.md`, kept so the run is auditable rather than resting on
a narrative.

- `candidates.json` — what the hunter (`hunter-integration-1`) produced, in the shape
  `record_finding` takes. **The third entry is not the hunter's.** It is a deliberately
  false candidate injected by the harness onto the parameterized query at
  `src/server.js:28`, to test whether a real verifier discriminates. Its `reachability`
  field says so.
- `verdicts.json` — what the verifier (`verifier-integration-1`) returned, in the shape
  `verify_finding` takes, keyed to the candidates by index.

## Replaying it

These were produced by agents reading the fixture directly; they were not pushed
through the tools, because that needs an operator attestation (see `SELF-SCAN.md`,
"What this run did not exercise"). To run the tool leg yourself, from the repository
root, with your own attestation:

```
node packages/cli/dist/bin.js init tests/fixtures/targets/express-vulnerable
node scripts/hunt-integration.mjs run tests/fixtures/targets/express-vulnerable \
  --candidates docs/phase-2a-agent-run/candidates.json \
  --verdicts  docs/phase-2a-agent-run/verdicts.json
```

The `init` step is a statement about your own authorization and is deliberately not
automatable. The runner embeds no agent.

## Caveat on reuse

Line numbers here are tied to the fixture as of this phase. The fixture was edited
twice during Phase 2a, so if it changes again these files describe lines that have
moved. The runner locates the planted blocks by text search at runtime rather than
by these numbers, so it will still score correctly — but a candidate's `line` will
no longer match what the agent meant.
