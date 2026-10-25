---
id: cross-file-taint-source-to-sink
vuln_classes: [taint-flow, injection]
cwe: [CWE-20, CWE-74]
depth_tier: L2
stacks: [node, python, go, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Apply the context-appropriate escaping or binding at the sink, which is the only place that knows what the value is about to become. A sanitizer at the source cannot know whether the value will end up in SQL, a shell command or markup.
  - stack: generic
    tier: guided
    guidance: Validate and narrow the value at the trust boundary where it enters, converting it to a type that can no longer carry the dangerous form — an integer, an enumeration member, an identifier looked up in a fixed map — so the rest of the chain handles a safe type.
  - stack: generic
    tier: design-change
    guidance: Where one tainted value reaches several sinks through shared helpers, give the value a distinct type at the boundary and require an explicit conversion to use it in a sink. The compiler or type checker then enforces what review currently has to.
references:
  - https://cwe.mitre.org/data/definitions/20.html
  - https://cwe.mitre.org/data/definitions/74.html
  - https://github.com/anthropics/defending-code-reference-harness
provenance:
  pack: defending-code
  upstream_commit: d3bea6b5793b5f3d59a75ebe69a58efa88383145
---

## Detection

An untrusted value enters at one file and reaches a dangerous sink in another, with no single file showing both ends. The chain typically runs through a request handler, a service or helper module, and then a data-access, filesystem, template or process-launching call. Neither end looks wrong alone: the handler merely passes a parameter onward, and the sink merely uses the argument it was given. Only the composition is the finding, so this requires following call edges across module boundaries rather than matching a pattern in one file.

## Verification

Build the chain explicitly and record each hop as a file and function, so the claim can be rechecked: source, every intermediate function and the parameter it carries the value in, and the sink. At each hop, look for something that removes the taint — validation that narrows the value, a type conversion, an escape or binding call — and if you find one, the chain ends there and there is no finding. Watch for taint being laundered through storage: a value written to a database or cache and read back later is still untrusted, and the read looks like an internal source. Where the chain passes through dynamic dispatch, an interface, a callback or a framework-registered hook, the static edge may be unresolvable; say which hop is unresolved rather than assuming the chain completes.

## Defensive use

Proves that the application's trust boundary is not where its author believes it is: input validated nowhere, or validated for the wrong context, travels from an entry point to a sink that acts on its structure, and the review that would catch it has to span files that no single diff shows together. Verify it statically by writing out the file-and-function chain hop by hop, checking each hop for a taint-removing operation, treating values read back from storage as still untrusted, and naming any hop whose call edge cannot be resolved. The fix is to escape or bind at the sink, which is the only point that knows the target context, and to narrow the value to a safe type at the boundary so later hops cannot reintroduce the problem.
