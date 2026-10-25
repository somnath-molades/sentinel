---
id: unsafe-deserialization-untrusted-payload
vuln_classes: [unsafe-deserialization]
cwe: [CWE-502]
depth_tier: L1
stacks: [python, php, node, java]
fix_patterns:
  - stack: python
    tier: mechanical
    guidance: Replace the object-reconstructing loader with a data-only format — JSON, or the safe YAML loader that builds plain scalars, lists and mappings and will not instantiate arbitrary types.
  - stack: php
    tier: guided
    guidance: Carry the data as JSON rather than a serialized object graph. Where a serialized payload cannot be removed, restrict permitted classes explicitly rather than allowing any class the autoloader can reach.
  - stack: generic
    tier: design-change
    guidance: If the payload must round-trip through an untrusted party, authenticate it with a server-held key and verify before parsing, so an unauthenticated payload never reaches the parser at all.
references:
  - https://cwe.mitre.org/data/definitions/502.html
  - https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A payload that arrived from outside — a request body, a cookie, a cache or queue entry, an uploaded file — is handed to a deserializer that reconstructs objects rather than parsing plain data. The distinction is the capability of the parser, not the format: loaders that can instantiate classes named in the payload, invoke constructors or run reducer hooks are in scope, while a JSON parser producing plain values is not.

Named loaders to search for:

- python: `pickle.load`, `pickle.loads`, `cPickle.loads`, `dill.loads`, `shelve.open`, `yaml.load` **without** a safe loader argument, `yaml.unsafe_load`, `yaml.full_load`, `jsonpickle.decode`, `torch.load` with weights-only loading disabled, and `numpy.load` with pickle allowed
- php: `unserialize` on request-derived input, and Laravel's `decrypt`/`unserialize` combination on a cookie payload
- node: `node-serialize`'s `unserialize`, `serialize-javascript` output passed back through an evaluator, `js-yaml`'s `load` on versions where it defaulted to the unsafe schema, and any custom reviver that constructs classes by a name taken from the payload
- java: `ObjectInputStream.readObject`, `XMLDecoder.readObject`, and `XStream.fromXML` without a type allowlist

The paired safe forms: `json.loads` and `JSON.parse`, `yaml.safe_load` or `yaml.load(data, Loader=yaml.SafeLoader)`, `js-yaml`'s default safe schema on current versions, `torch.load` with weights-only loading enabled, and any of the above constrained by an explicit permitted-class list.

## Verification

Identify which loader variant is called, since libraries commonly ship both a safe and an object-reconstructing entry point and the names differ by very little. Trace the payload to its origin and check whether anything authenticates it before parsing — a signature verified with a server-held key removes the untrusted property, while base64 encoding or compression does not. If the loader accepts a class allowlist, check whether one is supplied and whether it is actually restrictive.

## Defensive use

Proves that an attacker who controls the payload controls which objects the process constructs during parsing, which on these platforms is a well-trodden route to running attacker-chosen code inside the application — before any of the application's own validation runs, because it happens during parse. Verify it statically by naming the exact loader function, confirming it reconstructs objects, and confirming the payload reaches it from an untrusted origin with no prior signature verification. The fix is a data-only parser; where an object payload is unavoidable, verify a server-side signature before parsing and restrict permitted classes explicitly.
