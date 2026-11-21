---
id: unbounded-copy-into-fixed-buffer
vuln_classes: [memory-safety, buffer-overflow]
cwe: [CWE-787, CWE-120]
depth_tier: L1
domain: memory-safety
stacks: [c, cpp]
fix_patterns:
  - stack: c
    tier: mechanical
    guidance: Use the length-bounded copy variant with the destination's own capacity as the bound, computed from the destination rather than from the source, and check the result for truncation instead of ignoring it.
  - stack: c
    tier: guided
    guidance: Validate the attacker-supplied length against the destination capacity before the copy, and make the comparison in a type that cannot wrap — a signed-to-unsigned conversion turns a negative length into an enormous one.
  - stack: cpp
    tier: design-change
    guidance: Replace the fixed array and manual copy with a container that owns and grows its own storage, so the capacity check is structural rather than something each call site must remember.
references:
  - https://cwe.mitre.org/data/definitions/787.html
  - https://cwe.mitre.org/data/definitions/120.html
  - https://github.com/anthropics/defending-code-reference-harness
provenance:
  pack: defending-code
  upstream_commit: d3bea6b5793b5f3d59a75ebe69a58efa88383145
---

## Detection

Bytes are copied into a fixed-size stack or struct buffer with a length that comes from the input rather than from the destination's capacity. Shapes: a copy whose bound is the source length, a length field read from a parsed header and trusted, an index or offset arithmetic expression used without a range check, or a loop that terminates on a sentinel in attacker-controlled data.

Named sinks to search for:

- unbounded by construction, with no length parameter at all: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf` and `sscanf` with a bare `%s` conversion
- bounded by a parameter that is often the wrong value: `memcpy`, `memmove`, `strncpy`, `strncat`, `snprintf`, `bcopy`, `CopyMemory` — the finding is a length argument derived from the source or from parsed input rather than from `sizeof(dst)`
- allocation and indexing: `alloca` and a variable-length array with an untrusted size, `malloc` or `realloc` with a size expression that can wrap, and a pointer or array index computed from input without a range check
- C++ specifically: `std::vector::operator[]` and `std::array::operator[]` with an unchecked index (`at()` is the checked form), `std::memcpy` into `data()`, `reinterpret_cast` of a buffer to a struct pointer without a length check, and `std::string::copy` with a caller-supplied count

The arithmetic patterns that make a present bound check insufficient: `len + header_size` where the sum can wrap; a length held in a signed type and compared against an unsigned capacity; a difference of two pointers or offsets that can go negative; and a multiplication of a count by an element size with no overflow check.

## Verification

Read the destination's declared size and the expression used as the copy bound, and decide whether the bound is derived from the destination or from the input. Check the arithmetic for wrapping: a length plus a header size can overflow to a small value that passes a comparison, and a signed length compared against an unsigned capacity promotes in a way that admits negative values. Confirm the parsed length is not validated against the actual remaining input size earlier in the function, which is the common case where the construct turns out to be safe.

## Defensive use

Proves that input can write past the end of a buffer, which in this class means corrupting adjacent stack or heap state — return addresses, function pointers, allocator metadata — and so is a candidate for attacker-directed execution rather than only a crash. Verify it statically by comparing the declared destination capacity against the expression bounding the copy, checking the length arithmetic for wrapping and signedness errors, and confirming no earlier bound check constrains the parsed length. The fix is a length-bounded copy using the destination's own capacity with the truncation result checked; structurally, a self-sizing container so no call site carries the capacity by hand.
