---
id: path-traversal-unvalidated-file-path
vuln_classes: [path-traversal]
cwe: [CWE-22]
depth_tier: L1
stacks: [node, python, php, go]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: >-
      Resolve the joined path to its canonical absolute form and reject it unless it is
      inside the intended base directory. Compare resolved paths, not the strings that
      produced them, and compare on a path boundary rather than by string prefix — a
      prefix test admits /base-evil when the base is /base, which is the classic bypass
      of this fix. The reliable form is to compute the candidate's path relative to the
      base and accept it only if that relative path is not absolute, is not "..", and
      does not begin with ".." followed by the path separator; the empty relative path,
      meaning the base itself, is inside. Appending a trailing separator to the base
      before a prefix comparison is an equivalent fix. Apply the check after resolution,
      and reject rather than silently clamping the path into the base directory.
  - stack: generic
    tier: guided
    guidance: Prefer not accepting paths at all — take an opaque identifier and look up the real filename in a database or fixed map, so the caller never names a path.
  - stack: node
    tier: guided
    guidance: Normalize before validating, and treat the decoded form as the input — a check applied before URL decoding can be bypassed by encoding the traversal sequence.
references:
  - https://cwe.mitre.org/data/definitions/22.html
  - https://owasp.org/www-community/attacks/Path_Traversal
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A request-supplied value is joined onto a directory and used to open, read, write, serve or delete a file. The join is usually unremarkable path concatenation; the problem is that the caller's segment can climb out of the base directory with parent-directory references, or escape it entirely by being an absolute path, which most join functions honour by discarding the base.

Named sinks to search for, with a request-derived segment in the path argument:

- node: `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `fs.writeFile`, `fs.unlink`, `fs.rm`, `res.sendFile`, `res.download`, `express.static` given a computed root, and `path.join` or `path.resolve` whose result feeds any of these
- python: `open`, `pathlib.Path` division or `joinpath`, `os.path.join`, `shutil.copy` and `move`, `os.remove`, `send_file` and `send_from_directory` in Flask, `FileResponse` in Django, and `tarfile.extractall` or `zipfile.extractall`, where the traversal comes from entry names inside the archive
- php: `file_get_contents`, `file_put_contents`, `fopen`, `readfile`, `unlink`, `include`, `require`, and `move_uploaded_file`
- go: `os.Open`, `os.ReadFile`, `os.WriteFile`, `os.Remove`, `http.ServeFile`, and `filepath.Join` feeding any of these

Note that archive extraction is the same finding reached a different way: the untrusted segment is an entry name in the archive rather than a request parameter, and `extractall`-style helpers write wherever the entry says unless each name is checked.

## Verification

Read the order of operations. Validation that happens before normalization and decoding can be defeated, so confirm the check applies to the final resolved path. Confirm the check compares canonical absolute paths against the base directory rather than searching the input for suspicious substrings — and then confirm the comparison is on a path boundary, because a containment check written as a bare string prefix test is itself the finding: with a base of `/base` it accepts `/base-evil`. Then establish what the sink does — read, write or delete — since that sets the impact, and whether symlinks inside the base directory could redirect a path that passes the check.

## Defensive use

Proves that a caller can name files outside the directory the endpoint was meant to expose: on a read sink, retrieving application source, configuration and credential files; on a write or delete sink, altering files the application has permission to change. Verify it statically by confirming the untrusted segment reaches a filesystem call and that no canonical-path containment check is applied after normalization and decoding. The fix is to resolve the path and reject anything outside the base directory; better, accept an opaque identifier and resolve it to a filename yourself so no caller-supplied path reaches the filesystem.
