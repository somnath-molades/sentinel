#!/bin/sh
# Fail if any file pipes a network fetch into a shell or interpreter.
#   (no args)  scan the repo; exit 1 on a hit, 2 on any error (fails closed)
#   --stdin    apply the same pattern to stdin; exit 1 on a hit, 0 if clean (used by the test)
# docs/ and .superpowers/ discuss the pattern in prose, so they are excluded; so are this script and its test (which holds known-bad samples).
# Backslash line continuations are joined before matching, so a split command is still caught.
# shortcut: heuristic regex; obfuscation (variables, base64, `curl -o f; sh f`) is not caught, upgrade to a real shell parser if needed.

# Byte-wise matching: the pattern is ASCII, and a non-UTF-8 file (e.g. a hostile test fixture) must not abort sed/grep as "illegal byte sequence".
LC_ALL=C
export LC_ALL

FETCH='(curl|wget)'
INTERP='(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|perl|ruby)'
WRAP='((sudo|env|exec|nohup|command)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*)*'
PATTERN="${FETCH}.*\\|[[:space:]]*${WRAP}([^[:space:]|]*/)?${INTERP}([^[:alnum:]_.-]|\$)"
PATTERN="${PATTERN}|<\\([[:space:]]*${FETCH}"
PATTERN="${PATTERN}|(-c|eval)[[:space:]]+[\"']?(\\\$\\(|\`)[[:space:]]*${FETCH}"

# stdin -> joined lines -> grep. Exit 0 = hit, 1 = clean, 2 = error (grep's own convention).
matches() {
  sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' | grep -E -e "$PATTERN"
}

if [ "$1" = "--stdin" ]; then
  matches >/dev/null
  case $? in
    0) exit 1 ;;
    1) exit 0 ;;
    *) echo "ERROR: pattern match failed" >&2; exit 2 ;;
  esac
fi

files=$(git ls-files --cached --others --exclude-standard -- . ':(exclude)docs' ':(exclude).superpowers' ':(exclude)scripts/check-no-remote-install.sh' ':(exclude)scripts/check-no-remote-install.test.ts') || {
  echo "ERROR: could not list files (git ls-files failed)" >&2
  exit 2
}

found=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  out=$(matches < "$f")
  case $? in
    0) printf '%s: %s\n' "$f" "$out"; found=1 ;;
    1) ;;
    *) echo "ERROR: could not scan $f" >&2; exit 2 ;;
  esac
done <<EOF
$files
EOF

if [ "$found" -ne 0 ]; then
  echo "ERROR: remote fetch piped into a shell/interpreter found" >&2
  exit 1
fi
