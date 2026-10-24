#!/bin/sh
# Fail if any tracked or untracked file pipes a network fetch into a shell.
# docs/ discusses the pattern in prose, so it is excluded; so is this script.
if git grep -nEI --untracked -e '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([^[:alnum:]_]|$)' -- . ':!docs' ':!scripts/check-no-remote-install.sh' ':!.superpowers'; then
  echo "ERROR: remote fetch piped into a shell found" >&2
  exit 1
fi
