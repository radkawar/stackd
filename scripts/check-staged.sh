#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mapfile -d '' changed < <(git diff --cached --name-only -z --no-renames --diff-filter=ACM -- '*.go')
if (( ${#changed[@]} == 0 )); then
    exit 0
fi

# Check only staged Go contents, including partially staged files.
# Never rewrite the working tree or silently stage formatting changes.
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/stackd-staged.XXXXXXXX")
trap 'rm -rf "$snapshot"' EXIT
git checkout-index --prefix="$snapshot/" -- "${changed[@]}"
cd "$snapshot"
unformatted=$(gofmt -l -- "${changed[@]}")
if [[ -n "$unformatted" ]]; then
    printf 'Staged Go files need formatting; run gofmt and stage them:\n%s\n' "$unformatted" >&2
    exit 1
fi
