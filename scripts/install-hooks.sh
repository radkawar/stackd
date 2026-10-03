#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
previous=$(git config --get core.hooksPath || true)
if [[ "$previous" != .githooks ]]; then
    if [[ -n "$previous" ]]; then
        git config --local stackd.previousHooksPath "$previous"
    fi
    git config --local core.hooksPath .githooks
fi
printf 'Installed repository hooks: staged Go formatting; pushed-package vet/staticcheck. Full gate: make check.\n'
