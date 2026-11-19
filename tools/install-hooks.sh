#!/usr/bin/env bash
# Use the hooks in .githooks/ for this clone (pre-commit: leak check and author check).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "hooks enabled: $(git config core.hooksPath)"
