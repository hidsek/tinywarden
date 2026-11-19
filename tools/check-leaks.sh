#!/usr/bin/env bash
# Look for things that must not be committed or published.
#
#   tools/check-leaks.sh             every tracked file
#   tools/check-leaks.sh --staged    what is about to be committed (the pre-commit hook uses this)
#   tools/check-leaks.sh --stdin     text on standard input (for example `strings firmware.bin`)
#
# Always: private keys, tokens, absolute paths of a home directory, and email addresses other than
# the placeholders used in tests and docs. Also, if it exists, a personal list of extended regular
# expressions, one per line ('#' starts a comment): $TW_DENYLIST, default ~/.config/tinywarden/denylist.txt.
# That list holds the maintainer's own name and the like, so it is never part of the repository.
# Exit status 1 when something is found.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

GENERIC=(
  '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----'
  'gh[pousr]_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{30,}'
  'AKIA[0-9A-Z]{16}'
  'sk-[A-Za-z0-9]{32,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  '/(Users|home)/[A-Za-z][A-Za-z0-9._-]+/'
)
# Email addresses, except these
EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
EMAIL_OK='@(example\.(com|org|net|invalid)|users\.noreply\.github\.com|anthropic\.com)$|^git@github\.com$'

PERSONAL="${TW_DENYLIST:-$HOME/.config/tinywarden/denylist.txt}"
patterns=("${GENERIC[@]}")
if [[ -f "$PERSONAL" ]]; then
  while IFS= read -r p; do
    [[ -z "$p" || "$p" == \#* ]] && continue
    patterns+=("$p")
  done < "$PERSONAL"
fi

# This file names the patterns, so it is not scanned itself
SELF="tools/check-leaks.sh"
fail=0
report() { echo "leak check: $1"; fail=1; }

scan_text() {  # $1 = label, text on stdin
  local label="$1" text
  text="$(cat)"
  for p in "${patterns[@]}"; do
    if grep -E -i -q -e "$p" <<<"$text"; then report "$label matches: $p"; fi
  done
  while IFS= read -r addr; do
    [[ -z "$addr" ]] && continue
    grep -E -i -q "$EMAIL_OK" <<<"$addr" || report "$label has an email address: $addr"
  done < <(grep -E -o -e "$EMAIL" <<<"$text" | sort -u)
}

case "${1:-}" in
  --stdin)
    scan_text "input" ;;
  --staged)
    while IFS= read -r -d '' f; do
      [[ "$f" == "$SELF" ]] && continue
      git show ":$f" | LC_ALL=C grep -Iq . 2>/dev/null || continue  # skip binary files
      git show ":$f" | scan_text "$f"
    done < <(git diff --cached --name-only --diff-filter=ACMR -z) ;;
  "")
    while IFS= read -r -d '' f; do
      [[ "$f" == "$SELF" || ! -f "$f" ]] && continue
      LC_ALL=C grep -Iq . "$f" 2>/dev/null || continue
      scan_text "$f" < "$f"
    done < <(git ls-files -z) ;;
  *)
    echo "usage: $0 [--staged | --stdin]"; exit 2 ;;
esac

if (( fail )); then
  echo "leak check: FAILED"
  exit 1
fi
[[ -f "$PERSONAL" ]] || echo "leak check: ok (generic patterns only; no personal list at $PERSONAL)"
