#!/bin/zsh
# Build the GitHub Pages site (web flasher) for a release into the gh-pages branch of this repository.
#
#   release/make-site.sh v0.2.0
#
# Needs the binary from release/build-binary.sh. The branch is recreated as a single orphan commit each
# time, so old binaries do not pile up in history. ESP Web Tools (pinned) loads from unpkg; the binary is
# served by Pages itself because GitHub release downloads have no CORS headers. Never pushes.
set -euo pipefail
VERSION="${1:?usage: make-site.sh <version>}"
V="${VERSION#v}"
REL="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$REL/.." && pwd)"
ART="${TW_ARTIFACT_DIR:-$HOME/tinywarden-artifacts}/$VERSION"
BIN="tinywarden-$VERSION-esp32s3.bin"
[[ -f "$ART/$BIN" ]] || { echo "build the binary first: release/build-binary.sh $VERSION"; exit 1; }
(cd "$ART" && shasum -a 256 -c SHA256SUMS >/dev/null) || { echo "checksum mismatch"; exit 1; }
SHA=$(cut -d' ' -f1 "$ART/SHA256SUMS")

WORK="$(mktemp -d)"
IDX="$(mktemp -d)/index"
trap 'rm -rf "$WORK" "$(dirname "$IDX")"' EXIT
cp "$ART/$BIN" "$WORK/"
sed -e "s/{{VERSION}}/$V/g" -e "s/{{SHA256}}/$SHA/g" -e "s/{{BIN}}/$BIN/g" "$REL/site/index.html" > "$WORK/index.html"
# manifest.json: for esptool users and as a fallback; the page builds its own with the setup code
cat > "$WORK/manifest.json" <<JSON
{
  "name": "tinywarden",
  "version": "$V",
  "new_install_prompt_erase": true,
  "builds": [
    { "chipFamily": "ESP32-S3", "parts": [ { "path": "$BIN", "offset": 0 } ] }
  ]
}
JSON
touch "$WORK/.nojekyll"
# Google Search Console ownership file (public by design: it holds only the token)
cp "$REL"/site/google*.html "$WORK/" 2>/dev/null || true

# Scan the page too
cat "$WORK/index.html" "$WORK/manifest.json" | (cd "$REPO" && tools/check-leaks.sh --stdin) || exit 1

GIT=(git -C "$REPO")
TREE=$(GIT_INDEX_FILE="$IDX" "${GIT[@]}" --work-tree="$WORK" add -A . && GIT_INDEX_FILE="$IDX" "${GIT[@]}" --work-tree="$WORK" write-tree)
COMMIT=$(echo "tinywarden $VERSION web flasher" | "${GIT[@]}" commit-tree "$TREE")
"${GIT[@]}" update-ref refs/heads/gh-pages "$COMMIT"
echo "gh-pages = $COMMIT ($("${GIT[@]}" ls-tree --name-only gh-pages | tr '\n' ' '))"
