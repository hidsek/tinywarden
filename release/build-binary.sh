#!/bin/zsh
# Build the firmware image for a release from a tag of this repository.
#
#   release/build-binary.sh v0.2.0
#
# Checks out the tag into a temporary directory, builds it with only sdkconfig.defaults (development
# options off), merges bootloader + partition table + app into one image for offset 0x0, scans the
# image's strings with tools/check-leaks.sh, and writes it with SHA-256 sums to
# $TW_ARTIFACT_DIR/<version>/ (default ~/tinywarden-artifacts). Uploading is left to a person.
set -euo pipefail
VERSION="${1:?usage: build-binary.sh <version>}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TW_ARTIFACT_DIR:-$HOME/tinywarden-artifacts}/$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$REPO" rev-parse -q --verify "refs/tags/$VERSION" >/dev/null || { echo "no tag $VERSION"; exit 1; }
git -C "$REPO" archive "$VERSION" | tar -x -C "$WORK"

. "${IDF_PATH:-$HOME/esp/esp-idf}/export.sh" >/dev/null 2>&1
cd "$WORK/firmware"
echo "${VERSION#v}" > version.txt   # shown on the status page and in the app descriptor
idf.py set-target esp32s3 >/dev/null
idf.py build >/dev/null
grep -q '^# CONFIG_TW_DEV_DOWNLOAD_ENDPOINT is not set' sdkconfig || { echo "dev option on"; exit 1; }
grep -q '^# CONFIG_TW_DEV_SKIP_BUTTON is not set' sdkconfig || { echo "dev option on"; exit 1; }
grep -q '^CONFIG_TINYUSB_NET_MODE_NCM=y' sdkconfig || { echo "not NCM"; exit 1; }

mkdir -p "$OUT"
IMG="$OUT/tinywarden-$VERSION-esp32s3.bin"
(cd build && python -m esptool --chip esp32s3 merge_bin -o "$IMG" @flash_args >/dev/null)

# Nothing private inside (keys, tokens, home paths, email addresses, and the personal list if present).
# mbedTLS carries the PEM header lines themselves (the "BEGIN ... KEY" markers) as literals for its
# parser; a line that is only such a header is not a key, so those lines are left out of the scan.
strings -n 5 "$IMG" | grep -E -v -x -e '-----(BEGIN|END) [A-Z ]*-----' \
  | (cd "$REPO" && tools/check-leaks.sh --stdin) || { rm -f "$IMG"; echo "binary NOT clean"; exit 1; }

(cd "$OUT" && shasum -a 256 "$(basename "$IMG")" > SHA256SUMS)
echo "built $IMG ($(stat -f %z "$IMG") bytes)"
cat "$OUT/SHA256SUMS"
