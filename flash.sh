#!/bin/zsh
# Build and flash, then start the app without pressing RST.
# The board must be in download mode first: hold BOOT, press and release RST, release BOOT.
# (Rebooting into download mode over the network, POST /tw/dev/download-mode, does not work yet:
#  the board ends up hung until RST. See docs/SPEC.md 8.)
#
#   ./flash.sh          flash the app (keeps the vault)
#   ./flash.sh --wipe   also erase the vault partition (needed when the storage format changes) and
#                       write a new one-time setup code, printed at the end
set -e
setopt nonomatch
cd "$(dirname "$0")/firmware"
. ~/esp/esp-idf/export.sh >/dev/null 2>&1
idf.py build >/dev/null
P="$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)"
if [[ -z "$P" ]]; then
  echo "Waiting for download mode (hold BOOT, press RST, release BOOT)..."
  for i in {1..120}; do P="$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)"; [[ -n "$P" ]] && break; sleep 0.5; done
fi
[[ -n "$P" ]] || { echo "no download port"; exit 1 }
CODE=""
if [[ "$1" == "--wipe" ]]; then
  # The vault and the setup partition (0x110000-0x3FFFFF), then a new one-time setup code
  python -m esptool --chip esp32s3 -p "$P" --after no_reset erase_region 0x110000 0x2F0000
  SETUP="$(mktemp)"
  CODE="$(python3 -I ../tools/setup_code.py "$SETUP")"
  python -m esptool --chip esp32s3 -p "$P" --before no_reset --after no_reset write_flash 0x3F0000 "$SETUP" >/dev/null
  rm -f "$SETUP"
fi
idf.py -p "$P" flash
python -m esptool --chip esp32s3 -p "$P" --before no_reset --after watchdog_reset chip_id >/dev/null 2>&1 || true
echo "flashed; app starting"
if [[ -n "$CODE" ]]; then
  echo
  echo "Setup code: $CODE"
  echo "(opens https://192.168.237.1/ until an account is created; keep it until then)"
fi
