# tinywarden

English | [日本語](README.ja.md)

**Vaults get attacked where they pile up.**

When a cloud gets breached, your vault leaves with everyone else's. So keep it on your desk. tinywarden keeps your vault on a small USB device: out of reach from the internet, and a new device logs in only when you press its button. Kept on your desk, it doesn't need a passkey to guard it. It works with the official Bitwarden apps, site passkeys included.

Local is not a cure-all. If a device you log in on is compromised, nothing here helps, and a stolen board gives away its ciphertext to be attacked offline. A strong master password (with Argon2id) and safe devices are what protect the vault.

A tiny, unofficial Bitwarden-compatible server that lives on an ESP32-S3 board plugged in by USB. No cloud, no home server, no network: the vault stays on the board, and the official Bitwarden browser extension and mobile apps talk to it over a USB network link.

> **Unofficial and experimental.** tinywarden is a hobby project. It is not affiliated with, endorsed by or supported by Bitwarden, Inc. It has not been audited. Read [Security model](#security-model) before you put anything real on it, and always keep a backup elsewhere.

**Version 0.2.0: it works well on my desk, so I am sharing it.** It runs every day on my own devices (listed below), but that is one person's setup. Try it on yours, tell me what works and what doesn't, break it, improve it. Having fun with it together is the point. See [CONTRIBUTING.md](CONTRIBUTING.md).

## How it works

- The board shows up as a USB network adapter (CDC-NCM). It is `192.168.237.1`, the computer or phone gets `192.168.237.2` by DHCP. No gateway or DNS is handed out, so the host's internet keeps working.
- It serves the subset of the Bitwarden API that the official clients use, over HTTPS, with a certificate made on the board at first boot.
- Encryption happens in the official clients, exactly as with Bitwarden. The board only ever stores ciphertext, and on top of that seals every record it stores (AES-256-GCM, with a key that is in RAM only after a login). It never stores the username.
- Creating an account and logging in with the master password need a press of the board's BOOT button (the board's LED lights up while it waits, 30 seconds).
- The vault is kept in a small log-structured store on the flash, tested against simulated power cuts at random bytes.

## What I cared about

Security and ease of use together: one vault, on hardware you hold, that every device you own reaches the same way.

- **The same vault on every device.** Mac, Windows, iPhone and Android all use the same board, with the same server URL and the same official apps; plug it in, log in once, done. How it feels to use is up to Bitwarden's apps, and which devices it reaches depends on them and on the device bringing up USB networking (see [Works with](#works-with-checked-on-2026-11-19)).
- **The official apps, as they are.** No forked client, no browser add-on of its own: the Bitwarden extension and mobile apps from the stores just point at the board.
- **A physical step.** Creating the account, logging in, saving a backup, changing the KDF and wiping all wait for a press of the board's BOOT button. Ten wrong master passwords erase the vault.
- **The board never sees your secrets.** It stores only ciphertext. The master password and the vault key never reach it: the status page and the merge page do their crypto in the browser.
- **A stolen board gives away little.** The username (email) is not stored, so a thief who reads the flash has to guess the username and the master password together. Everything else is sealed: not even the number, type or dates of items can be read.
- **Quiet about what it is.** The status page is always locked. Before unlocking it shows device information only, so someone who plugs the board in cannot tell what it is.
- **It survives power cuts.** The vault is a small log-structured store, tested against simulated power cuts at random bytes.
- **Argon2id, even without a web vault.** The apps always create accounts with PBKDF2 and can change it only from Bitwarden's web vault, which does not fit on the board, so the status page does it.
- **Your data stays reachable.** Backups from the status page, a merge page that compares two vaults and writes normal Bitwarden exports, and restore into any Bitwarden or Vaultwarden account. If an app update ever breaks tinywarden, you are not locked in.
- **It stays out of the way.** No gateway or DNS is handed out, so the computer's internet keeps working; the apps keep working without the board once logged in.
- **Honest about the limits.** What it does not protect against is written down in [Security model](#security-model).

## Works with (checked on 2026-11-19)

| Device | Client | Notes |
|---|---|---|
| macOS | Browser extension (Chrome, Brave) | |
| Windows 11 | Browser extension (Chrome, Edge) | The USB driver binds automatically. Trust the certificate with `certutil -addstore -user Root` (double-click install did not work) |
| iPhone 17 (USB-C) | Bitwarden iOS app | Turn the certificate on under Settings > General > About > Certificate Trust Settings |
| moto g24 (Android 14) | Bitwarden Android app | Turn Wi-Fi and mobile data off while talking to the board: Android sends app traffic only to its main network |
| Chromebook | Browser extension (Chrome) | Chrome may block the certificate download (it comes over plain HTTP): keep it from the download list (Ctrl+J). Import it at `chrome://certificate-manager` |
| Redmi 2201117TL (Android 13) | — | Did not work: the phone never brought the USB network up |

Windows 10 has no inbox CDC-NCM driver and is untested. Firefox is not supported yet.

Setup steps for each device: [docs/SETUP.en.md](docs/SETUP.en.md). Everyday use and backups: [docs/MANUAL.en.md](docs/MANUAL.en.md).

## Passkeys

Bitwarden stores passkeys inside vault items, and tinywarden stores items as they come, so passkeys sync like everything else. Logging in with a passkey from an imported vault and registering a new passkey both work; using a newly registered passkey on another device after a sync has not been tried yet.

## Hardware

An ESP32-S3 board with native USB, 4 MB flash and 2 MB PSRAM. Developed on an "ESP32-S3 SuperMini" (ESP32-S3FH4R2). The LED on GPIO48 and the BOOT button on GPIO0 are used (on the development board GPIO48 is a plain LED that shows red; boards with a WS2812 RGB LED there can choose it in `idf.py menuconfig`, tinywarden > LED on GPIO48). On that board the "BAT" LED belongs to the charger and cannot be turned off from firmware.

## Flash a prebuilt binary

**From the browser:** https://hidsek.github.io/tinywarden/ (Chrome or Edge on a computer). Put the board in download mode and press the button. Tick "Erase device" only on a first install. The page shows a one-time **setup code** and writes its hash to the board: until an account exists, it opens the status page. Note it down before flashing.

**With esptool:** Each GitHub release has `tinywarden-<version>-esp32s3.bin` (bootloader, partition table and app merged for offset `0x0`) and `SHA256SUMS`. Check the hash, put the board in download mode (hold BOOT, press and release RST, release BOOT), then:

```sh
pip install esptool
esptool.py --chip esp32s3 erase_flash                                   # first install only: erases everything, including any vault
esptool.py --chip esp32s3 write_flash 0x0 tinywarden-<version>-esp32s3.bin
python3 -I tools/setup_code.py setup.bin                                # prints a setup code (optional, see below)
esptool.py --chip esp32s3 write_flash 0x3F0000 setup.bin
```

The setup code only opens the status page before an account exists. Without it, just create the account first and unlock the status page with the account.

Press RST to start it. Or use Espressif's browser flasher (https://espressif.github.io/esptool-js/, Chrome or Edge) with the same file at address `0x0`.

To update a board that already holds a vault, skip `erase_flash`: writing the image leaves the vault and the certificate alone. Take a backup first anyway. **Coming from v0.2:** v0.3 stores the vault differently and cannot open a v0.2 vault; export first, erase, and import (see [docs/MANUAL.en.md](docs/MANUAL.en.md), "Moving from v0.2 to v0.3").

The binary is built from the tagged source with only `firmware/sdkconfig.defaults` (development options off). Each board makes its own certificate and keys at first boot; nothing secret is in the image.

## Build and flash (ESP-IDF 5.5)

```sh
cd firmware
idf.py set-target esp32s3
idf.py build
```

Put the board in download mode (hold BOOT, press and release RST, release BOOT), then:

```sh
./flash.sh          # build, flash, start the app
./flash.sh --wipe   # also erase the vault partition and print a new setup code
```

Flashing logs every client out: access tokens are signed with a key made fresh at every boot.

## First use

1. Plug the board in.
2. Trust its certificate on that device: open `https://192.168.237.1/`, unlock it, and download the certificate there (details per device in [docs/SETUP.en.md](docs/SETUP.en.md)).
3. In the extension or app, choose self-hosted and set the server URL to `https://192.168.237.1`.
4. Create the account on one device, pressing BOOT while the board's LED is lit. Log in on the others (BOOT again). **Pick the username at random** (one `@` is enough; it need not be a real address) and write it down with the master password: the board does not store it, which makes a stolen board much harder to crack, and also means nobody can tell you what it was.
5. On the status page, switch the KDF to Argon2id ("鍵を作る計算を変える"): the official apps always create accounts with PBKDF2, and the board cannot change that without your password. This logs every client out, so log in on your other devices afterwards.
6. Set the vault timeout action to "Lock". The clients keep an encrypted copy of the vault, so day-to-day use (viewing, autofill, unlocking) works without the board. The board is needed to log in and to sync.

Merge page: `https://192.168.237.1/merge` compares two vaults (password-protected exports, tinywarden backups, or the board itself) side by side in the browser, and saves either everything (for an empty account) or only what one side lacks (to import into it as it is).

Status page: `https://192.168.237.1/`. Always locked; unlock it with the account's username and master password (BOOT; wrong ones count toward the wipe limit), or with the setup code before an account exists. Then: item counts, capacity, recent requests and changes, apps and versions seen, KDF and switching it to Argon2id, encrypted backup, wipe, and this manual (`/manual`).

## Backups and getting your data out

The clients are official apps that update themselves. If an update ever breaks login with tinywarden, your data must still be reachable, so:

- **Status page > "控えを保存" (save backup)**: username, master password and the BOOT button (PBKDF2 or Argon2id, computed in the browser). Downloads the vault, still encrypted. Wrong passwords count toward the wipe limit, like logins. The file does not contain the username; opening it asks for it.
- **`tools/tw_backup.py`** (Python standard library only; Argon2id accounts also need `pip install argon2-cffi`):
  ```sh
  python3 -I tools/tw_backup.py fetch backup.json            # log in (BOOT), save the vault still encrypted
  python3 -I tools/tw_backup.py decrypt backup.json out.json # offline: master password -> password-protected Bitwarden export
  ```
  `decrypt` writes a Bitwarden password-protected JSON export (it asks for a file password), which Bitwarden or Vaultwarden can import into a new account. `--plain` writes the unencrypted export instead. The export format follows the official clients' source; importing it into real Bitwarden is still to be confirmed.

To restore, create a new account wherever you move to (a fresh tinywarden, Bitwarden, Vaultwarden) and import.

## Security model

What protects the vault is **the strength of your master password, together with a username nobody knows**. Make the password long (five random words, or 16+ random characters), pick the username at random, and switch the KDF to Argon2id. In particular:

- **The board is not locked down.** Flash encryption, secure boot and disabling download mode are not applied (they burn eFuses and cannot be undone). Anyone holding the board can read the flash.
- **What a flash dump shows:** the KDF settings and the wrapped keys, the rough number and size of records, and how many writes there were. Not the username (never stored), not the content, the type, the number or the dates of items (sealed with a key that exists only in RAM after a login). To try passwords offline, the attacker must guess the username and the master password together.
- **What it cannot hide:** a flash dump matches the public firmware, so it tells what the board is. The Bitwarden API paths answer anyone (the apps need them), and the USB vendor is Espressif. Only hardware flash encryption would hide the firmware.
- **A board stolen while plugged in and logged in** has the storage key in RAM; JTAG is not disabled, so it could be read.
- Every device you log in to also keeps a copy of the same ciphertext.
- The BOOT button is the second factor for logins, account creation, unlocking the status page, backups and wipes. 10 wrong master passwords erase the vault.
- Access tokens are signed with a per-boot key: unplugging and replugging the board logs every client out on the next sync.
- There is no account recovery. Forget the master password or the username and the vault is gone.
- The status page is locked until you unlock it with the account (or the setup code, before an account exists). Before that it shows device information only, and the pages, scripts and manual that would tell what the device is answer 404.

## Tests

```sh
# Vault store against a simulated NOR flash, with power cuts at random bytes
cd test/host
cc -std=c11 -O2 -g -Wall -Wextra -fsanitize=address,undefined -I../../firmware/main ../../firmware/main/logstore.c test_logstore.c -o t
ASAN_OPTIONS=detect_leaks=0 ./t

# Backup tool crypto (AES against openssl and FIPS-197, a synthetic vault)
python3 -I test/host/test_tw_backup.py

# One-time setup code image (the layout the firmware reads)
python3 -I test/host/test_setup_code.py

# Browser crypto (PBKDF2, Argon2id against RFC 9106 and OpenSSL, exports) and the merge page's logic
node test/web/test_twcrypto.mjs
node test/web/test_merge.mjs
```

Before committing, run `tools/install-hooks.sh` once: a pre-commit hook then checks for leaked keys, tokens, home paths and email addresses (`tools/check-leaks.sh`). Publishing a version: [release/PUBLISH.md](release/PUBLISH.md).

`test/device/device_test.py` drives a development build over the API. See [docs/TESTING.md](docs/TESTING.md).

Development builds (`CONFIG_TW_DEV_DOWNLOAD_ENDPOINT`, `CONFIG_TW_DEV_SKIP_BUTTON` in `firmware/sdkconfig`) skip the button and add test endpoints. Never use one on a board that holds a real vault.

## Documents

| Document | Contents |
|---|---|
| [docs/MANUAL.en.md](docs/MANUAL.en.md) | How to use it, backups, merging vaults, Argon2id, lifespan |
| [docs/SETUP.en.md](docs/SETUP.en.md) | Setup per device |
| [docs/SPEC.md](docs/SPEC.md) | The specification: network, certificates, storage, API, status page (Japanese) |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Why things are the way they are, measurements, what was tried, comparison with Bitwarden and Vaultwarden (Japanese) |
| [docs/TESTING.md](docs/TESTING.md) | Tests and results (Japanese) |
| [release/PUBLISH.md](release/PUBLISH.md) | Version numbers and how a version is published (English) |

## Never automate

Anything that writes eFuses (`espefuse.py burn_*`, secure boot, flash encryption, disabling download mode). It cannot be undone.

## Support

This is a personal project, shared as is. Issues are welcome, but fixes (for example after a Bitwarden client update) come when time allows.

How to report problems, send changes, or join in on a dedicated board: [CONTRIBUTING.md](CONTRIBUTING.md).

If tinywarden is useful to you, a coffee is always welcome: https://ko-fi.com/hidsek

## Acknowledgements

- [Bitwarden](https://bitwarden.com/) for the open-source clients this works with. "Bitwarden" is a trademark of Bitwarden, Inc.
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden), whose API responses were the reference for what the clients expect.
- Espressif for ESP-IDF and esp_tinyusb (`firmware/main/usb_ecm_glue.c` is adapted from esp_tinyusb, Apache-2.0).
- Written with the help of Claude (Anthropic).

## License

See [LICENSE](LICENSE).
