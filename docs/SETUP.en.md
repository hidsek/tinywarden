# tinywarden setup per device

日本語: [SETUP.md](SETUP.md)

Everyday use and backups: [MANUAL.en.md](MANUAL.en.md). Reasons and research (Japanese): [DECISIONS.md](DECISIONS.md), section "ほかの機器で使えるか" (can it be used on other devices).

The board's status page is in Japanese. Labels are quoted here as they appear on the page, with an English gloss.

## Devices tested (2026-11-19)

| Device | What runs | Result | Notes |
|---|---|---|---|
| Mac | Browser extension (Chrome, Brave) | Works | — |
| Windows 11 | Browser extension (Chrome, Edge) | Works | Install the certificate from the command line (double-click did not work) |
| iPhone 17 (USB-C, iOS 26.5.1) | Bitwarden iOS app | Works | After installing the certificate, turn it on in Certificate Trust Settings |
| moto g24 (Android 14) | Bitwarden Android app | Works | Turn off Wi-Fi and mobile data while talking to the board |
| Chromebook | Browser extension (Chrome) | Works (2026-11-24) | If the certificate download is blocked, keep it. Import at `chrome://certificate-manager`. The Android app was not tried |
| Redmi 2201117TL (Android 13) | — | Does not work | The board does not show up as a network |
| Windows 10 | — | Not tried | No built-in driver, expected not to work |
| Firefox | — | Not yet | Not on the allow list (future work) |

On every device the board is `192.168.237.1` and the connected side gets `192.168.237.2`. The board hands out no router or DNS, so the device's internet connection keeps working.

## Common to all devices

1. **Create the account on one device first.** On the others, just log in with the same username (email) and master password. The board does not store the username, so pick it at random and write it down ([MANUAL.en.md](MANUAL.en.md), "Choosing a username").
2. **Trust the certificate once on each device.** The certificate is made on the board and served at `http://192.168.237.1/ca.crt`. Its name is `Local CA 192.168.237.1`. To be safe, compare it with "証明書 SHA-256" (certificate SHA-256) on the status page (`https://192.168.237.1/`; shown even while locked). Remove the certificate of v0.2 and earlier (`tinywarden CA 192.168.237.1`) if it is installed.
3. **The server URL is `https://192.168.237.1`.** In the extension or app, choose "Self-hosted" on the login screen and enter it.
4. **Press the BOOT button when creating the account and when logging in.** Press it while the board's LED (GPIO48) is lit (within 30 seconds). The LED's color differs between boards.
5. **After creating the account, switch the key derivation to Argon2id on the status page.** Unlock the status page with the username and master password you created (before the account exists, with the setup code shown when flashing). The apps always create accounts with PBKDF2, so do this once, right after creating it (steps in [MANUAL.en.md](MANUAL.en.md), "Switching the key derivation"). It logs everyone out, so log in on your other devices after that.
6. **Set the vault timeout action to "Lock".** With "Log out", you need the board and the button every time.
7. Plugging the board back in and syncing logs you out (the board makes a new signing key at every start). Just log in again.

If the certificate is ever regenerated (rare: when a firmware update changes its form), remove the old one on every device and install the new one.

## Mac

1. Plug in the board. "Espressif Device" appears in System Settings > Network and gets `192.168.237.2`.
2. Trust the certificate (macOS asks for your password):
   ```sh
   curl -o ca.crt http://192.168.237.1/ca.crt
   security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ca.crt
   ```
3. Quit the browser and open it again.
4. In the extension, set the server URL to `https://192.168.237.1`, then create an account or log in (BOOT button).

Check: `curl https://192.168.237.1/alive` answers without a warning.

## Windows 11

1. Plug in the board. The driver is installed automatically, and "UsbNcm Host Device" appears under "Network adapters" in Device Manager.
   - If it appears under "Other devices" with a "!": right-click > Update driver > Browse my computer for drivers > Let me pick from a list of available drivers > Network adapters > manufacturer "Microsoft" > "UsbNcm Host Device".
2. Open `http://192.168.237.1/ca.crt` in the browser to download it.
3. Install the certificate from Command Prompt (no administrator rights needed; answer "Yes" when asked):
   ```
   certutil -addstore -user Root %USERPROFILE%\Downloads\ca.crt
   ```
   **Installing by double-click did not work** (the wizard may put it somewhere other than "Trusted Root Certification Authorities").
4. Quit Chrome or Edge, open it again, and check that `https://192.168.237.1/` opens without a warning.
5. In the extension, set the server URL to `https://192.168.237.1` and log in (BOOT button).

Check: run `ipconfig` in Command Prompt. If `192.168.237.2` is listed, you are connected.

## Chromebook

1. Plug in the board. If `http://192.168.237.1/progress` opens in Chrome, you are connected (Settings may not show the address; that is fine).
2. Open `http://192.168.237.1/ca.crt` in Chrome to download it. **If Chrome blocks it as insecure, press `Ctrl + J` and choose "Keep" in the download list** (only the certificate is served over plain HTTP, since it is not trusted yet).
3. Type `chrome://certificate-manager` in the address bar, then Local certificates > Custom > Import, and choose `ca.crt` (some versions have no menu entry for it in Settings; on older versions use the "Authorities" tab of `chrome://settings/certificates`).
4. Close every Chrome window, open it again, and check that `https://192.168.237.1/` opens without a warning.
5. In the extension, set the server URL to `https://192.168.237.1` and log in (BOOT button).

## iPhone

A USB-C iPhone, connected with one cable.

1. Send `ca.crt` (downloaded on the Mac) to the iPhone with AirDrop. Without a Mac, plug in the board and open `http://192.168.237.1/ca.crt` in Safari.
2. Open "Profile Downloaded" near the top of Settings and install it (named `Local CA 192.168.237.1`).
3. **In Settings > General > About > Certificate Trust Settings, turn on `Local CA 192.168.237.1`.** Without this you get "The certificate for this server is invalid".
4. Plug the board into the iPhone. "Ethernet" appears in Settings. The internet keeps working over mobile data or Wi-Fi.
5. In the Bitwarden iOS app, choose "Self-hosted", enter `https://192.168.237.1` as the server URL, and save.
6. Create an account or log in (BOOT button).

Check: `https://192.168.237.1/` opens in Safari without a warning.

## Android

**Depends on the model.** Some phones cannot use USB Ethernet (the Redmi 2201117TL could not). Android 14 or later has better odds.

1. Plug the board into the phone.
2. **Turn on airplane mode and turn off Wi-Fi too** (see "Note for Android" below).
3. Open `http://192.168.237.1/progress` in Chrome. If some English text appears, you are connected. If it says to turn on the internet, this model cannot be used.
4. Open `http://192.168.237.1/ca.crt` in Chrome to download the certificate.
5. Install it in Settings > Security & privacy > More security settings > Encryption & credentials > Install a certificate > CA certificate (menu names differ a little between models).
6. In the Bitwarden Android app, choose "Self-hosted" and enter `https://192.168.237.1` as the server URL.
7. Log in (BOOT button).
8. When done, turn off airplane mode and unplug the board.

**Note for Android:** Android sends an app's traffic over one "main" network only. While Wi-Fi or mobile data is connected, that becomes the main network, traffic for the board goes out there and times out. So turn off Wi-Fi and mobile data only while talking to the board (login, sync). Viewing, autofill and unlocking need neither the board nor the switch, because the vault is inside the app.

Usual sync routine: airplane mode (Wi-Fi off too) > plug in the board and sync in the app > airplane mode off > unplug the board (the internet comes back even with it plugged in, but the board draws power from the phone's battery).

## Troubleshooting

| Symptom | What to check |
|---|---|
| No network appears | Try another cable (some are charge-only). On Android it depends on the model |
| Certificate error | Did you trust the certificate on that device? iPhone: Certificate Trust Settings turned on. Windows: installed with `certutil`? Did you reopen the browser? |
| "Press the button…" at login | Press BOOT while the board's LED is lit |
| Timeout on Android | Are Wi-Fi and mobile data off? |
| Suddenly cannot log in from an app or browser | An app update may have changed how it talks to the server. Check versions and failures under "つないできたアプリ" (apps that connected) on the status page. You can still get your data out with "控えを保存" (save a backup) on the status page, after unlocking it (MANUAL, "Backups") |
