# Using tinywarden

日本語: [MANUAL.md](MANUAL.md)

An ESP32-S3 plugged in over USB becomes a Bitwarden server (browser extension, iPhone and Android apps). **Setup per device: [SETUP.en.md](SETUP.en.md).** How it works: `docs/SPEC.md`; why: `docs/DECISIONS.md` (both in Japanese).

The board's status page is in Japanese. Labels are quoted here as they appear on the page, with an English gloss.

## Before you start

- **If you forget your master password, nobody can recover it.** Not the board, not the author, not Bitwarden. Write it on paper and keep it with your important documents.
- **Plugging the board back in logs you out.** While it is unplugged you keep using the vault stored on your device. When you plug it back in and sync, you are logged out and log in again (BOOT button needed). Flashing firmware does the same.
- **If the board breaks or is lost, the vault is gone with it.** Keep a backup somewhere else (see "Backups").
- **An extension or app update may one day stop you from logging in.** Official apps update automatically and may not work until tinywarden catches up. So that you can still get your data out, **save a backup once a month with "控えを保存" (save a backup) on the status page.** `tools/tw_backup.py decrypt` turns it back into a Bitwarden export without any app (Example 1b below).
- Whoever gets the board can read the encrypted data on it. Without the master password they cannot read the contents, but they can try passwords offline. **Use a long master password** (4–5 random words, or 16+ random characters).
- **The username (email address) is not stored on the board.** A thief has to guess the username and the master password together. So the username gets stronger if you **pick it at random** instead of using your usual email (see "Choosing a username"). In return, **if you forget the username, you cannot open the vault either.** Write it on paper together with the master password.

### Choosing a username

- One `@` is enough. It does not have to be a real email address (no confirmation email is sent).
- Use **one or two random words** (for example in the form `kumo-hashi@home`, with words picked by dice). One word makes guessing about 7,776 times more work.
- A name (`tanaka@home`) or something very short (`a@z`) is tried first, so it adds almost nothing.
- With several boards, `…@home` and `…@work` let you switch between them with the extension's account switcher.

## First setup

Steps for each device (Mac, Windows, iPhone, Android) and the list of tested devices are in **[SETUP.en.md](SETUP.en.md)**. The flow is the same everywhere:

0. Flashing the firmware shows a **setup code** (like `ABCD-EFGH-JKLM`). Until the account exists, it opens the status page. Note it down.
1. Plug in the board (your device gets `192.168.237.2`; your internet keeps working).
2. On that device, trust the certificate `Local CA 192.168.237.1`, once.
3. In the extension or app, choose "Self-hosted" and enter `https://192.168.237.1` as the server URL.
4. Create the account on the first device (for the username, see "Choosing a username"). **Press the BOOT button while the board's LED (GPIO48) is lit (within 30 seconds).** On the other devices, just log in (BOOT again). Once the account exists, the setup code stops working.
5. **On the status page, switch the key derivation to Argon2id** (see "Switching the key derivation"). Open the status page with the username and master password you just created. The apps always create accounts with PBKDF2, so do this once, right after creating it. It logs everyone out, so log in on your other devices after that.
6. Set the vault timeout action to **"Lock"** (with "Log out" you need the board and the button every time).

## Everyday use

**The extension and apps keep an encrypted copy of the vault on your device.** Unplugging the board, closing the app or restarting the phone does not erase it. Once unlocked (master password, PIN or biometrics), you can view and autofill without the board. The board is needed only to log in and to sync (sending additions, edits and deletions to the board).

- The copy on your device is erased when: you log out yourself, the timeout action is "Log out", or **you plug the board back in and sync** (the board makes a new signing key at every start, rejects the old token, and the app logs out; logging in again brings everything back).
- So set the timeout action to "Lock".
- For unlocking, we recommend **a PIN together with "Lock with master password on browser restart" (on)**. Use the PIN day to day and type the master password only after restarting the browser.
  - A PIN only opens the copy inside that app on that device. If someone learns it, it is useless without that device. If someone learns the master password, everyone who has the encrypted data (logged-in devices, the board, backups) can read all of it.
  - With "Lock with master password on browser restart" off, the key that the PIN opens stays on disk. If those files are stolen, a short PIN can be brute-forced offline. So keep it on.
  - If you think someone saw your PIN, change the PIN on that device. Other devices and the master password can stay as they are.

- Day to day, the extension alone is enough. Unlocking happens inside the extension, so no button press.
- The button is needed only for: creating the account, logging in with the password (a new browser, after re-plugging), unlocking the status page, and saving a backup, changing the key derivation or erasing everything from the status page.
- The board's LED (GPIO48) lights up when it is waiting for the button. Its color differs between boards (on some SuperMini boards it looks red). While it is lit, the board does not answer anything else.
- A blue "BAT" LED that keeps blinking is the charging circuit looking for a battery, not a fault. Firmware cannot turn it off; cover it with tape or put the board in a case if it bothers you.

## Status page

Open `https://192.168.237.1/` in a browser. **It is always locked.** While locked it shows only device information (chip, version, uptime, memory), so someone who merely plugs it in cannot tell what it is.

- **Unlocking:** enter the username and master password, press "解除" (unlock), and press BOOT while the board's LED is lit. The master password is hashed in the page, so it never reaches the board. **Wrong passwords count as failed logins; 10 in a row erase everything.**
- Before the account exists, enter the **setup code** instead (the one shown when flashing; dashes and case do not matter).
- The page locks itself after 30 minutes; "鍵を掛ける" (lock) locks it at once. Re-plugging the board also locks it.
- Once unlocked, **this manual** can be read on the board itself (`https://192.168.237.1/manual`).

| Row | What it tells you |
|---|---|
| 項目・フォルダ (items, folders) | Counts (counted when the vault is unlocked) |
| 保存領域・あと入る件数 (storage, room left) | Free space. About 1,000 items fit, at 2.6 KB per item on average |
| 古い版 (old versions) | Old versions left by edits and deletions. The board cleans them up before it fills |
| 起動時の読み込み (load at start) | Red text means power was cut while writing (the half-written item was discarded) |
| 直近の通信 (recent requests) | When something fails, shows where it stopped |
| 最近の変更 (recent changes) | When something was saved or deleted (contents are encrypted, so item names are not shown; deleted ones show no type) |

Everything on the board except the username, which is not stored at all, is kept encrypted, including the type, count and dates of items. The key is in the board's memory only after someone logs in, and is gone when it is unplugged.

## Import

1. Export from the service you use now. We recommend **password-protected JSON (the "File password" type)**. The "Account restricted" type cannot be imported into a new tinywarden account.
2. In the extension, open Settings > Vault options > Import and choose the file.
3. About 800 items take around 15 seconds. Progress is at `http://192.168.237.1/progress` (the status page does not open during an import).

| Format | What gets in |
|---|---|
| Password-protected JSON | Everything (folders, cards, identities, passkeys) |
| JSON | Everything, but the file is not encrypted, so delete it right after |
| CSV | Logins and secure notes only |

Attachments are not imported in any format.

- **Importing twice gives you two of every item** (Bitwarden does not check for duplicates).
- If it does not fit, nothing is imported and you get "空きが足りない" (not enough space). It never imports halfway (unless the power is cut).
- One import can be up to about 1.7 MB (about 1,000 items). Beyond that you get "大きすぎる" (too large).

## Merging vaults (`https://192.168.237.1/merge`)

Compare two vaults, then merge them into one or export only what one side is missing. Open it from "保管庫をまとめる" (merge vaults) on the status page. Everything is computed in the browser; the contents are sent neither to the board nor to the internet (closing the page discards them).

- **Input:** for A and for B, first choose "ファイル" (file) or "この基板" (this board). For a file, only the field the file needs appears: the file password, or that account's username and master password (backups made before v0.3 contain the username, so it is not asked). For this board, the username and master password. A and B can be different accounts.
- **What you can load (one each for A and B):** a password-protected export (made in Vaultwarden or Bitwarden with "Password protected"), a tinywarden backup, an unencrypted export, or the board's current contents (username, master password, BOOT). Bitwarden and Vaultwarden "Account restricted" exports cannot be opened, because their key is on the server (export again and choose "Password protected"). The password is the file password you set when exporting, for a password-protected export, or the master password, for a tinywarden backup (the page tells you which).
- **Matching:** the same ID means the same item. Items whose ID changed on import are matched by type, name, username and the host of the URL. Different ways of writing "empty" (empty string vs missing field), passkey use counts and password revision dates do not count as differences.
- **Screen:** A's cards on the left, B's on the right, differing fields highlighted. At the top: "差分なし" (no differences), or the counts of differing, A-only and B-only items, plus how many items the saved file will have. Click the card to keep (green frame). In the middle: "両方" (keep both) and "捨てる" (drop). At first, for differing items the newer one is chosen, and items on one side only are kept. Passwords and the like are hidden; "隠した値を見せる" (show hidden values) reveals them.
- **Saving:** "全部まとめる" (merge everything) and "足りない分だけ" (only what is missing; into A or into B, each with counts of additions and of items to delete by hand) are side by side. Choose one, then set a file password and the key derivation, and save.
- **Output (always a password-protected export):** the file's key derivation is Argon2id by default. The app opens the file when importing, so Bitwarden cloud and Vaultwarden can both read it (current official apps support Argon2id files). For older apps or non-Bitwarden tools, choose PBKDF2.
  - **Merge everything:** the whole vault as you chose it. Import it into an **empty account** (importing into one with items creates duplicates).
  - **Only what B is missing / only what A is missing:** items the other side does not have, plus differing items where you chose the other side's version. You can **import it straight into the existing account**. Import can only add, so the old versions left on the other side, and the other side's items you chose to drop, must be deleted by hand using the list shown on the page.
- **Examples:**
  - Bring only what you added in the cloud into tinywarden: A = this board, B = cloud export > "Aに足りない分だけ保存" (save only what A is missing) > import into tinywarden.
  - Turn a tinywarden backup into an importable file (no terminal): load only the backup into A and use "全部まとめて保存" (save everything merged).
- When A and B have different passwords for an item, the password you did not choose goes into the kept item's password history (newest first, up to 5). If you choose wrong, you can still find the old password.
- Folders are matched by name. Whether importing creates duplicate folders with the same name has not been checked yet.

## Switching the key derivation (Argon2id)

Switch the computation that turns the master password into the vault key (KDF) from PBKDF2 to Argon2id.

- **Why:** if the encrypted data is stolen (the board, a logged-in device's copy, a backup), the attacker tries master passwords one by one. Argon2id needs a lot of memory (32 MB) per try, so adding GPUs barely speeds it up (roughly 1/20 the speed of PBKDF2, as an estimate). A long master password matters most; Argon2id is insurance on top of it.
- **Why you do it yourself:** the official apps always create accounts with PBKDF2 (600,000 iterations). The board does not know your master password, so it cannot change this on its own. With Vaultwarden or Bitwarden cloud, too, you change it yourself in the web vault settings.
- **Steps:**
  1. Save a backup with "控えを保存" (save a backup).
  2. Under "鍵を作る計算を変える" (change key derivation) on the status page, enter your username and master password, leave "Argon2id（メモリ32MB、6回、並列4）" (memory 32 MB, 6 iterations, parallelism 4) selected, and press "変える" (change).
  3. When the board's LED lights up, press BOOT. Within 2 minutes after that, the page computes the newly wrapped key and sends it (Argon2id takes a few seconds on a computer).
  4. Done when it says "変えました" (changed) and the "鍵を作る計算（KDF）" row shows Argon2id.
- **Afterwards:** every device is logged out. Log in again in the extension and phone apps (BOOT). The vault contents are unchanged (only the vault key is re-wrapped).
- The values are the defaults Bitwarden apps use when Argon2id is chosen. The iPhone autofill screen has little memory to work with, so do not raise the memory.
- Unlocking with Face ID or a fingerprint just takes out a key stored on the device, so no computation happens. Unlocking with the master password or PIN runs Argon2id (1–2 seconds on a phone).
- You can switch back to PBKDF2 (choose "PBKDF2（60万回）" in the same field).

## Erasing everything

Unlock the status page, type "消去" (erase) at the bottom, press "全部消す" (erase everything), and press BOOT while the board's LED is lit. The account and all items are erased. The certificate stays, so the Mac settings can stay as they are.

Ten wrong master passwords in a row (at login or on the status page) also erase everything in the same way.

- Afterwards you can create a new account from the extension or app. The setup code, however, was erased when the first account was created. To open the status page (and the manual) before creating the new account, flash the firmware again to get a new setup code (the web flasher writes a new code even without "Erase device").
- If you forgot the username or master password and cannot open the status page, flash again with "Erase device" ticked (this erases everything).

## Backups

Keep an encrypted copy somewhere else, so that a broken or lost board does not cost you anything. **How you do it is up to you.** These are examples.

### Example 1: save a password-protected JSON once a month

1. Export from the extension as password-protected JSON (the "File password" type).
2. Put the file somewhere other than the board (cloud storage, an encrypted USB stick, …).
3. Keep several older copies too (last month, the month before, …). If you back up broken contents, you can still go back a generation.

- Make the file password as long as the master password. Whoever gets the file can try passwords offline.
- Do not put unencrypted JSON or CSV in the cloud.

### Example 1b: back up without the apps (status page, `tools/tw_backup.py`)

A way to get your data out even if an extension or app update one day stops you from logging in.

**From the status page** (easiest; works on a Mac or an iPhone): under "控えを保存" (save a backup), enter your username and master password, press the button, and press BOOT while the board's LED is lit. The master password is hashed in the page before it is sent, so it never reaches the board. Wrong passwords count the same as failed logins; 10 in a row erase everything. A file `backup-<date>.json` is saved. Its contents stay encrypted. **The backup does not contain the username**, so enter it when opening the file (`decrypt`, the merge page).

**From a terminal on a Mac:**

A tool for getting your data out even if an app update one day stops you from logging in. It needs only the Mac's Python, nothing to install.

```sh
python3 -I tools/tw_backup.py fetch backup.json            # log in (press BOOT) and save, still encrypted
python3 -I tools/tw_backup.py decrypt backup.json out.json # unlock with the master password into a password-protected Bitwarden export (no board needed)
```

- A file saved from the status page can be restored with `decrypt` as is. It asks for the username (backups made before v0.3 contain it and do not ask).
- A file saved by `fetch` stays encrypted, so treat it like a password-protected JSON. When saving, it also checks that your master password opens it.
- `decrypt` asks for a new file password (12+ characters) and writes `out.json` in the same form as Bitwarden's "password protected" export. No unencrypted file is left on disk. Enter that password when importing.
- `--plain` writes unencrypted JSON. Use it only for a destination that cannot read password-protected files, and delete it right after importing.
- Items in the trash are left out. Attachments are not supported (tinywarden does not handle attachments).
- For an Argon2id account, `tools/tw_backup.py` needs `pip install argon2-cffi` (PBKDF2 needs nothing). "控えを保存" on the status page computes either one in the browser.

### Example 2: keep a second board

1. Set up a second board through first setup (trust its certificate too). Do not plug both in at once (both call themselves `192.168.237.1`).
2. Once a month, export from the first board, plug in the second, erase it and import.
3. On the second board's status page, check that the counts match the first.
4. Keep the second board somewhere other than the first.

If the first board breaks, plug in the second and log in, and you have the vault as of the last copy. It also checks every month that your backup really restores.

### Restoring

**Create a new account at the destination and import into it.** The destination can be a new tinywarden (or an erased board), Bitwarden cloud or Vaultwarden.

- Password-protected JSON (Example 1): import it as is.
- A backup from the status page or `tw_backup.py` (Example 1b): first run `python3 -I tools/tw_backup.py decrypt backup.json out.json` to make a password-protected export, then import `out.json` (you are asked for the file password).
- There is no feature to write a board's encrypted data straight onto another board. Importing into a new account works with any destination and is more reliable.

## Moving from v0.2 to v0.3

v0.3 changed how the vault is stored (the username is not stored, everything is encrypted). **A v0.2 vault cannot be opened by v0.3.** Nothing is migrated on the board; move it like this:

1. **Still on v0.2**, export from the extension as **password-protected JSON** (Settings > Vault options > Export, the "File password" type). To be safe, also save a backup with "控えを保存" on the status page.
2. On the web flasher, **tick "Erase device"** and flash v0.3. Note the **setup code**.
3. The certificate is new too (now named `Local CA 192.168.237.1`). On each device, remove the old `tinywarden CA 192.168.237.1` and install the new one ([SETUP.en.md](SETUP.en.md)).
4. Create the account with a new, randomly chosen username and your master password (BOOT).
5. Open the status page with the new username and master password, and switch the key derivation to Argon2id.
6. Log in again in the extension and import the file from step 1 (file password).
7. Log in again on your other devices with the new username. Check on the status page that the counts match.

If you flash v0.3 over a v0.2 vault without erasing, login is refused with "Old format" (it does not count as a failure, so nothing is erased).

## Keeping it for a long time (lifespan and weak points)

Stored with care, the board can be expected to last around ten years (all figures are general rules of thumb, not measured on this board). But not decades without any attention.

| Part | Rough lifespan | What to watch |
|---|---|---|
| Flash (where the vault lives) | Typical NOR flash is designed to keep data for about 20 years; less at higher temperatures | Rewrites are also limited (about 100,000 per location). tinywarden spreads writes over the whole area, so normal use is fine |
| The chip itself | Usually lasts decades | Sensitive to static. Touch metal to discharge before handling |
| USB connector | Wears with plugging and unplugging | Most likely to fail first |
| Solder and board | Corrode with humidity | Store in a dry place, in an anti-static bag |
| Cheap clones | Quality varies a lot between units | Having two is reassuring |

**What usually gives out first is not the board but "an official app update that stops it from connecting."** So even when you are not using it, plug it in once a year to check.

### Storing it, passing it on (just in case)

Because the vault is a physical thing you hold, you can pass it on to your family.

- Keep it somewhere cool and dry, with an anti-static bag and a desiccant.
- About once a year, plug it in and check that it opens. Take a fresh backup at the same time ("控えを保存", or make an importable file with the merge page).
- Have two boards, one as a spare. Keep the backup file and the paper with the master password somewhere other than the boards as well.
- For whoever takes over, write the steps "plug in > trust the certificate > enter the server URL in the extension and log in with the username and master password (press BOOT)" on one sheet of paper and keep it together. The board does not keep the username, so without it on paper the vault cannot be passed on. If an app update has made it unusable, importing the backup into a new Bitwarden (or similar) account still gets the contents out ("Restoring").

## Troubleshooting

| What happened | What to do |
|---|---|
| Plugging in the board cuts the internet | Old firmware (a version that handed out a gateway). Unplugging fixes it. Flash new firmware |
| Certificate error in the extension | Check that you trusted the certificate. Quit the browser and open it again |
| iPhone says "The certificate for this server is invalid" | Check it is turned on in Certificate Trust Settings. If a firmware update regenerated the certificate, remove the old profile and install it again |
| Cannot log in or create an account | Did you press BOOT while the board's LED was lit? Is the username right (the board does not know it, so a wrong one looks like a wrong password)? Read the error under "直近の通信" (recent requests) on the status page |
| "Old format" | You flashed v0.3 over a v0.2 vault. See "Moving from v0.2 to v0.3" |
| Status page says "コードが違います" (wrong code) | Is it the setup code from this flash? Flashing again changes it. After the account exists it no longer works (use the username and master password) |
| Forgot the username | The board cannot tell you. A device that is still logged in shows it in the extension's or app's account display. If none is, neither the board nor status-page backups can be opened. A password-protected export opens with its file password alone, so import that into a new account |
| Suddenly logged out | The board was unplugged or restarted ("前回の再起動の理由", reason for last restart, on the status page). Log in again |
| The board does not answer at all | Press the board's RST button once. If that does not help, unplug and plug it back in |
| Import says "大きすぎる" (too large) | Split the export in two and import them one at a time |
| Import says "空きが足りない" (not enough space) | Check free space on the status page. Delete items you do not need, or import less |

## Flashing firmware (for developers)

1. Enter download mode: hold BOOT, press and release RST, wait a second, release BOOT.
2. `./flash.sh` (`./flash.sh --wipe` when the storage format changed; this erases the vault and prints a new setup code at the end).
3. It starts on its own after flashing. You are logged out, so log in again.

Builds with development features enabled in `firmware/sdkconfig` (`CONFIG_TW_DEV_DOWNLOAD_ENDPOINT`, `CONFIG_TW_DEV_SKIP_BUTTON`) must never be used for a real vault. `CONFIG_TW_DEV_SKIP_BUTTON` in particular skips the button check, so anyone can log in or erase everything.
