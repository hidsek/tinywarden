# Contributing to tinywarden

English below / 日本語は下にあります。

tinywarden is a personal project shared as is. Ideas, reports and help are welcome; replies and fixes come when time allows. English or Japanese, either is fine.

## Reporting a problem

Open an issue with:

- the board (for example "ESP32-S3 SuperMini") and the tinywarden version (status page > ファームウェア)
- the device and app: OS and version, and the Bitwarden app or extension version (status page > つないできたアプリ shows what the board saw)
- what you did, what you expected, and what happened
- the rows of the status page's request log (直近の通信) around the failure, if any

**Never paste** your master password, your email address, exported vault files, backups, tokens or anything from inside the vault. The status page shows no secrets, but check before you paste.

## Security issues

Please do not open a public issue for something that could put someone's vault at risk. Use GitHub's private vulnerability reporting on this repository (Security > Report a vulnerability).

## Pull requests

Welcome, especially small ones. They are reviewed and merged here.

- Keep one change per pull request.
- Run the tests that touch your change (see README > Tests). The CI runs them too, and builds the firmware.
- `tools/install-hooks.sh` enables a pre-commit check for leaked keys, tokens, home paths and email addresses.
- Do not add anything that writes eFuses (secure boot, flash encryption, disabling download mode). Those cannot be undone and stay manual.
- Development builds (`CONFIG_TW_DEV_*`) must never be on by default.

## Hardware

A dedicated board would be fun to make someday. If you are interested, get in touch (an issue is fine).

---

# tinywardenへの参加

tinywardenは、個人のプロジェクトをそのまま公開しているものです。アイデア、不具合の報告、手伝いは歓迎します。返事や修正は、時間があるときになります。英語でも日本語でも大丈夫です。

## 不具合の報告

Issueに、次のことを書いてください。

- 基板（たとえば「ESP32-S3 SuperMini」）と、tinywardenの版（管理ページの「ファームウェア」）
- 機器とアプリ: OSとその版、Bitwardenのアプリか拡張機能の版（管理ページの「つないできたアプリ」に、基板が見たものが出ています）
- 何をしたか、どうなるはずだったか、実際にどうなったか
- うまくいかなかったときの、管理ページの「直近の通信」の行（あれば）

**貼らないでください:** マスターパスワード、メールアドレス、エクスポートしたファイル、控え、トークン、保管庫の中身。管理ページには秘密の情報は出ませんが、貼る前に確かめてください。

## 安全に関わる問題

誰かの保管庫を危険にさらすおそれのある問題は、公開のIssueにしないでください。このリポジトリの、GitHubの非公開の脆弱性報告（Security > Report a vulnerability）を使ってください。

## プルリクエスト

歓迎します。小さいものだと特にうれしいです。ここで見て、マージします。

- 1つのプルリクエストには、1つの変更だけにしてください。
- 変更に関係するテストを動かしてください（READMEの「テスト」）。CIでも、テストとファームウェアのビルドが動きます。
- `tools/install-hooks.sh` を一度動かすと、コミットの前に、鍵やトークン、手元のフォルダの場所、メールアドレスが入っていないかを確かめます。
- eFuseに書き込むもの（セキュアブート、フラッシュの暗号化、ダウンロードモードの無効化）は足さないでください。元に戻せないので、手作業のままにしています。
- 開発用のビルド（`CONFIG_TW_DEV_*`）を、初めからオンにしないでください。

## ハードウェア

いつか専用の基板を作れたら面白いと思っています。興味があれば、気軽に連絡ください（Issueで大丈夫です）。
