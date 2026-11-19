# tinywarden 仕様書（v0.2.0）

決まった内容だけを書く。理由・経緯・測った結果・未解決の点は [DECISIONS.md](DECISIONS.md)（検討記録）に書く。使い方は [MANUAL.md](MANUAL.md)。

対象の基板: **ESP32-S3 SuperMini（ESP32-S3FH4R2、フラッシュ4MB・PSRAM 2MB）**。**Wi-Fiは使わない**（技適マークが無いため。USBだけなら電波を出さない）。返すJSONの形は、Vaultwarden（2026-11-15時点のmain、`4051a4d`）に合わせる。

## 1. 何をするものか

ESP32-S3を1つUSBで挿すだけで、Bitwardenのブラウザ拡張機能のサーバーとして動く。保管庫は機器の中だけにあり、クラウドにもMacにもサーバーを置かない（拡張機能が自分で持つキャッシュは除く）。

```
Bitwardenの拡張機能（改造なし）
   │  HTTPS  https://192.168.237.1
   ▼
ESP32-S3（USBのネットワーク機器 CDC-NCM として見える）
   ├─ HTTPSサーバー（API と管理ページ）
   ├─ HTTPサーバー（証明書の配布と、インポートの進み具合）
   ├─ ログインの確認・回数制限・消去
   ├─ 本体のボタン（BOOT, GPIO0）と色つきLED（GPIO48）
   └─ フラッシュの専用区画に、暗号文のJSONを追記式（ログ方式）で保存
```

- 1台1ユーザー
- 暗号化・復号は全部拡張機能の中。機器は暗号文を解釈しない
- Macに入れるソフトは無い。最初に機器の証明書を信頼させるだけ

## 2. ネットワーク

| 項目 | 値 |
|---|---|
| USBの種類 | CDC-NCM |
| 機器のIP | `192.168.237.1/24` |
| Mac側 | 機器のDHCPサーバーから `192.168.237.2` 以降をもらう |
| DHCPで渡すもの | IPとネットマスクだけ。ゲートウェイとDNSは渡さない |
| 拡張機能のサーバーURL | `https://192.168.237.1` |
| HTTP（80番） | 証明書の配布（`GET /tinywarden.crt`）と、インポートの進み具合（`GET /progress`）。ほかは全部HTTPSへ |
| HTTPS（443番） | API全部と管理ページ |
| 内部の制御用ポート | HTTPSは32769、HTTPは32768（別々にする） |

## 3. 証明書

- 最初の起動で、機器の中で2枚の証明書を作る（鍵はどちらもECDSA P-256）
  - 認証局: `CN=tinywarden CA 192.168.237.1`、自分で署名、`CA:TRUE`（pathlen 0）、用途は証明書の署名。名前の制約（必須の印つき）で、使えるのは `IP:192.168.237.1` だけ（ドメイン名とメールは存在しない `invalid` の下だけ）。**この鍵は、サーバー証明書に署名したらすぐ捨てる**。保存しない
  - サーバー証明書: `CN=tinywarden 192.168.237.1`、SAN `IP:192.168.237.1`、`CA:FALSE`、用途はデジタル署名、拡張鍵用途はサーバー認証だけ。認証局が署名する。HTTPSではこれだけを送る
  - NVSに保存するのは、認証局の証明書（`tlsca`）、サーバー証明書（`tlscrt`）、その鍵（`tlskey`）、形の版（`tlsver`、今は4）。起動時に版が違えば、2枚とも作り直す
  - 有効期間はどちらも825日未満。日付は、作った時点のファームウェアのビルド日から決める
- 人が信頼させるのは認証局の証明書。管理ページのSHA-256も認証局の証明書のもの
- 配り方: `http://192.168.237.1/tinywarden.crt`（認証局の証明書）。Macでは `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db tinywarden.crt`
- 証明書は公開してよい。サーバー証明書の秘密鍵は機器の外に出さない
- iPhone: 証明書をAirDropなどで送り、プロファイルとして入れ、「設定 → 一般 → 情報 → 証明書信頼設定」でオンにする
- 保管庫を消しても（全消去でも）証明書は変わらない。作り直すのは、NVSを消したときと、形の版が上がったとき

## 4. 時計

- 機器の時計 ＝ max（ファームウェアのビルド日時, 前に保存した時刻）＋ 起動からの経過時間。変更があるたびにNVSに保存する
- `revision-date` は、いつも「今」を返す
- アクセストークン（JWT）の `exp` は `2147483000`（2038-01-19。32ビットの整数に収まる最大に近い値。Androidのアプリは `exp` を32ビットの `Int` で読むので、これより大きいとログインの直後に落ちる）
- JWTの署名の鍵は起動のたびに作り直す（抜いたり再起動したりするとログアウトになる）。リフレッシュトークンはRAMにだけ持つ

## 5. 保存の形（ログ方式）

### 区画

| 区画 | 位置 | 大きさ | 中身 |
|---|---|---|---|
| `nvs` | 0x9000 | 24KB | NVSの名前空間 `tw`: `fails`（失敗の回数）、`clock`（時計）、`tlskey`・`tlscrt`（証明書） |
| `factory` | 0x10000 | 1MB | ファームウェア |
| `storage` | 0x110000 | 0x2F0000（64KBの区画47個） | 保管庫。種類は `data`・`0x40`。ファイルシステムは使わない |

### 仕組み

- 64KBの区画（セグメント）に、記録（レコード）を前から順に足していく。書いた記録は上書きしない
- 編集は新しい版を足す。削除は「削除の印（トゥームストーン）」を足す
- 起動時に全部の区画を読み、キーごとに通し番号が一番大きい版を最新として、PSRAMに目次を作る。中身は目次に置かず、読むときにフラッシュから読む
- キーは（種類, ID）。種類は ユーザー・フォルダ・項目・自己テスト用 の4つ。呼び出す側はパス（`/tw/user.json`、`/tw/f/<id>.json`、`/tw/c/<id>.json`）を使い、`store.c` がキーに直す
- ログの本体（`logstore.c`）はESP-IDFに依存しない

### 記録の形

区画の先頭16バイト: 目印 `TWSG`、区画の通し番号、形式の版（1）、CRC32。

記録（40バイトの見出し＋中身、4バイト単位に切り上げ）:

| 欄 | 大きさ | 中身 |
|---|---|---|
| 目印 | 4 | `TWR1` |
| 通し番号 | 4 | 全体で増えていく番号。大きいほど新しい |
| 時刻 | 4 | 書いた時刻（機器の時計、秒） |
| 種類・操作・印 | 1・1・2 | 操作は「保存」か「削除」。印は「大掃除で写したもの」 |
| ID | 16 | UUIDを16バイトにしたもの。ユーザーは全部0 |
| 長さ | 4 | 中身のバイト数（最大65,480） |
| CRC32 | 4 | 見出しと中身の全体 |

中身は、拡張機能に返す形のJSON（項目は `cipherDetails`、フォルダは `folder`、ユーザーは下の表）。

### 書き込み

1. 今書いている区画の末尾に、記録を1回で書く
2. 読み直して、書いたとおりか確かめる。違えばその区画を閉じて、新しい区画に書き直す
3. 区画がいっぱいなら閉じて、空の区画を使う。空の区画は常に1つ以上残す（大掃除の行き先）

### 大掃除（GC）

空きが足りないときに、最新版が一番少ない区画を選んで、次の順にする。

1. その区画にある最新版を、今書いている区画の末尾に写す（通し番号は新しく振る）
2. 区画を、後ろのセクターから消去する
3. 消去が全部終わってから、その区画にあった古い版のぶんを数え直し、要らなくなった削除の印を目次から外す

- 削除の印は、そのキーの古い「保存」の版がフラッシュに残っているあいだは必要
- 古い版の数は「保存」だけ数える（古い削除の印は数えない）
- 写す途中で、古い保存の版が残っていない削除の印は、写さずに捨ててよい

### 起動時の読み込み

| 見つけたもの | どうするか |
|---|---|
| CRCが合わない記録 | そこから後ろを捨て、その区画を閉じる（以後、そこには書かない） |
| 同じキーの版が複数 | 通し番号が一番大きいものを使う |
| 見出しが消えていて中身が半端な区画 | 消去し直して空にする |
| 区画の見出しが正しくない区画 | 消去し直して空にする |

一番新しい区画の末尾がきれいに空いていれば、そこから書き足す。

### 容量

- 約束する容量 ＝（区画の数 − 3）× (64KB − 16バイト)。3区画ぶんは大掃除のための余裕
- 1件の上限は65,480バイト

### 最近の変更

直近32件の変更（時刻、種類、操作、ID）をメモリに持ち、管理ページに出す。大掃除で写した記録は含めない。

### ユーザーの記録

| 欄 | 中身 |
|---|---|
| `id`, `email`, `name`, `securityStamp`, `creationDate` | 基本 |
| `key` | マスターキーで包んだユーザーキー（`akey`） |
| `privateKey`, `publicKey` | 暗号化された秘密鍵と公開鍵 |
| `accountKeys` | v2アカウントの鍵の情報（来たらそのまま保存して返す） |
| `kdf`, `kdfIterations`, `kdfMemory`, `kdfParallelism`, `salt` | 拡張機能が鍵を作るときの設定 |
| `userKeyId` | `user-key-id` で送られてきた値 |
| `pwSalt`, `pwIter`, `pwHash` | ログインの確認用（下の6） |

KDFを変えると（`POST /tw/kdf`）、`key`、`kdf*`、`pwSalt`・`pwIter`・`pwHash`、`securityStamp` を1回の書き込みで置き換える。電源が切れても、前の記録か新しい記録のどちらかが残る
| `devices` | ログインした拡張機能の `deviceIdentifier` の一覧 |

## 6. ログインの確認と回数制限

- 拡張機能は、マスターパスワードから作った値（`masterPasswordHash`、base64）を送ってくる
- 機器は、それに PBKDF2-HMAC-SHA256（塩16バイト、10,000回）をかけた値を `pwHash` として持つ
- 確かめる順番:
  1. `fails` を1つ増やしてNVSに保存する（照合より先）
  2. 照合する（時間が一定になる比べ方）
  3. 合っていたら `fails` を0に戻す
- `fails` が10回に達したら、`storage` 区画を丸ごと消去して初期化する
- 本体のボタンを30秒以内に押させる場面: パスワードでのログイン、アカウントの作成、管理ページからの控えの保存・KDFの変更・全消去。押されなければ断る（回数には数えない）
- ボタンを待っているあいだは、GPIO48のLEDを点滅させる（0.25秒ごと）。それ以外はLEDを消す（起動時にも消す）。LEDの種類は設定（`TW_LED_KIND`）で選ぶ: ふつうのLED（ピンをHighで点く。開発に使ったSuperMiniはこれで、赤く光る。初期値）か、WS2812（R・G・Bを同じ強さ64/255で光らせるので、色の並び順に関係なく光る）。ふつうのLEDにWS2812の信号を送ると、点滅せずに薄く光るだけになる
- ボタンを待っているあいだ、HTTPSのサーバーはほかの要求に答えない
- マスターパスワードの復旧と、バックアップコードの仕組みは持たない

## 7. URL一覧

全部のURLで、`Origin` が許可リスト（Chrome/Braveの拡張機能 `chrome-extension://nngceckbapebfimnlniiiahkandclblb`）にあれば、CORSの許可を返す。`OPTIONS` には事前確認の返事を返す。

### 認証なし

| URL | 返すもの |
|---|---|
| `GET /` | 管理ページ（下の8） |
| `GET /alive` | 今の時刻の文字列。ヘッダー `X-Tinywarden-Diag` に80番の状態と内部メモリ |
| `GET /api/config` | サーバーの設定（`version: "2026.6.0"`、`server.name: "tinywarden"`、`environment` は `https://192.168.237.1` 系、ユーザーがいれば登録不可） |
| `POST /identity/accounts/prelogin`、`/prelogin/password` | ユーザーのKDFの設定。メールが違えば既定値（PBKDF2 600,000回） |
| `POST /identity/accounts/register/send-verification-email` | ユーザーがいなければ、登録用のトークン（32バイトの乱数のbase64url、43文字）を返す（`Accept: application/json` ならJSONの文字列、違えば平文）。メールは送らない |
| `POST /identity/accounts/register/finish` | 空の機器のときだけ。ボタンを押させてからユーザーを作る。`{"object":"registerFinish"}` |
| `POST /identity/connect/token` | `grant_type=password`（ボタン＋照合＋回数制限）と `refresh_token` |
| `GET /api/devices/knowndevice` | `X-Request-Email`（base64url）と `X-Device-Identifier` を見て true/false |
| `POST /tw/backup` | 控え。ヘッダー `X-Tinywarden-Confirm: backup` と、本文 `{"email", "masterPasswordHash"}`（ログインと同じハッシュ。管理ページがブラウザの中で、PBKDF2かArgon2idで計算する）が必要。ログインと同じく、ボタン、失敗の回数（10回で全消去）で確かめてから、`{"tinywarden_backup":1, "saved", "email", "prelogin":{kdf…}, "sync":{同期と同じもの}}` を返す（暗号化されたまま。`tools/tw_backup.py` の `fetch` と同じ形） |
| `POST /tw/kdf/key` | KDFの変更の1段目。ヘッダー `X-Tinywarden-Confirm: kdf`、本文 `{"email", "masterPasswordHash"}`。ログインと同じく、ボタンと失敗の回数で確かめてから、`{"key"（今のマスターキーで包んだユーザーキー）, "kdf", "kdfIterations", "kdfMemory", "kdfParallelism", "token"}` を返す。`token` は32バイトの乱数のbase64url、メモリだけに持ち、2分で切れる |
| `POST /tw/kdf` | KDFの変更の2段目。ヘッダー `X-Tinywarden-Confirm: kdf`、本文 `{"token", "masterPasswordHash"（新しいマスターキーから）, "key"（新しいマスターキーで包み直したユーザーキー、EncStringの種類2）, "kdf", "kdfIterations", "kdfMemory", "kdfParallelism"}`。`token` は合っていても違っていても1回で捨てる。KDFの範囲: PBKDF2は600,000〜2,000,000回、Argon2idは回数2〜10、メモリ16〜1024MiB、並列1〜16。ユーザーの記録を1回で書き換え（5の「ユーザーの記録」）、署名の鍵を作り直して、全員をログアウトさせる。`{"ok": true}` |
| `GET /merge` | 保管庫をまとめるページ（MANUAL参照）。`firmware/web/merge.html`、スクリプトは `/web/merge-ui.js`、`/web/merge.js`。管理ページと同じCSP、`Cache-Control: no-store`。基板に送るのは「この基板から取る」のときの `/identity/accounts/prelogin` と `/tw/backup` だけ |
| `GET /web/*` | 管理ページが使うスクリプト（`firmware/web/` をファームウェアに埋め込んだもの）。`status.js`、`twcrypto.js`（PBKDF2・Argon2id・EncString・エクスポート）、`vendor/noble-hashes/`（Argon2id、`@noble/hashes` 2.0.1、MIT）。`Cache-Control: no-cache`、`X-Content-Type-Options: nosniff` |
| `POST /tw/wipe` | 全消去。ヘッダー `X-Tinywarden-Confirm: wipe-all` が必要。ボタンを押させてから、`storage` を消去し、`fails` とトークンを戻す |

### 認証あり（`Authorization: Bearer <JWT>`）

| URL | 返すもの |
|---|---|
| `GET /api/accounts/profile` | プロフィール（`object: "profile"`） |
| `GET /api/accounts/revision-date` | 今の時刻（ミリ秒） |
| `POST /api/accounts/key-management/user-key-id` | 受けた値を保存して200 |
| `GET /api/auth-requests/pending` | 空の一覧 |
| `GET /api/sync` | プロフィール、フォルダ、項目を全部。フラッシュから読みながら、8KBずつまとめて送る |
| `POST /api/ciphers`、`POST /api/ciphers/create` | 項目を作る |
| `POST /api/ciphers/import` | インポート（下の9） |
| `GET /api/ciphers/{id}`、`/{id}/details` | 項目1つ |
| `PUT /api/ciphers/{id}`（`POST` も可） | 更新 |
| `PUT /api/ciphers/{id}/partial` | お気に入りとフォルダだけ変える |
| `PUT /api/ciphers/{id}/delete` | ごみ箱へ（`deletedDate` を入れる） |
| `PUT /api/ciphers/{id}/restore` | ごみ箱から戻す |
| `DELETE /api/ciphers/{id}` | 完全に削除 |
| `POST /api/folders`、`PUT /api/folders/{id}`、`DELETE /api/folders/{id}` | フォルダ |

### HTTP（80番）

| URL | 返すもの |
|---|---|
| `GET /tinywarden.crt` | 証明書 |
| `GET /progress` | インポートの進み具合（件数だけ）、起動からの時間、前回の再起動の理由、内部メモリ。2秒ごとに読み直すヘッダー付き |
| ほか | `https://192.168.237.1/alive` へ転送 |

### 開発用ビルドだけ

`firmware/sdkconfig`（gitに入れない）で有効にする。共有の既定値 `sdkconfig.defaults` では無効。本物の保管庫には使わない。

| 設定 | 中身 |
|---|---|
| `CONFIG_TW_DEV_DOWNLOAD_ENDPOINT` | `POST /tw/dev/selftest?n=900`（偽の約1.5KBの記録をn件書き、速さとメモリを `/progress` に出す）、`POST /tw/dev/selftest-clean`（それを消す）、`POST /tw/dev/reboot`（再起動）、`POST /tw/dev/download-mode`（書き込みモードで再起動。動かない。DECISIONS参照） |
| `CONFIG_TW_DEV_SKIP_BUTTON` | ボタンを待たずに許可する。管理ページに赤字で出す |

作らないもの: `/notifications/hub`（404）、アイコン、添付ファイル、組織、Send、2要素認証、緊急アクセス、ウェブの保管庫。

### 項目の保存のしかた

拡張機能から来たJSONをそのまま元にして、サーバーが持つ欄だけ足して保存し、そのまま返す。中身（暗号文）は読まない。

足す欄: `object: "cipherDetails"`、`id`、`creationDate`、`revisionDate`、`deletedDate`、`archivedDate: null`、`organizationId: null`、`collectionIds: []`、`attachments: null`、`organizationUseTotp: true`、`edit: true`、`viewPassword: true`、`permissions: {delete: true, restore: true}`、無ければ `folderId: null`・`favorite: false`・`reprompt: 0`・`key: null`。消す欄: `lastKnownRevisionDate`。

更新（`PUT /api/ciphers/<id>`、`POST /api/ciphers/<id>`）では、本文の `lastKnownRevisionDate` が、保存されている項目の `revisionDate` より1秒を超えて古ければ、保存せずに400「The client copy of this cipher is out of date. Resync the client and try again.」を返す（Vaultwardenと同じ）。`lastKnownRevisionDate` が無いときは確かめない。

### エラーの形

`message`、`validationErrors: {"": [message]}`、`ErrorModel` を返す。ただし、インポートのエラーは `validationErrors: null` にする。

## 8. 管理ページ（`https://192.168.237.1/`）

ログインなしで開ける。メールアドレスと保管庫の中身は出さない。

- 保管庫: ユーザーがいるか、項目とフォルダの数、保存領域（容量・使用・空き）、あと何件入るかの目安（1件2,200バイトとして）、古い版の量と区画の空き、起動時の読み込みの時間（書きかけの記録を捨てたか）、最後のインポートの結果、インポート1回の上限
- 機器: ファームウェアの版とビルド日時、起動からの時間、前回の再起動の理由、80番の状態、内部メモリとPSRAMの空き（起動後の最小も）、証明書のSHA-256
- 直近の通信: 20件。方法、パス（`?` から後ろは捨てる）、結果、エラーの文章、アプリの名前と版（`Bitwarden-Client-Name`、`Bitwarden-Client-Version`）
- つないできたアプリ: 起動してから見たアプリを、名前・版・`Device-Type` の組ごとに6つまで。回数、最初と最後の時刻、最後のログイン失敗（`/identity/` で2xx以外）とその文章。メモリだけに持つ
- 見出しなどの値はアプリから来るので、英数字と ` ._-+()` 以外は `?` にしてから出す。パスの `<>&"'` も `?` にする
- 最近の変更: 20件
- 鍵を作る計算（KDF）: 今の種類と設定。PBKDF2のままなら赤字で、Argon2idに変えるよう出す
- 控えを保存: メールとマスターパスワード（ブラウザの中でPBKDF2かArgon2idで計算し、ログイン用のハッシュだけを送る）、本体のボタン
- 鍵を作る計算を変える: メールとマスターパスワード、変えた後の種類（Argon2id メモリ32MB・6回・並列4 が初期値、PBKDF2 60万回）。ページが `/tw/kdf/key` で今の包みを受け取り、ブラウザの中でユーザーキーを開けて新しいマスターキーで包み直し、開け直して確かめてから `/tw/kdf` に送る。マスターパスワードとユーザーキーは機器に届かない
- 全部消す: 「消去」と入力するとボタンが押せる。押したあと30秒以内に本体のボタンを押すと消える
- スクリプトは `/web/status.js` から読む（ページの中には書かない）。ページには `Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` を付ける

## 9. インポート

```
{"ciphers": [...], "folders": [{"name", "id"?}], "folderRelationships": [{"key": 項目の番号, "value": フォルダの番号}]}
```

- 届いた全体をPSRAMに置き、項目を1件ずつ取り出してJSONにする
- 受けられる大きさ ＝ PSRAMで今取れる一番大きい塊 − 256KB
- 書く前に、全部入るか計算する。足りなければ1件も書かずに断る
- フォルダは、`id` が既にあればそれを使い、無ければ作る
- 進み具合は `http://192.168.237.1/progress` に出す

## 10. 開発の道具

- `flash.sh`: ビルドして書き込み、そのままアプリを起動する。先に書き込みモードにしておく（BOOTを押したままRSTを押して離し、BOOTを離す）。`--wipe` で保管庫の区画も消す
- `test/host/test_logstore.c`: `logstore.c` をMac上で、NORフラッシュをまねて試す（ランダムな操作をモデルと比べる、容量いっぱいでの大掃除、書き込みや消去の途中での電源断）。`cc -std=c11 -O2 -Wall -Wextra -fsanitize=address,undefined -I../../firmware/main ../../firmware/main/logstore.c test_logstore.c -o t && ./t`（`./t 40` で電源断だけを40通りの乱数で）
- ログはUSBに出さない。管理ページと `/progress` に出す

## 11. 守り

- 機器を全部閉じる（セキュアブート、フラッシュ暗号化、ダウンロードモードとJTAGの無効化）のは、開発が終わってから新しい基板で、手作業でやる（eFuseを焼く操作は自動化しない）
- それまでは、基板を手に入れた人はフラッシュを読み出せる。マスターパスワードは長くする
- マスターパスワードと機器の両方を取られたら、中身は全部読まれる
- 拡張機能はパソコンの中にも保管庫のキャッシュを持つ。パソコンが乗っ取られたら、機器の強さは関係ない
- 機器が壊れたり、なくなったりしたときに備えて、バックアップを別の場所に持つ（MANUAL参照）
- 開発用ビルドを、本物の保管庫に使わない
