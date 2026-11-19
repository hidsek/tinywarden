#!/usr/bin/env python3
"""On-device test for tinywarden, run from the Mac against a plugged-in board.

Needs a development build (firmware/sdkconfig):
  CONFIG_TW_DEV_DOWNLOAD_ENDPOINT=y  (self-test and reboot endpoints)
  CONFIG_TW_DEV_SKIP_BUTTON=y        (registration, login and wipe without pressing BOOT)
and an empty board (no user). It creates a throwaway account, so never run it on a real vault.

  python3 -I test/device/device_test.py               # full run (about 10 minutes)
  python3 -I test/device/device_test.py --quick       # skip the GC stress rounds
  python3 -I test/device/device_test.py --wipe-first  # wipe the board before starting

The payload is synthetic: random bytes shaped like Bitwarden EncStrings. The board never decrypts
anything, so this exercises the same paths as a real vault of the same size.
"""
import argparse
import base64
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://192.168.237.1"
HTTP = "http://192.168.237.1"
EMAIL = "device-test@example.invalid"
PW_HASH = base64.b64encode(b"device-test-master-password-hash").decode()
DEVICE_ID = "11111111-2222-3333-4444-555555555555"

CTX = ssl.create_default_context()
CTX.check_hostname = False  # the board's certificate is for an IP; trust is not what we test here
CTX.verify_mode = ssl.CERT_NONE

results = []


def req(method, url, body=None, headers=None, timeout=60):
    data = None
    h = dict(headers or {})
    if isinstance(body, (dict, list)):
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        data = body.encode()
    elif isinstance(body, bytes):
        data = body
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, context=CTX if url.startswith("https") else None, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    return ok


def status_page():
    code, body = req("GET", BASE + "/")
    return code, body.decode("utf-8", "replace")


def login():
    form = urllib.parse.urlencode({
        "grant_type": "password", "username": EMAIL, "password": PW_HASH, "scope": "api offline_access",
        "client_id": "web", "deviceType": "10", "deviceIdentifier": DEVICE_ID, "deviceName": "device-test",
    })
    code, body = req("POST", BASE + "/identity/connect/token", form,
                     {"Content-Type": "application/x-www-form-urlencoded"})
    tok = json.loads(body).get("access_token") if code == 200 else None
    return code, tok


def sync(tok):
    t0 = time.time()
    code, body = req("GET", BASE + "/api/sync", headers={"Authorization": "Bearer " + tok}, timeout=300)
    return code, (json.loads(body) if code == 200 else None), time.time() - t0


def enc(n):
    b = lambda k: base64.b64encode(os.urandom(k)).decode()
    return f"2.{b(16)}|{b(n)}|{b(32)}"


def make_import(n_items=800, n_folders=3, seed=1):
    """Shaped like a typical vault: 750 logins, 40 cards, 10 notes per 800 items."""
    random.seed(seed)
    ciphers = []
    for i in range(n_items):
        t = 1 if i < n_items * 750 // 800 else (3 if i < n_items * 790 // 800 else 2)
        c = {"type": t, "name": enc(24), "notes": enc(random.choice([0, 200, 600])) if random.random() < 0.3 else None,
             "favorite": False, "reprompt": 0, "folderId": None, "organizationId": None, "key": enc(64)}
        if t == 1:
            c["login"] = {"username": enc(24), "password": enc(32), "totp": None,
                          "uris": [{"uri": enc(48), "match": None}], "fido2Credentials": []}
        elif t == 3:
            c["card"] = {k: enc(16) for k in ("cardholderName", "number", "expMonth", "expYear", "code", "brand")}
        else:
            c["secureNote"] = {"type": 0}
        c["passwordHistory"] = [{"password": enc(32), "lastUsedDate": "2026-01-01T00:00:00Z"}] if random.random() < 0.3 else None
        ciphers.append(c)
    folders = [{"name": enc(16)} for _ in range(n_folders)]
    rels = [{"key": i, "value": i % n_folders} for i in range(0, n_items, 4)]
    return {"ciphers": ciphers, "folders": folders, "folderRelationships": rels}


def wait_alive(seconds=60):
    for _ in range(seconds // 2):
        try:
            if req("GET", BASE + "/alive", timeout=3)[0] == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def selftest_round(n):
    req("POST", f"{BASE}/tw/dev/selftest?n={n}")
    for _ in range(400):
        _, body = req("GET", HTTP + "/progress", timeout=5)
        text = body.decode()
        if f"writing {n} synthetic" in text and ("done in" in text or "FAILED" in text):
            return text
        time.sleep(3)
    return "timeout"


def norm(c):
    return json.dumps({k: v for k, v in c.items() if k != "revisionDate"}, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip the GC stress rounds")
    ap.add_argument("--wipe-first", action="store_true", help="wipe the board before starting")
    ap.add_argument("--items", type=int, default=800)
    args = ap.parse_args()

    # 0. Preconditions
    code, page = status_page()
    if not check("status page answers", code == 200, f"HTTP {code}"):
        return finish()
    if not check("development build with button skip", "BOOTボタンの確認を省略中" in page,
                 "flash a build with CONFIG_TW_DEV_SKIP_BUTTON=y"):
        return finish()
    if args.wipe_first:
        code, _ = req("POST", BASE + "/tw/wipe", headers={"X-Tinywarden-Confirm": "wipe-all"}, timeout=120)
        check("wipe before start", code == 200, f"HTTP {code}")
    code, body = req("GET", BASE + "/api/config")
    if not check("board is empty (registration open)", code == 200 and not json.loads(body)["settings"]["disableUserRegistration"],
                 "use --wipe-first"):
        return finish()

    # 1. Registration and login
    code, body = req("POST", BASE + "/identity/accounts/register/send-verification-email",
                     {"email": EMAIL, "name": "device test"}, {"Accept": "application/json"})
    token = json.loads(body) if code == 200 else ""
    check("registration token is 43 chars", code == 200 and len(token) == 43, f"len {len(token)}")
    code, _ = req("POST", BASE + "/identity/accounts/register/finish", {
        "email": EMAIL, "emailVerificationToken": token, "masterPasswordHash": PW_HASH, "masterPasswordHint": None,
        "userSymmetricKey": enc(64), "userAsymmetricKeys": {"publicKey": "PUB", "encryptedPrivateKey": enc(256)},
        "kdf": 0, "kdfIterations": 600000})
    check("register", code == 200, f"HTTP {code}")
    code, tok = login()
    if not check("login", code == 200 and tok, f"HTTP {code}"):
        return finish()
    code, wrong = req("POST", BASE + "/identity/connect/token", urllib.parse.urlencode({
        "grant_type": "password", "username": EMAIL, "password": base64.b64encode(b"wrong").decode(),
        "scope": "api offline_access", "client_id": "web", "deviceType": "10", "deviceIdentifier": DEVICE_ID}),
        {"Content-Type": "application/x-www-form-urlencoded"})
    check("wrong password is rejected", code == 400, f"HTTP {code}")
    login()  # resets the failure counter
    code, s, _ = sync(tok)
    check("sync of an empty vault", code == 200 and s["ciphers"] == [] and s["folders"] == [])

    # 2. Import
    code, body = req("POST", BASE + "/api/ciphers/import", b"{not json", {"Authorization": "Bearer " + tok,
                                                                           "Content-Type": "application/json"})
    err = json.loads(body) if body.startswith(b"{") else {}
    check("broken import is rejected without validationErrors", code == 400 and err.get("validationErrors") is None,
          err.get("message", ""))
    data = make_import(args.items)
    payload = json.dumps(data).encode()
    t0 = time.time()
    code, body = req("POST", BASE + "/api/ciphers/import", payload,
                     {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, timeout=900)
    dt = time.time() - t0
    check(f"import {args.items} items", code == 200, f"HTTP {code}, {len(payload) // 1024} KB, {dt:.1f} s")
    code, s1, dts = sync(tok)
    n_folder = sum(1 for c in (s1 or {}).get("ciphers", []) if c.get("folderId"))
    check("sync after import: item and folder counts", code == 200 and len(s1["ciphers"]) == args.items
          and len(s1["folders"]) == 3, f"{len(s1['ciphers']) if s1 else '?'} items, {dts:.1f} s")
    check("folder assignments kept", n_folder == len(data["folderRelationships"]), f"{n_folder}")
    types = {t: sum(1 for c in s1["ciphers"] if c["type"] == t) for t in (1, 2, 3)}
    check("item types kept", types == {t: sum(1 for c in data["ciphers"] if c["type"] == t) for t in (1, 2, 3)}, str(types))

    # 3. Edit and delete
    first, second = s1["ciphers"][0], s1["ciphers"][1]
    edited = dict(first, name="2.EDITED|EDITED|EDITED")
    code, _ = req("PUT", f"{BASE}/api/ciphers/{first['id']}", edited, {"Authorization": "Bearer " + tok})
    check("edit one item", code == 200, f"HTTP {code}")
    code, _ = req("DELETE", f"{BASE}/api/ciphers/{second['id']}", headers={"Authorization": "Bearer " + tok})
    check("delete one item", code == 200, f"HTTP {code}")
    expected = {c["id"]: c for c in s1["ciphers"] if c["id"] != second["id"]}
    expected[first["id"]] = None  # edited; compared by name below

    def compare(label, s):
        got = {c["id"]: c for c in s["ciphers"]}
        missing = [i for i in expected if i not in got]
        changed = [i for i, c in expected.items() if c is not None and i in got and norm(c) != norm(got[i])]
        ok = not missing and not changed and second["id"] not in got and got.get(first["id"], {}).get("name") == edited["name"]
        check(label, ok, f"{len(got)} items, missing {len(missing)}, changed {len(changed)}")

    code, s2, _ = sync(tok)
    compare("vault after edit and delete", s2)

    # 4. Reboot: the vault is read back from flash
    req("POST", BASE + "/tw/dev/reboot")
    time.sleep(4)
    check("board comes back after reboot", wait_alive())
    code, old = sync(tok)[:2]
    check("old token is rejected after reboot (per-boot signing key)", code == 401, f"HTTP {code}")
    code, tok = login()
    code, s3, _ = sync(tok)
    compare("vault after reboot", s3)

    # 5. GC stress: fill the store with self-test records and delete them, three times
    if not args.quick:
        for r in range(3):
            text = selftest_round(900)
            line = next((l for l in text.splitlines() if "done in" in l or "FAILED" in l), text[-120:])
            check(f"GC stress round {r + 1}: 900 records written", "done in" in text, line.strip())
            code, body = req("POST", BASE + "/tw/dev/selftest-clean", timeout=600)
            check(f"GC stress round {r + 1}: cleaned", code == 200, body.decode().strip())
        code, s4, _ = sync(tok)
        compare("vault after GC stress", s4)

    # 6. Leave the board empty
    code, _ = req("POST", BASE + "/tw/wipe", headers={"X-Tinywarden-Confirm": "wipe-all"}, timeout=120)
    check("wipe at the end", code == 200, f"HTTP {code}")
    return finish()


def finish():
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
