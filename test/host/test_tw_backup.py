#!/usr/bin/env python3
"""Checks tools/tw_backup.py: its AES against openssl, and a full decrypt of a synthetic backup
encrypted with openssl the way Bitwarden clients encrypt.  python3 -I test/host/test_tw_backup.py"""
import base64, hashlib, hmac, json, os, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import tw_backup as tb

def ossl_enc(key, iv, data):
    return subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()],
                          input=data, capture_output=True, check=True).stdout

def enc(data, keys):
    if isinstance(data, str): data = data.encode()
    iv = os.urandom(16); ct = ossl_enc(keys[0], iv, data)
    mac = hmac.new(keys[1], iv + ct, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ct, mac))

fails = 0
def check(name, ok):
    global fails
    print(("PASS " if ok else "FAIL ") + name); fails += not ok

# 1. AES against openssl, lengths 0..70
ok = True
for n in list(range(0, 71)) + [1000, 4096]:
    key, iv, pt = os.urandom(32), os.urandom(16), os.urandom(n)
    ok &= tb.aes256_cbc_decrypt(key, iv, ossl_enc(key, iv, pt)) == pt
check("AES-256-CBC decrypt matches openssl (73 lengths)", ok)

# 2. FIPS-197 C.3 AES-256 known answer (one block)
k = bytes(range(32)); pt = bytes.fromhex("00112233445566778899aabbccddeeff")
ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
check("AES-256 FIPS-197 known answer", tb._decrypt_block(tb._expand_key(k), ct) == pt)
check("AES-256 FIPS-197 known answer (encrypt)", tb._encrypt_block(tb._expand_key(k), pt) == ct)
ok = True
for n in list(range(0, 40)) + [1000]:
    key, iv, pt2 = os.urandom(32), os.urandom(16), os.urandom(n)
    ct2 = tb.aes256_cbc_encrypt(key, iv, pt2)
    ok &= ct2 == ossl_enc(key, iv, pt2)
check("AES-256-CBC encrypt matches openssl (41 lengths)", ok)

# 3. Full synthetic vault
email, pw = "Someone@Example.com ", "correct horse battery staple"
pre = {"kdf": 0, "kdfIterations": 600000}
mk = tb.master_key(pw, email, pre)
user = os.urandom(64); ukeys = (user[:32], user[32:])
item = os.urandom(64); ikeys = (item[:32], item[32:])
sync = {"profile": {"key": enc(user, tb.stretch(mk)), "email": email},
        "folders": [{"id": "f1", "name": enc("仕事", ukeys)}],
        "ciphers": [
          {"id": "c1", "type": 1, "folderId": "f1", "key": enc(item, ukeys), "name": enc("銀行", ikeys),
           "notes": None, "favorite": True, "reprompt": 0, "organizationId": None, "deletedDate": None,
           "login": {"username": enc("me", ikeys), "password": enc("p@ss|w0rd", ikeys), "totp": None,
                     "uris": [{"uri": enc("https://bank.example", ikeys), "match": None, "uriChecksum": enc("x", ikeys)}]},
           "fields": [{"name": enc("PIN", ikeys), "value": enc("1234", ikeys), "type": 1, "linkedId": None}],
           "object": "cipherDetails", "edit": True},
          {"id": "c2", "type": 2, "name": enc("メモ", ukeys), "notes": enc("長い\nメモ", ukeys), "secureNote": {"type": 0},
           "organizationId": None, "deletedDate": None},
          {"id": "c3", "type": 1, "name": enc("trash", ukeys), "deletedDate": "2026-01-01T00:00:00Z", "organizationId": None}]}
with tempfile.TemporaryDirectory() as d:
    bpath, opath = os.path.join(d, "b.json"), os.path.join(d, "o.json")
    json.dump({"tinywarden_backup": 1, "email": email, "prelogin": pre, "sync": sync}, open(bpath, "w"))
    import getpass
    getpass.getpass = lambda prompt="": pw
    tb.cmd_decrypt(type("A", (), {"backup": bpath, "out": opath, "plain": True}))
    out = json.load(open(opath))
    check("output file is private (0600)", oct(os.stat(opath).st_mode & 0o777) == "0o600")
    i1 = next(i for i in out["items"] if i["id"] == "c1")
    check("folder name", out["folders"] == [{"id": "f1", "name": "仕事"}])
    check("item with its own key", i1["name"] == "銀行" and i1["login"]["password"] == "p@ss|w0rd"
          and i1["login"]["uris"][0]["uri"] == "https://bank.example" and i1["fields"][0]["value"] == "1234")
    check("server-only fields dropped", "key" not in i1 and "object" not in i1 and "uriChecksum" not in i1["login"]["uris"][0])
    check("note with the user key", next(i for i in out["items"] if i["id"] == "c2")["notes"] == "長い\nメモ")
    check("trash skipped", len(out["items"]) == 2 and out["encrypted"] is False)
    # Default output: password-protected export, as Bitwarden's importer reads it
    answers = iter([pw, "file-password-123", "file-password-123"])
    getpass.getpass = lambda prompt="": next(answers)
    ppath = os.path.join(d, "p.json")
    tb.cmd_decrypt(type("A", (), {"backup": bpath, "out": ppath, "plain": False}))
    pdoc = json.load(open(ppath))
    check("protected export has Bitwarden's fields", pdoc["encrypted"] is True and pdoc["passwordProtected"] is True
          and pdoc["kdfType"] == 0 and pdoc["kdfIterations"] == 600000 and len(base64.b64decode(pdoc["salt"])) == 16)
    fkeys = tb.stretch(hashlib.pbkdf2_hmac("sha256", b"file-password-123", pdoc["salt"].encode(), 600000, 32))
    tb.dec(pdoc["encKeyValidation_DO_NOT_EDIT"], fkeys)
    inner = json.loads(tb.dec(pdoc["data"], fkeys))
    check("protected export decrypts to the same plain export", inner == out)
    check("no plain text in the protected file", "銀行" not in open(ppath).read() and "p@ss" not in open(ppath).read())
    getpass.getpass = lambda prompt="": "wrong"
    try:
        tb.cmd_decrypt(type("A", (), {"backup": bpath, "out": opath, "plain": True})); check("wrong password rejected", False)
    except SystemExit as e:
        check("wrong password rejected", "wrong master password" in str(e))
print(f"\n{'all passed' if not fails else f'{fails} failed'}"); sys.exit(1 if fails else 0)
