#!/usr/bin/env python3
"""tinywarden backup and offline decryption, without any Bitwarden app.

If an app or extension update ever stops logging in to tinywarden, the vault can still be read:

  python3 -I tools/tw_backup.py fetch backup.json      # log in (press BOOT), save the encrypted vault
  python3 -I tools/tw_backup.py decrypt backup.json export.json   # master password -> plain JSON

fetch saves the vault exactly as the board serves it: still encrypted, safe to keep like an
encrypted export. decrypt runs offline and writes a Bitwarden password-protected JSON export (asks
for a new file password), which Bitwarden and Vaultwarden import directly. Nothing unencrypted is
written to disk. --plain writes the unencrypted JSON export instead (import it, then delete it).

Only the Python standard library is used (AES is implemented below), so this keeps working without
installing anything. Argon2id accounts need `pip install argon2-cffi`; PBKDF2 (the default) does not.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://192.168.237.1"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CA = os.path.join(HERE, "..", "certs", "tinywarden.crt")
DEVICE_ID = "7f3c1e2a-0b8d-4c6e-9a51-00000000b0c0"

# ---------------------------------------------------------------- AES-256-CBC decryption

def _xt(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _mul(a, b) == 1:
                inv[a] = b
                break
    s = []
    for a in range(256):
        x = inv[a]
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        s.append(y ^ 0x63)
    return s


SBOX = _sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
M9, M11, M13, M14 = ([_mul(x, k) for x in range(256)] for k in (9, 11, 13, 14))


def _expand_key(key):
    assert len(key) == 32
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xt(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(15)]


def _decrypt_block(rk, block):
    s = [a ^ b for a, b in zip(block, rk[14])]
    for r in range(13, -1, -1):
        s = [s[(i + 4 * (i % 4) * 3) % 16] for i in range(16)]  # inverse ShiftRows (column-major)
        s = [INV_SBOX[b] for b in s]
        s = [a ^ b for a, b in zip(s, rk[r])]
        if r:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3], M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3],
                        M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3], M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3]]
            s = out
    return bytes(s)


def _encrypt_block(rk, block):
    s = [a ^ b for a, b in zip(block, rk[0])]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major)
        if r < 14:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [_xt(a0) ^ _xt(a1) ^ a1 ^ a2 ^ a3, a0 ^ _xt(a1) ^ _xt(a2) ^ a2 ^ a3,
                        a0 ^ a1 ^ _xt(a2) ^ _xt(a3) ^ a3, _xt(a0) ^ a0 ^ a1 ^ a2 ^ _xt(a3)]
            s = out
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(s)


def aes256_cbc_encrypt(key, iv, data):
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    rk = _expand_key(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        prev = _encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)


def aes256_cbc_decrypt(key, iv, data):
    if len(data) == 0 or len(data) % 16:
        raise ValueError("bad ciphertext length")
    rk = _expand_key(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(rk, blk), prev))
        prev = blk
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return bytes(out[:-pad])

# ---------------------------------------------------------------- Bitwarden key derivation

def master_key(password, email, kdf):
    pw = password.encode()
    salt = email.strip().lower().encode()
    kind = kdf.get("kdf", 0)
    if kind == 0:
        return hashlib.pbkdf2_hmac("sha256", pw, salt, int(kdf["kdfIterations"]), 32)
    if kind == 1:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            sys.exit("This account uses Argon2id. Install it first: pip install argon2-cffi")
        return hash_secret_raw(pw, hashlib.sha256(salt).digest(), time_cost=int(kdf["kdfIterations"]),
                               memory_cost=int(kdf["kdfMemory"]) * 1024, parallelism=int(kdf["kdfParallelism"]),
                               hash_len=32, type=Type.ID)
    sys.exit(f"unknown KDF type {kind}")


def password_hash(mk, password):
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32)).decode()


def stretch(mk):
    # HKDF-Expand (no extract step), SHA-256, one block each
    return (hmac.new(mk, b"enc\x01", hashlib.sha256).digest(), hmac.new(mk, b"mac\x01", hashlib.sha256).digest())


ENC_RE = re.compile(r"^2\.([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)$")


class MacError(Exception):
    pass


def dec(s, keys):
    m = ENC_RE.match(s)
    if not m:
        raise ValueError("not an EncString of type 2")
    iv, ct, mac = (base64.b64decode(x) for x in m.groups())
    enc_key, mac_key = keys
    if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac):
        raise MacError()
    return aes256_cbc_decrypt(enc_key, iv, ct)


def enc(data, keys):
    if isinstance(data, str):
        data = data.encode("utf-8")
    enc_key, mac_key = keys
    iv = os.urandom(16)
    ct = aes256_cbc_encrypt(enc_key, iv, data)
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ct, mac))


def password_protected_export(clear_text, file_password, iterations=600000):
    """Bitwarden's password-protected JSON export (clients: BaseVaultExportService.buildPasswordExport):
    key = stretch(PBKDF2-SHA256(password, salt as its base64 string, iterations))."""
    salt = base64.b64encode(os.urandom(16)).decode()
    mk = hashlib.pbkdf2_hmac("sha256", file_password.encode(), salt.encode(), iterations, 32)
    keys = stretch(mk)
    import uuid
    return {"encrypted": True, "passwordProtected": True, "salt": salt, "kdfType": 0,
            "kdfIterations": iterations, "encKeyValidation_DO_NOT_EDIT": enc(str(uuid.uuid4()), keys),
            "data": enc(clear_text, keys)}


def split64(b):
    if len(b) != 64:
        raise ValueError(f"key of {len(b)} bytes, expected 64")
    return b[:32], b[32:]

# ---------------------------------------------------------------- talking to the board

def ctx(cafile):
    # Checks the chain against the tinywarden CA and the IP in the certificate (SAN IP:192.168.237.1)
    return ssl.create_default_context(cafile=cafile)


def http(method, path, cafile, body=None, headers=None, timeout=60):
    data = None
    h = dict(headers or {})
    if isinstance(body, dict):
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    elif isinstance(body, str):
        data = body.encode()
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, context=ctx(cafile), timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def cmd_fetch(a):
    email = input("Email: ").strip()
    password = getpass.getpass("Master password: ")
    code, body = http("POST", "/identity/accounts/prelogin", a.cafile, {"email": email})
    if code != 200:
        sys.exit(f"prelogin failed: HTTP {code} {body[:200]!r}")
    pre = json.loads(body)
    mk = master_key(password, email, pre)
    form = urllib.parse.urlencode({
        "grant_type": "password", "username": email, "password": password_hash(mk, password),
        "scope": "api offline_access", "client_id": "cli", "deviceType": "14",
        "deviceIdentifier": DEVICE_ID, "deviceName": "tw_backup"})
    print("Press BOOT on the tinywarden when it blinks (30 seconds)...")
    code, body = http("POST", "/identity/connect/token", a.cafile, form,
                      {"Content-Type": "application/x-www-form-urlencoded",
                       "Bitwarden-Client-Name": "tw_backup", "Bitwarden-Client-Version": "1"}, timeout=60)
    if code != 200:
        msg = json.loads(body).get("ErrorModel", {}).get("Message", "") if body.startswith(b"{") else body[:200]
        sys.exit(f"login failed: HTTP {code} {msg}")
    tok = json.loads(body)["access_token"]
    code, body = http("GET", "/api/sync", a.cafile, headers={"Authorization": "Bearer " + tok,
                      "Bitwarden-Client-Name": "tw_backup", "Bitwarden-Client-Version": "1"}, timeout=600)
    if code != 200:
        sys.exit(f"sync failed: HTTP {code}")
    sync = json.loads(body)
    out = {"tinywarden_backup": 1, "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "email": email, "prelogin": pre, "sync": sync}
    with open(a.out, "w") as f:
        json.dump(out, f)
    n = len(sync.get("ciphers", []))
    # Prove the file can be decrypted while the password is at hand
    keys = user_keys(sync, mk)
    print(f"saved {n} items and {len(sync.get('folders', []))} folders to {a.out} (still encrypted)")
    if keys:
        print("checked: this master password decrypts the backup")

# ---------------------------------------------------------------- decryption to Bitwarden's export

def lower_first(o):
    if isinstance(o, dict):
        return {(k[:1].lower() + k[1:]): lower_first(v) for k, v in o.items()}
    if isinstance(o, list):
        return [lower_first(v) for v in o]
    return o


def user_keys(sync, mk):
    sync = lower_first(sync)
    enc = sync.get("profile", {}).get("key")
    if not enc:
        enc = (sync.get("userDecryption", {}).get("masterPasswordUnlock", {}) or {}).get("masterKeyEncryptedUserKey")
    if not enc:
        sys.exit("no encrypted user key in the backup")
    try:
        return split64(dec(enc, stretch(mk)))
    except MacError:
        sys.exit("wrong master password (or wrong email)")


def dec_tree(o, keys):
    if isinstance(o, str) and ENC_RE.match(o):
        return dec(o, keys).decode("utf-8")
    if isinstance(o, dict):
        return {k: dec_tree(v, keys) for k, v in o.items()}
    if isinstance(o, list):
        return [dec_tree(v, keys) for v in o]
    return o


DROP = {"key", "object", "edit", "viewPassword", "permissions", "organizationUseTotp", "attachments",
        "collectionIds", "data", "uriChecksum"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in DROP}
    if isinstance(o, list):
        return [strip(v) for v in o]
    return o


def cmd_decrypt(a):
    with open(a.backup) as f:
        b = json.load(f)
    if b.get("tinywarden_backup") != 1:
        sys.exit("not a tw_backup file")
    sync = lower_first(b["sync"])
    password = getpass.getpass("Master password: ")
    keys = user_keys(sync, master_key(password, b["email"], b["prelogin"]))
    folders = [{"id": f["id"], "name": dec(f["name"], keys).decode()} for f in sync.get("folders", [])]
    items, skipped = [], 0
    for c in sync.get("ciphers", []):
        if c.get("deletedDate") or c.get("organizationId"):
            skipped += 1
            continue
        k = split64(dec(c["key"], keys)) if c.get("key") else keys
        item = dec_tree(strip(c), k)  # strip first: "key" is under the user key, not the item key
        item["collectionIds"] = None
        items.append(item)
    plain = {"encrypted": False, "folders": folders, "items": items}
    if a.plain:
        doc, note = plain, "THIS FILE IS NOT ENCRYPTED. Import it, then delete it."
    else:
        while True:
            fpw = getpass.getpass("New password for the export file (12+ characters): ")
            if len(fpw) < 12:
                print("too short")
                continue
            if getpass.getpass("Again: ") == fpw:
                break
            print("did not match")
        doc = password_protected_export(json.dumps(plain, ensure_ascii=False), fpw)
        note = "Password-protected Bitwarden export. Import it with the file password."
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"wrote {len(items)} items and {len(folders)} folders to {a.out}"
          + (f" (skipped {skipped} in the trash or in an organization)" if skipped else ""))
    print(note)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="log in to the board and save the encrypted vault")
    f.add_argument("out")
    f.add_argument("--cafile", default=DEFAULT_CA, help="tinywarden CA certificate (default: certs/tinywarden.crt)")
    d = sub.add_parser("decrypt", help="decrypt a saved backup into Bitwarden's JSON export (offline)")
    d.add_argument("backup")
    d.add_argument("out")
    d.add_argument("--plain", action="store_true", help="write the unencrypted JSON export instead")
    a = ap.parse_args()
    {"fetch": cmd_fetch, "decrypt": cmd_decrypt}[a.cmd](a)


if __name__ == "__main__":
    main()
