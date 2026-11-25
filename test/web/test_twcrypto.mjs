// Tests for firmware/web/twcrypto.js (the browser crypto the board's pages use). Node 20+ (WebCrypto).
//   node test/web/test_twcrypto.mjs
// Checks Argon2id against RFC 9106 and OpenSSL, and the export format against tools/tw_backup.py.
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as tw from "../../firmware/web/twcrypto.js";
import { argon2id } from "../../firmware/web/vendor/noble-hashes/argon2.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const hex = (u8) => Buffer.from(u8).toString("hex");
let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log("ok  ", name); } catch (e) { failed++; console.log("FAIL", name, "-", e.message); }
}
function eq(a, b, what = "value") {
  const sa = JSON.stringify(a), sb = JSON.stringify(b);
  if (sa !== sb) throw new Error(`${what}: ${sa.slice(0, 120)} != ${sb.slice(0, 120)}`);
}
async function rejects(p, cls) {
  try { await p; } catch (e) { if (!cls || e instanceof cls) return; throw new Error(`threw ${e.name}, expected ${cls.name}`); }
  throw new Error("did not throw");
}
function python(code, input) {
  return execFileSync("python3", ["-I", "-c", `import sys; sys.path.insert(0, ${JSON.stringify(path.join(root, "tools"))})\n` + code],
    { input, encoding: "utf8" });
}

await check("Argon2id: RFC 9106 section 5.3 test vector", async () => {
  const tag = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2),
    { t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4) });
  eq(hex(tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", "tag");
});

await check("Argon2id master key with the clients' settings equals OpenSSL", async () => {
  const cfg = { kdf: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4 };
  const mk = await tw.masterKey("correct horse battery staple", "  User@Example.com ", cfg);
  let ref;
  try {
    const salt = hex(await tw.sha256(new TextEncoder().encode("user@example.com")));
    ref = execFileSync("openssl", ["kdf", "-keylen", "32", "-kdfopt", "pass:correct horse battery staple",
      "-kdfopt", `hexsalt:${salt}`, "-kdfopt", "iter:6", "-kdfopt", "memcost:32768", "-kdfopt", "lanes:4",
      "-kdfopt", "threads:1", "ARGON2ID"], { encoding: "utf8" }).trim().replace(/:/g, "").toLowerCase();
  } catch (e) {
    console.log("     (OpenSSL 3.2+ with ARGON2ID not available, skipped)");
    return;
  }
  eq(hex(mk), ref, "master key");
});

await check("PBKDF2 master key and login hash equal tw_backup.py", async () => {
  const cfg = { kdf: 0, kdfIterations: 600000 };
  const mk = await tw.masterKey("pässwörd", "Me@Example.com", cfg);
  const h = await tw.masterPasswordHash(mk, "pässwörd");
  const ref = python(`import tw_backup, json
mk = tw_backup.master_key("pässwörd", "Me@Example.com", {"kdf": 0, "kdfIterations": 600000})
print(json.dumps([mk.hex(), tw_backup.password_hash(mk, "pässwörd")]))`);
  eq([hex(mk), h], JSON.parse(ref));
});

await check("stretch equals tw_backup.py", async () => {
  const k = new Uint8Array(32).map((_, i) => i);
  const s = await tw.stretch(k);
  const ref = JSON.parse(python(`import tw_backup, json
e, m = tw_backup.stretch(bytes(range(32)))
print(json.dumps([e.hex(), m.hex()]))`));
  eq([hex(s.enc), hex(s.mac)], ref);
});

await check("EncString round trip, tamper and wrong key are refused", async () => {
  const keys = tw.splitKey(crypto.getRandomValues(new Uint8Array(64)));
  const s = await tw.enc("日本語 and emoji 🔑", keys);
  eq(await tw.decString(s, keys), "日本語 and emoji 🔑");
  const parts = s.split("|");
  const bad = parts[0] + "|" + parts[1].replace(/^./, (c) => (c === "A" ? "B" : "A")) + "|" + parts[2];
  await rejects(tw.decString(bad, keys), tw.MacError);
  await rejects(tw.decString(s, tw.splitKey(crypto.getRandomValues(new Uint8Array(64)))), tw.MacError);
});

const plain = {
  encrypted: false,
  folders: [{ id: "f1", name: "仕事" }],
  items: [{ id: "i1", type: 1, name: "example", folderId: "f1", notes: null,
    login: { username: "me", password: "p@ss", uris: [{ uri: "https://example.com", match: null }] } }],
};

await check("password-protected export (Argon2id) round trip, wrong password refused", async () => {
  const cfg = { kdfType: 1, iterations: 2, memory: 16, parallelism: 1 };
  const doc = await tw.makeProtectedExport(plain, "file password 1", cfg);
  eq([doc.kdfType, doc.kdfIterations, doc.kdfMemory, doc.kdfParallelism], [1, 2, 16, 1], "kdf fields");
  eq(await tw.openProtectedExport(doc, "file password 1"), plain);
  await rejects(tw.openProtectedExport(doc, "wrong"), tw.MacError);
});

await check("password-protected export made by tw_backup.py opens here", async () => {
  const doc = JSON.parse(python(`import tw_backup, json
print(json.dumps(tw_backup.password_protected_export(sys.stdin.read(), "file password 2", 5000)))`, JSON.stringify(plain)));
  eq(await tw.openProtectedExport(doc, "file password 2"), plain);
});

await check("password-protected export made here (PBKDF2) opens in Python", async () => {
  const doc = await tw.makeProtectedExport(plain, "file password 3", { kdfType: 0, iterations: 5000 });
  const out = python(`import tw_backup, json, hashlib
d = json.load(sys.stdin)
keys = tw_backup.stretch(hashlib.pbkdf2_hmac("sha256", b"file password 3", d["salt"].encode(), d["kdfIterations"], 32))
tw_backup.dec(d["encKeyValidation_DO_NOT_EDIT"], keys)
print(tw_backup.dec(d["data"], keys).decode())`, JSON.stringify(doc));
  eq(JSON.parse(out), plain);
});

await check("KDF settings outside the bounds are refused", async () => {
  for (const bad of [{ kdfType: 0, kdfIterations: 100 }, { kdfType: 1, kdfIterations: 3, kdfMemory: 4096, kdfParallelism: 4 },
    { kdfType: 1, kdfIterations: 1, kdfMemory: 32, kdfParallelism: 4 }, { kdfType: 7, kdfIterations: 3 }]) {
    let threw = false;
    try { tw.kdfConfig(bad); } catch { threw = true; }
    if (!threw) throw new Error("accepted " + JSON.stringify(bad));
  }
});

// A synthetic tinywarden backup, built the way the clients store a vault
async function makeBackup(password, email, prelogin) {
  const mk = await tw.masterKey(password, email, prelogin);
  const userKeyRaw = crypto.getRandomValues(new Uint8Array(64));
  const userKey = tw.splitKey(userKeyRaw);
  const itemKeyRaw = crypto.getRandomValues(new Uint8Array(64));
  const itemKey = tw.splitKey(itemKeyRaw);
  const E = (s, k) => tw.enc(s, k);
  return {
    tinywarden_backup: 1, saved: "2026-11-20T00:00:00Z", email, prelogin,
    sync: {
      Profile: { Key: await E(userKeyRaw, await tw.stretch(mk)) },
      Folders: [{ Id: "f1", Name: await E("仕事", userKey) }],
      Ciphers: [
        { Id: "i1", Type: 1, Key: await E(itemKeyRaw, userKey), Name: await E("with item key", itemKey), FolderId: "f1",
          Notes: null, Login: { Username: await E("me", itemKey), Password: await E("p1", itemKey),
            Uris: [{ Uri: await E("https://a.example", itemKey), Match: null }] }, Object: "cipherDetails", Edit: true },
        { Id: "i2", Type: 2, Name: await E("no item key", userKey), Notes: await E("note", userKey), SecureNote: { Type: 0 } },
        { Id: "i3", Type: 1, Name: await E("in trash", userKey), DeletedDate: "2026-11-01T00:00:00Z" },
      ],
    },
  };
}

for (const [label, prelogin] of [["PBKDF2", { kdf: 0, kdfIterations: 5000, kdfMemory: null, kdfParallelism: null }],
  ["Argon2id", { kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1 }]]) {
  await check(`tinywarden backup (${label}) decrypts to an export, wrong password refused`, async () => {
    const b = await makeBackup("master pw", "Me@Example.com", prelogin);
    const { plain: p, skipped } = await tw.openTwBackup(b, "master pw");
    eq(skipped, 1, "skipped");
    eq(p.folders, [{ id: "f1", name: "仕事" }], "folders");
    eq(p.items.map((i) => [i.id, i.name, i.login?.password ?? i.notes, i.login?.uris?.[0]?.uri ?? null]),
      [["i1", "with item key", "p1", "https://a.example"], ["i2", "no item key", "note", null]], "items");
    if ("key" in p.items[0] || "object" in p.items[0] || "edit" in p.items[0]) throw new Error("fields not stripped");
    await rejects(tw.openTwBackup(b, "wrong"), tw.MacError);
  });
}

await check("format 2 backup (no username in the file) needs the username", async () => {
  const b = await makeBackup("master pw", "Me@Example.com", { kdf: 0, kdfIterations: 5000, kdfMemory: null, kdfParallelism: null });
  delete b.email;
  b.tinywarden_backup = 2;
  if (!tw.isTwBackup(b) || !tw.twBackupNeedsUsername(b)) throw new Error("not recognised as format 2");
  await rejects(tw.openTwBackup(b, "master pw"), Error);
  const { plain: p } = await tw.openTwBackup(b, "master pw", undefined, " me@example.com ");
  eq(p.items.length, 2, "items");
  await rejects(tw.openTwBackup(b, "master pw", undefined, "someone-else@example.com"), tw.MacError);
});

// The locked page computes the login hash on its own (twcrypto.js is not served before unlocking)
const { loginHash } = await import("../../firmware/web/unlock.js");
for (const [label, pre] of [["PBKDF2", { kdf: 0, kdfIterations: 5000, kdfMemory: null, kdfParallelism: null }],
  ["Argon2id", { kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1 }]]) {
  await check(`unlock page login hash matches twcrypto (${label})`, async () => {
    const want = await tw.masterPasswordHash(await tw.masterKey("pw ゆ", "Me@Example.com", pre), "pw ゆ");
    eq(await loginHash(" me@example.com ", "pw ゆ", pre), want, "hash");
  });
}

if (failed) { console.log(`${failed} failed`); process.exit(1); }
console.log("all passed");
