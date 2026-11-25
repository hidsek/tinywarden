// Bitwarden crypto for the pages the board serves. Everything runs in the browser (WebCrypto, plus
// Argon2id from vendor/noble-hashes); the board never sees a password or plaintext.
// Same rules as tools/tw_backup.py and the official clients:
//   master key  = KDF(password, email trimmed and lowercased)
//   export key  = stretch(KDF(file password, the export's "salt" string))
//   KDF         = PBKDF2-SHA256(password, salt, iterations)
//               | Argon2id v0x13(password, SHA-256(salt), t, memory MiB * 1024 KiB, p), 32 bytes
//   stretch     = HKDF-Expand(key, "enc") | HKDF-Expand(key, "mac"), SHA-256, 32 bytes each
//   EncString 2 = "2." iv | AES-256-CBC(PKCS#7) | HMAC-SHA256(mac key, iv || ciphertext), base64
import { argon2idAsync } from "./vendor/noble-hashes/argon2.js";

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

export const KDF_PBKDF2 = 0;
export const KDF_ARGON2ID = 1;
// What the current Bitwarden clients fill in when Argon2id is chosen
export const ARGON2ID_DEFAULT = { kdfType: KDF_ARGON2ID, iterations: 6, memory: 32, parallelism: 4 };

export class MacError extends Error {
  constructor() { super("MAC mismatch (wrong password or damaged data)"); this.name = "MacError"; }
}

// ------------------------------------------------------------------ bytes

export function b64enc(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}

export function b64dec(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function eqConst(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export async function sha256(u8) {
  return new Uint8Array(await subtle.digest("SHA-256", u8));
}

async function hmacSha256(key, data) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

export async function pbkdf2(password, salt, iterations) {
  const k = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, k, 256));
}

// ------------------------------------------------------------------ KDF

// Accepts the prelogin shape {kdf, kdfIterations, kdfMemory, kdfParallelism}, the export shape
// {kdfType, kdfIterations, kdfMemory, kdfParallelism} and {kdfType, iterations, memory, parallelism}.
// Bounds follow the clients' import limits; the upper ones also stop a hostile file from asking the
// browser for gigabytes.
export function kdfConfig(o) {
  const type = o.kdfType ?? o.kdf ?? KDF_PBKDF2;
  const iterations = o.kdfIterations ?? o.iterations;
  if (type === KDF_PBKDF2) {
    if (!Number.isInteger(iterations) || iterations < 5000 || iterations > 2000000) throw new Error("PBKDF2の回数が範囲外です");
    return { kdfType: type, iterations };
  }
  if (type === KDF_ARGON2ID) {
    const memory = o.kdfMemory ?? o.memory;
    const parallelism = o.kdfParallelism ?? o.parallelism;
    const ok = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
    if (!ok(iterations, 2, 10) || !ok(memory, 16, 1024) || !ok(parallelism, 1, 16)) throw new Error("Argon2idの設定が範囲外です");
    return { kdfType: type, iterations, memory, parallelism };
  }
  throw new Error(`知らないKDFの種類です: ${type}`);
}

// password and salt are strings or bytes. onProgress(0..1) is called during Argon2id.
export async function kdf(password, salt, cfg, onProgress) {
  const pw = typeof password === "string" ? te.encode(password) : password;
  const s = typeof salt === "string" ? te.encode(salt) : salt;
  const c = kdfConfig(cfg);
  if (c.kdfType === KDF_PBKDF2) return pbkdf2(pw, s, c.iterations);
  return argon2idAsync(pw, await sha256(s), {
    t: c.iterations, m: c.memory * 1024, p: c.parallelism, dkLen: 32, onProgress,
  });
}

export async function stretch(key32) {
  // HKDF-Expand without the extract step: one block is HMAC(key, info || 0x01)
  return {
    enc: await hmacSha256(key32, concat(te.encode("enc"), new Uint8Array([1]))),
    mac: await hmacSha256(key32, concat(te.encode("mac"), new Uint8Array([1]))),
  };
}

export function splitKey(u8) {
  if (u8.length !== 64) throw new Error(`鍵の長さが${u8.length}バイトです（64のはず）`);
  return { enc: u8.slice(0, 32), mac: u8.slice(32) };
}

export async function masterKey(password, email, cfg, onProgress) {
  return kdf(password, email.trim().toLowerCase(), cfg, onProgress);
}

// The value the clients send as masterPasswordHash
export async function masterPasswordHash(mk, password) {
  return b64enc(await pbkdf2(mk, te.encode(password), 1));
}

// ------------------------------------------------------------------ EncString type 2

const ENC_RE = /^2\.([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)$/;

export function isEncString(s) {
  return typeof s === "string" && ENC_RE.test(s);
}

export async function decBytes(s, keys) {
  const m = ENC_RE.exec(s);
  if (!m) throw new Error("EncString（種類2）ではありません");
  const [iv, ct, mac] = m.slice(1).map(b64dec);
  if (!eqConst(await hmacSha256(keys.mac, concat(iv, ct)), mac)) throw new MacError();
  const k = await subtle.importKey("raw", keys.enc, "AES-CBC", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, k, ct));
}

export async function decString(s, keys) {
  return td.decode(await decBytes(s, keys));
}

export async function enc(data, keys) {
  const pt = typeof data === "string" ? te.encode(data) : data;
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const k = await subtle.importKey("raw", keys.enc, "AES-CBC", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, pt));
  const mac = await hmacSha256(keys.mac, concat(iv, ct));
  return `2.${b64enc(iv)}|${b64enc(ct)}|${b64enc(mac)}`;
}

// ------------------------------------------------------------------ password-protected export

export function isProtectedExport(doc) {
  return doc && doc.encrypted === true && doc.passwordProtected === true && typeof doc.salt === "string"
    && isEncString(doc.encKeyValidation_DO_NOT_EDIT) && isEncString(doc.data);
}

// Returns the plain export object ({encrypted: false, folders, items}). Throws MacError on a wrong password.
export async function openProtectedExport(doc, password, onProgress) {
  if (!isProtectedExport(doc)) throw new Error("パスワード付きのエクスポートではありません");
  const keys = await stretch(await kdf(password, doc.salt, doc, onProgress));
  await decBytes(doc.encKeyValidation_DO_NOT_EDIT, keys); // MacError here means a wrong file password
  return JSON.parse(await decString(doc.data, keys));
}

// plain: {encrypted: false, folders, items}. cfg defaults to Argon2id with the clients' settings.
export async function makeProtectedExport(plain, password, cfg = ARGON2ID_DEFAULT, onProgress) {
  const c = kdfConfig(cfg);
  const salt = b64enc(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  const keys = await stretch(await kdf(password, salt, c, onProgress));
  const doc = {
    encrypted: true, passwordProtected: true, salt, kdfType: c.kdfType, kdfIterations: c.iterations,
  };
  if (c.kdfType === KDF_ARGON2ID) { doc.kdfMemory = c.memory; doc.kdfParallelism = c.parallelism; }
  doc.encKeyValidation_DO_NOT_EDIT = await enc(globalThis.crypto.randomUUID(), keys);
  doc.data = await enc(JSON.stringify(plain), keys);
  return doc;
}

// ------------------------------------------------------------------ tinywarden backup (status page / tw_backup.py fetch)

// Format 1 carries the email; format 2 (firmware 0.3 and later) does not: the board does not store it,
// so the username has to be typed in to open the file.
export function isTwBackup(doc) {
  return !!doc && doc.sync && doc.prelogin &&
    ((doc.tinywarden_backup === 1 && typeof doc.email === "string") || doc.tinywarden_backup === 2);
}

export function twBackupNeedsUsername(doc) {
  return isTwBackup(doc) && typeof doc.email !== "string";
}

function lowerFirst(o) {
  if (Array.isArray(o)) return o.map(lowerFirst);
  if (o && typeof o === "object") {
    return Object.fromEntries(Object.entries(o).map(([k, v]) => [k.slice(0, 1).toLowerCase() + k.slice(1), lowerFirst(v)]));
  }
  return o;
}

// Fields that are not part of an export (same list as tw_backup.py)
const DROP = new Set(["key", "object", "edit", "viewPassword", "permissions", "organizationUseTotp", "attachments",
  "collectionIds", "data", "uriChecksum"]);

function strip(o) {
  if (Array.isArray(o)) return o.map(strip);
  if (o && typeof o === "object") return Object.fromEntries(Object.entries(o).filter(([k]) => !DROP.has(k)).map(([k, v]) => [k, strip(v)]));
  return o;
}

async function decTree(o, keys) {
  if (isEncString(o)) return decString(o, keys);
  if (Array.isArray(o)) return Promise.all(o.map((v) => decTree(v, keys)));
  if (o && typeof o === "object") {
    const out = {};
    for (const [k, v] of Object.entries(o)) out[k] = await decTree(v, keys);
    return out;
  }
  return o;
}

// Decrypts a tinywarden backup into a plain export. Returns {plain, skipped}; MacError = wrong password or
// username. username is used when the file has none (format 2).
export async function openTwBackup(doc, password, onProgress, username) {
  if (!isTwBackup(doc)) throw new Error("控えのファイルではありません");
  const sync = lowerFirst(doc.sync);
  const user = typeof doc.email === "string" ? doc.email : username;
  if (!user) throw new Error("ユーザー名（メール）を入れてください");
  const mk = await masterKey(password, user, doc.prelogin, onProgress);
  const wrapped = sync.profile?.key ?? sync.userDecryption?.masterPasswordUnlock?.masterKeyEncryptedUserKey;
  if (!wrapped) throw new Error("控えに暗号化された保管庫の鍵がありません");
  const userKey = splitKey(await decBytes(wrapped, await stretch(mk)));
  const folders = [];
  for (const f of sync.folders ?? []) folders.push({ id: f.id, name: await decString(f.name, userKey) });
  const items = [];
  let skipped = 0;
  for (const c of sync.ciphers ?? []) {
    if (c.deletedDate || c.organizationId) { skipped++; continue; }
    const k = c.key ? splitKey(await decBytes(c.key, userKey)) : userKey;
    const item = await decTree(strip(c), k); // strip first: "key" is under the user key, not the item key
    item.collectionIds = null;
    items.push(item);
  }
  return { plain: { encrypted: false, folders, items }, skipped };
}
