// Comparing and merging two plain Bitwarden exports ({encrypted: false, folders, items}).
// Pure functions, no I/O; the page (merge-ui.js) decrypts the inputs and encrypts the result.
//
//   const pairs = compare(a, b);            // [{kind, a, b, diffs, choice}]
//   ...the person changes pair.choice...
//   const out = build(a, b, pairs);         // plain export to encrypt and import into an EMPTY account
//
// kind:   "same" (identical content) | "differ" | "onlyA" | "onlyB"
// choice: "a" | "b" | "both" | "none"   (defaults: same/differ -> newer revision, else a; onlyX -> keep)

const TYPE_LOGIN = 1;

function norm(s) {
  return (s ?? "").toString().trim().toLowerCase();
}

function firstHost(item) {
  const u = item.login?.uris?.find((x) => x?.uri)?.uri;
  if (!u) return "";
  try { return new URL(u.includes("://") ? u : "https://" + u).hostname.replace(/^www\./, ""); } catch { return norm(u); }
}

// How two items are recognised as "the same entry" when their ids differ (ids change on import)
export function matchKey(item) {
  const parts = [item.type, norm(item.name)];
  if (item.type === TYPE_LOGIN) parts.push(norm(item.login?.username), firstHost(item));
  return JSON.stringify(parts);
}

// Fields that say nothing about the content. encryptedFor / encryptedByKeyId: which account and key the
// newer clients encrypted the item for. An import re-encrypts under the new account, so they differ from the
// export file even when nothing else does.
const META = new Set(["id", "organizationId", "folderId", "collectionIds", "revisionDate", "creationDate", "deletedDate",
  "archivedDate", "passwordHistory", "encryptedFor", "encryptedByKeyId"]);

// Inside an item: values that change without the content changing
const NOISE = new Set(["counter", "passwordRevisionDate", "uriChecksum"]);

// Same content written differently compares equal: "" / false / 0 / [] / {} / null / missing are all "empty"
// (0 is also the default for uri match, reprompt and note type), keys in any order.
function canon(v) {
  if (Array.isArray(v)) {
    const a = v.map(canon);
    return a.length ? a : null;
  }
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (NOISE.has(k)) continue;
      const c = canon(v[k]);
      if (c !== null) out[k] = c;
    }
    return Object.keys(out).length ? out : null;
  }
  if (v === undefined || v === "" || v === false || v === 0) return null;
  return v;
}

function folderName(exp, id) {
  if (!id) return null;
  return exp.folders?.find((f) => f.id === id)?.name ?? null;
}

// Top-level (and login.*) field names whose values differ; folder compared by name
export function diffFields(a, b, expA, expB) {
  const out = [];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of [...keys].sort()) {
    if (META.has(k)) continue;
    if (k === "login" && (a.login || b.login)) {
      const lk = new Set([...Object.keys(a.login ?? {}), ...Object.keys(b.login ?? {})]);
      for (const f of [...lk].sort()) {
        if (NOISE.has(f)) continue;
        if (JSON.stringify(canon(a.login?.[f])) !== JSON.stringify(canon(b.login?.[f]))) out.push("login." + f);
      }
      continue;
    }
    if (JSON.stringify(canon(a[k])) !== JSON.stringify(canon(b[k]))) out.push(k);
  }
  if (folderName(expA, a.folderId) !== folderName(expB, b.folderId)) out.push("folder");
  return out;
}

function time(item) {
  const t = Date.parse(item?.revisionDate ?? "");
  return Number.isNaN(t) ? null : t;
}

export function newer(a, b) {
  const ta = time(a), tb = time(b);
  if (ta !== null && tb !== null && tb > ta) return "b";
  if (ta === null && tb !== null) return "b";
  return "a";
}

export function compare(expA, expB) {
  const A = (expA.items ?? []).filter((i) => !i.deletedDate);
  const B = (expB.items ?? []).filter((i) => !i.deletedDate);
  const usedB = new Set();
  const pairs = [];
  const take = (a, j) => {
    usedB.add(j);
    const b = B[j];
    const diffs = diffFields(a, b, expA, expB);
    const kind = diffs.length ? "differ" : "same";
    pairs.push({ kind, a, b, diffs, choice: newer(a, b) });
  };
  const byId = new Map(B.map((b, j) => [b.id, j]));
  const rest = [];
  for (const a of A) {
    const j = a.id ? byId.get(a.id) : undefined;
    if (j !== undefined && !usedB.has(j) && B[j].type === a.type) take(a, j);
    else rest.push(a);
  }
  const byKey = new Map();
  B.forEach((b, j) => { if (!usedB.has(j)) { const k = matchKey(b); if (!byKey.has(k)) byKey.set(k, []); byKey.get(k).push(j); } });
  for (const a of rest) {
    const list = byKey.get(matchKey(a));
    const j = list?.find((x) => !usedB.has(x));
    if (j !== undefined) take(a, j);
    else pairs.push({ kind: "onlyA", a, b: null, diffs: [], choice: "a" });
  }
  B.forEach((b, j) => { if (!usedB.has(j)) pairs.push({ kind: "onlyB", a: null, b, diffs: [], choice: "b" }); });
  return pairs;
}

export function summary(pairs) {
  const s = { same: 0, differ: 0, onlyA: 0, onlyB: 0 };
  for (const p of pairs) s[p.kind]++;
  return s;
}

// Password history of the kept item gains the other copy's password (and both histories), newest first,
// at most 5 entries like the clients keep.
function mergedHistory(win, lose, nowIso) {
  const list = [...(win.passwordHistory ?? []), ...(lose.passwordHistory ?? [])];
  const wp = win.login?.password, lp = lose.login?.password;
  if (lp && lp !== wp) list.push({ lastUsedDate: lose.revisionDate ?? nowIso, password: lp });
  const seen = new Set();
  const out = [];
  for (const h of list.sort((x, y) => (Date.parse(y.lastUsedDate) || 0) - (Date.parse(x.lastUsedDate) || 0))) {
    if (!h?.password || h.password === wp || seen.has(h.password)) continue;
    seen.add(h.password);
    out.push({ lastUsedDate: h.lastUsedDate, password: h.password });
  }
  return out.slice(0, 5);
}

function uuid() {
  return globalThis.crypto.randomUUID();
}

export function build(expA, expB, pairs, nowIso = new Date().toISOString()) {
  // Folders merged by name; items point at the merged folder through the source folder's name
  const folders = [];
  const idByName = new Map();
  for (const f of [...(expA.folders ?? []), ...(expB.folders ?? [])]) {
    if (!f?.name || idByName.has(f.name)) continue;
    const id = folders.some((x) => x.id === f.id) || !f.id ? uuid() : f.id;
    idByName.set(f.name, id);
    folders.push({ id, name: f.name });
  }
  const items = [];
  const ids = new Set();
  const put = (item, exp, extra = {}) => {
    const copy = structuredClone(item);
    Object.assign(copy, extra);
    const fname = folderName(exp, item.folderId);
    copy.folderId = fname ? idByName.get(fname) ?? null : null;
    copy.organizationId = null;
    copy.collectionIds = null;
    if (!copy.id || ids.has(copy.id)) copy.id = uuid();
    ids.add(copy.id);
    items.push(copy);
  };
  for (const p of pairs) {
    if (p.choice === "none") continue;
    if (p.kind === "onlyA") { put(p.a, expA); continue; }
    if (p.kind === "onlyB") { put(p.b, expB); continue; }
    if (p.choice === "both") { put(p.a, expA); put(p.b, expB); continue; }
    const [win, winExp, lose] = p.choice === "b" ? [p.b, expB, p.a] : [p.a, expA, p.b];
    const extra = win.type === TYPE_LOGIN ? { passwordHistory: mergedHistory(win, lose, nowIso) } : {};
    put(win, winExp, extra);
  }
  return { encrypted: false, folders, items };
}

// Only what one side is missing, to import into that side as it is (no wipe). into = "a" | "b".
// Returns {plain, remove}: plain holds the items the target lacks or should get in a newer form;
// remove lists the target's own items that import cannot replace or delete (delete them by hand
// after importing): the old copy of each "differ" item taken from the other side, and items the
// person chose to drop.
export function buildDelta(expA, expB, pairs, into, nowIso = new Date().toISOString()) {
  const src = into === "b" ? "a" : "b";
  const srcExp = src === "a" ? expA : expB;
  const dstExp = src === "a" ? expB : expA;
  const take = [];
  const remove = [];
  for (const p of pairs) {
    const s = p[src], d = p[into];
    if (p.kind === "same") continue;
    if (!d) { if (p.choice === src) take.push({ item: s, lose: null }); continue; }   // only on the source side
    if (!s) { if (p.choice === "none") remove.push(d); continue; }                    // only on the target side
    if (p.choice === src) { take.push({ item: s, lose: d }); remove.push(d); }         // differ, source wins
    else if (p.choice === "both") take.push({ item: s, lose: null });
    else if (p.choice === "none") remove.push(d);
  }
  const fake = take.map(({ item, lose }) => (lose
    ? { kind: "differ", a: item, b: lose, diffs: [], choice: "a" }
    : { kind: "onlyA", a: item, b: null, diffs: [], choice: "a" }));
  const plain = build(srcExp, { items: [], folders: [] }, fake, nowIso);
  // Only folders that the taken items use
  const used = new Set(plain.items.map((i) => i.folderId).filter(Boolean));
  plain.folders = plain.folders.filter((f) => used.has(f.id));
  return { plain, remove: remove.map((i) => ({ id: i.id, name: i.name, username: i.login?.username ?? null, folder: folderName(dstExp, i.folderId) })) };
}
