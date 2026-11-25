// Tests for firmware/web/merge.js (comparing and merging two plain exports). Node 20+.
//   node test/web/test_merge.mjs
import * as m from "../../firmware/web/merge.js";
import * as tw from "../../firmware/web/twcrypto.js";

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log("ok  ", name); } catch (e) { failed++; console.log("FAIL", name, "-", e.message); }
}
function eq(a, b, what = "value") {
  const sa = JSON.stringify(a), sb = JSON.stringify(b);
  if (sa !== sb) throw new Error(`${what}: ${sa.slice(0, 200)} != ${sb.slice(0, 200)}`);
}

const login = (id, name, user, pw, uri, rev, extra = {}) => ({
  id, type: 1, name, folderId: null, notes: null, favorite: false, reprompt: 0, organizationId: null, collectionIds: null,
  login: { username: user, password: pw, totp: null, uris: uri ? [{ match: null, uri }] : [], fido2Credentials: [] },
  revisionDate: rev, creationDate: "2026-01-01T00:00:00.000Z", ...extra,
});

const A = {
  encrypted: false,
  folders: [{ id: "fa1", name: "仕事" }, { id: "fa2", name: "家" }],
  items: [
    login("same-id", "GitHub", "me", "pw1", "https://github.com/login", "2026-05-01T00:00:00Z", { folderId: "fa1" }),
    login("a-2", "Example", "me@example.com", "old", "https://www.example.com", "2026-03-01T00:00:00Z",
      { passwordHistory: [{ lastUsedDate: "2026-02-01T00:00:00Z", password: "older" }] }),
    login("a-3", "Only in A", "x", "y", "https://a.example", "2026-01-02T00:00:00Z", { folderId: "fa2" }),
    { id: "a-4", type: 2, name: "メモ", notes: "same text", secureNote: { type: 0 }, folderId: null, revisionDate: "2026-01-01T00:00:00Z" },
    login("a-5", "Trash", "t", "t", null, "2026-01-01T00:00:00Z", { deletedDate: "2026-02-01T00:00:00Z" }),
  ],
};
const B = {
  encrypted: false,
  folders: [{ id: "fb1", name: "仕事" }, { id: "fb3", name: "趣味" }],
  items: [
    // same id, same content, folder of the same name with another id, an empty field written differently
    login("same-id", "GitHub", "me", "pw1", "https://github.com/login", "2026-06-01T00:00:00Z", { folderId: "fb1", notes: "" }),
    // other id (imported), same name/user/host -> paired, password changed later
    login("b-2", "example", "ME@example.com ", "new", "https://example.com/account", "2026-09-01T00:00:00Z"),
    login("b-3", "Only in B", "x", "y", "https://b.example", "2026-01-03T00:00:00Z", { folderId: "fb3" }),
    { id: "b-4", type: 2, name: "メモ", notes: "same text", secureNote: { type: 0 }, folderId: null },
  ],
};

await check("compare: pairs by id, then by type/name/username/host; trash ignored", async () => {
  const pairs = m.compare(A, B);
  const sig = pairs.map((p) => [p.kind, p.a?.id ?? null, p.b?.id ?? null]);
  eq(sig, [["same", "same-id", "same-id"], ["differ", "a-2", "b-2"], ["onlyA", "a-3", null], ["same", "a-4", "b-4"],
    ["onlyB", null, "b-3"]]);
  eq(m.summary(pairs), { same: 2, differ: 1, onlyA: 1, onlyB: 1 });
});

await check("compare: differing fields are named, folder compared by name", async () => {
  const p = m.compare(A, B).find((x) => x.kind === "differ");
  eq(p.diffs, ["login.password", "login.uris", "login.username", "name"]);
  const moved = m.compare(A, { ...B, items: [{ ...B.items[0], folderId: "fb3" }] })[0];
  eq([moved.kind, moved.diffs], ["differ", ["folder"]]);
});

await check("compare: which account and key an item was encrypted for is not a difference", async () => {
  const x = login("x", "Site", "u", "p", "https://s.example", "2024-08-23T02:45:00Z");
  const y = login("y", "Site", "u", "p", "https://s.example", "2026-11-19T17:48:00Z",
    { encryptedFor: "1e0f310a-5b33-471a-ba3d-7a2e5d493c0b", encryptedByKeyId: "ac7b80541a0d5cd99cd94784cfe00989" });
  const [p] = m.compare({ items: [x], folders: [] }, { items: [y], folders: [] });
  eq([p.kind, p.diffs], ["same", []]);
});

await check("compare: empty written differently, passkey counter and password date are not differences", async () => {
  const x = login("x", "Site", "u", "p", "https://s.example", "2026-01-01T00:00:00Z",
    { favorite: false, reprompt: 0, fields: [], card: {} });
  x.login.fido2Credentials = [{ credentialId: "c1", counter: "0", rpId: "s.example" }];
  x.login.passwordRevisionDate = "2026-01-01T00:00:00Z";
  const y = login("y", "Site", "u", "p", "https://s.example", "2026-02-01T00:00:00Z", { favorite: null });
  delete y.reprompt;
  y.login.fido2Credentials = [{ rpId: "s.example", credentialId: "c1", counter: "7" }];
  y.login.uris[0].match = 0;
  const [p] = m.compare({ items: [x], folders: [] }, { items: [y], folders: [] });
  eq([p.kind, p.diffs], ["same", []]);
  y.login.fido2Credentials[0].credentialId = "c2";
  eq(m.compare({ items: [x], folders: [] }, { items: [y], folders: [] })[0].diffs, ["login.fido2Credentials"]);
});

await check("defaults: newer revision wins, one-sided items are kept", async () => {
  const pairs = m.compare(A, B);
  eq(pairs.map((p) => p.choice), ["b", "b", "a", "a", "b"]);
  eq(m.newer({ revisionDate: null }, { revisionDate: "2026-01-01T00:00:00Z" }), "b");
  eq(m.newer({ revisionDate: "2026-01-01T00:00:00Z" }, { revisionDate: null }), "a");
});

await check("build: folders merged by name, items point at merged folders", async () => {
  const out = m.build(A, B, m.compare(A, B));
  eq(out.folders.map((f) => f.name), ["仕事", "家", "趣味"]);
  const fid = Object.fromEntries(out.folders.map((f) => [f.name, f.id]));
  const byName = Object.fromEntries(out.items.map((i) => [i.name, i]));
  eq(byName.GitHub.folderId, fid["仕事"], "GitHub folder");
  eq(byName["Only in A"].folderId, fid["家"], "A-only folder");
  eq(byName["Only in B"].folderId, fid["趣味"], "B-only folder");
  eq(out.items.length, 5, "count");
  eq(out.encrypted, false);
});

await check("build: the losing password goes into the history (newest first, no duplicates)", async () => {
  const out = m.build(A, B, m.compare(A, B), "2026-11-20T00:00:00Z");
  const ex = out.items.find((i) => i.id === "b-2");
  eq(ex.login.password, "new");
  eq(ex.passwordHistory, [{ lastUsedDate: "2026-03-01T00:00:00Z", password: "old" },
    { lastUsedDate: "2026-02-01T00:00:00Z", password: "older" }]);
  const pairs = m.compare(A, B);
  pairs[1].choice = "a";
  const kept = m.build(A, B, pairs).items.find((i) => i.id === "a-2");
  eq([kept.login.password, kept.passwordHistory.map((h) => h.password)], ["old", ["new", "older"]]);
});

await check("build: 'both' keeps two items with distinct ids, 'none' drops", async () => {
  const pairs = m.compare(A, B);
  pairs[0].choice = "both";
  pairs[2].choice = "none";
  const out = m.build(A, B, pairs);
  const gh = out.items.filter((i) => i.name === "GitHub");
  eq(gh.length, 2, "two copies");
  if (gh[0].id === gh[1].id) throw new Error("same id twice");
  if (out.items.some((i) => i.name === "Only in A")) throw new Error("dropped item kept");
  eq(new Set(out.items.map((i) => i.id)).size, out.items.length, "unique ids");
});

await check("build: input objects are not changed", async () => {
  const before = JSON.stringify([A, B]);
  m.build(A, B, m.compare(A, B));
  eq(JSON.stringify([A, B]), before);
});

await check("buildDelta: only what B lacks, plus the list to delete by hand", async () => {
  const pairs = m.compare(A, B);
  pairs.find((p) => p.kind === "differ").choice = "a";     // A's Example wins over B's
  const { plain, remove } = m.buildDelta(A, B, pairs, "b", "2026-11-20T00:00:00Z");
  eq(plain.items.map((i) => i.name).sort(), ["Example", "Only in A"], "items for B");
  eq(plain.items.find((i) => i.name === "Example").passwordHistory.map((h) => h.password), ["new", "older"], "history");
  eq(plain.folders.map((f) => f.name), ["家"], "only used folders");
  eq(remove.map((r) => r.name), ["example"], "B's old copy to delete");
  const back = m.buildDelta(A, B, m.compare(A, B), "a");
  eq(back.plain.items.map((i) => i.name).sort(), ["Only in B", "example"], "items for A (newer B wins by default)");
  eq(back.remove.map((r) => r.name), ["Example"], "A's old copy to delete");
  const drop = m.compare(A, B);
  drop.find((p) => p.kind === "onlyB").choice = "none";
  eq(m.buildDelta(A, B, drop, "b").remove.map((r) => r.name), ["Only in B"], "dropped B item");
});

await check("merged result survives a password-protected export round trip", async () => {
  const out = m.build(A, B, m.compare(A, B));
  const doc = await tw.makeProtectedExport(out, "merge file pw", { kdfType: 1, iterations: 2, memory: 16, parallelism: 1 });
  eq(await tw.openProtectedExport(doc, "merge file pw"), out);
});

if (failed) { console.log(`${failed} failed`); process.exit(1); }
console.log("all passed");
