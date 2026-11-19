// The merge page (/merge). Opens two vaults in the browser, shows how they differ, lets the person
// choose per item, and saves one password-protected export. Nothing is sent anywhere except, when
// "この基板から取る" is used, the login hash to the board (same as the status page's backup).
// Every value from a vault is shown with textContent, never as HTML.
import * as tw from "./twcrypto.js";
import * as mg from "./merge.js";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of kids) if (c != null) e.append(c);
  return e;
};

const sides = { A: null, B: null }; // opened plain exports
const names = { A: "", B: "" };   // where each came from
let pairs = [];
let show = null; // null: pick automatically
let reveal = false;
let outMode = "all";  // "all" | "delta"
let deltaTo = "b";   // which side the delta file is for

const JA = {
  "Button not pressed within 30 seconds": "30秒以内にBOOTボタンが押されませんでした",
  "Email or master password is incorrect": "メールかマスターパスワードが違います（失敗の回数に数えました）",
  "Too many failed attempts. This tinywarden has been erased": "失敗が多すぎたので、tinywardenの中身を全部消しました",
};

// ---------------------------------------------------------------- the two inputs

function buildSide(name) {
  const root = $("side" + name);
  const radio = (v, label) => {
    const r = el("input", { type: "radio", name: "src" + name, value: v });
    return [r, el("label", {}, r, " " + label)];
  };
  const [rFile, lFile] = radio("file", "ファイル");
  const [rBoard, lBoard] = radio("board", "この基板");
  rFile.checked = true;

  // From a file
  const file = el("input", { type: "file", accept: ".json,application/json" });
  const kind = el("p", { class: "mute" });
  const guide = el("div", { class: "mute diff" },
    el("div", { text: "どのパスワードを使うかは、ファイルで決まります（選ぶと自動で切り替わります）:" }),
    el("ul", {},
      el("li", { text: "Bitwarden・Vaultwardenの「パスワード付き」エクスポート → エクスポートしたときに決めたファイルのパスワード" }),
      el("li", { text: "tinywardenの控え（管理ページの「控えを保存」） → tinywardenのマスターパスワード" }),
      el("li", { text: "Bitwarden・Vaultwardenの「アカウント制限付き」エクスポート → 開けません（鍵がサーバーにあるため）。エクスポートし直すときに「パスワード付き」を選んでください" })));
  const showKind = (text, ok = true) => { kind.replaceChildren(el("b", { text })); kind.className = ok ? "" : "ng"; };
  const pw = el("input", { type: "password", autocomplete: "off" });
  const pwLabel = el("span", { text: "パスワード" });
  const pwRow = el("p", { hidden: "" }, el("label", {}, pwLabel, el("br"), pw));
  const open = el("button", { text: "開く", hidden: "" });
  const filePane = el("div", {}, el("p", {}, file), guide, kind, pwRow, el("p", {}, open));

  // From this board
  const email = el("input", { type: "email", autocomplete: "username" });
  const mpw = el("input", { type: "password", autocomplete: "current-password" });
  const board = el("button", { text: "この基板から取る" });
  const boardPane = el("div", { hidden: "" },
    el("p", { class: "mute", text: "tinywardenに今入っている中身を使います。BOOTボタンが要ります（控えの保存と同じ）。" }),
    el("p", {}, el("label", {}, "メール", el("br"), email)),
    el("p", {}, el("label", {}, "マスターパスワード", el("br"), mpw)), el("p", {}, board));

  const msg = el("p", { class: "mute" });
  const say = (t, cls = "mute") => { msg.textContent = t; msg.className = cls; };
  let doc = null;

  const clear = () => { sides[name] = null; names[name] = ""; say(""); update(); };
  rFile.onchange = rBoard.onchange = () => {
    filePane.hidden = !rFile.checked;
    boardPane.hidden = !rBoard.checked;
    clear();
  };

  file.onchange = async () => {
    doc = null;
    pwRow.hidden = open.hidden = true;
    clear();
    const f = file.files[0];
    if (!f) return;
    try {
      doc = JSON.parse(await f.text());
    } catch {
      showKind("JSONとして読めません。", false);
      return;
    }
    if (tw.isProtectedExport(doc)) {
      showKind("Bitwarden・Vaultwardenなどの、パスワード付きのエクスポートです。");
      pwLabel.textContent = "ファイルのパスワード（エクスポートしたときに決めたもの。マスターパスワードではありません）";
      pwRow.hidden = open.hidden = false;
    } else if (tw.isTwBackup(doc)) {
      // The master key is made from this account's email, so the email comes from the file
      showKind(`tinywardenの控えです（${doc.email} のアカウント）。`);
      pwLabel.textContent = `tinywardenのマスターパスワード（${doc.email} のアカウント。控えには別のパスワードはありません）`;
      pwRow.hidden = open.hidden = false;
    } else if (doc?.encrypted === false && Array.isArray(doc.items)) {
      showKind("暗号化されていないエクスポートです。パスワードは要りません。");
      open.hidden = false;
    } else if (doc?.encrypted === true) {
      showKind("「アカウント制限付き」のエクスポートなので開けません（鍵がサーバーにあるため）。エクスポートし直すときに「パスワード付き」を選んでください。", false);
      doc = null;
    } else {
      showKind("Bitwardenのエクスポートでも、tinywardenの控えでもないようです。", false);
      doc = null;
    }
  };

  open.onclick = async () => {
    if (!doc) return;
    open.disabled = true;
    try {
      const prog = (p) => say(`開いています… ${Math.round(p * 100)}%`);
      say("開いています…");
      let plain, note = "";
      if (tw.isProtectedExport(doc)) plain = await tw.openProtectedExport(doc, pw.value, prog);
      else if (tw.isTwBackup(doc)) {
        const r = await tw.openTwBackup(doc, pw.value, prog);
        plain = r.plain;
        if (r.skipped) note = `（ゴミ箱と組織の ${r.skipped} 件は除いた）`;
      } else plain = doc;
      pw.value = "";
      names[name] = file.files[0]?.name ?? "";
      opened(plain, note);
    } catch (e) {
      say(e instanceof tw.MacError ? "パスワードが違います。" : "開けませんでした: " + (e.message || e), "ng");
    } finally {
      open.disabled = false;
    }
  };

  // Take the board's current vault directly (same steps as the status page's backup)
  board.onclick = async () => {
    const em = email.value.trim().toLowerCase(), p = mpw.value;
    if (!em || !p) { say("メールとマスターパスワードを入れてください。", "ng"); return; }
    board.disabled = true;
    try {
      const pre = await (await fetch("/identity/accounts/prelogin", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: em }),
      })).json();
      const mk = await tw.masterKey(p, em, pre, (x) => say(`マスターパスワードを計算中… ${Math.round(x * 100)}%`));
      const mph = await tw.masterPasswordHash(mk, p);
      say("基板のLEDが光っているあいだ（30秒以内）にBOOTボタンを押してください。");
      const r = await fetch("/tw/backup", {
        method: "POST", headers: { "X-tinywarden-Confirm": "backup", "Content-Type": "application/json" },
        body: JSON.stringify({ email: em, masterPasswordHash: mph }),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(JA[j.message] ?? j.message ?? String(r.status));
      }
      say("読み出し中…");
      const res = await tw.openTwBackup(await r.json(), p, () => {});
      mpw.value = "";
      names[name] = "この基板";
      opened(res.plain, "");
    } catch (e) {
      say("取れませんでした: " + (e.message || e), "ng");
    } finally {
      board.disabled = false;
    }
  };

  function opened(plain, note) {
    sides[name] = plain;
    say(`開きました: 項目 ${plain.items?.length ?? 0} 件、フォルダ ${plain.folders?.length ?? 0} 個 ${note}`, "ok");
    update();
  }

  root.append(el("p", { class: "bar" }, el("span", { class: "mute", text: "どこから:" }), lFile, lBoard), filePane, boardPane, msg);
}

// ---------------------------------------------------------------- side-by-side view

const LABEL = {
  name: "名前", notes: "メモ", favorite: "お気に入り", reprompt: "パスワードの再確認", fields: "カスタムフィールド",
  "login.username": "ユーザー名", "login.password": "パスワード", "login.totp": "認証キー（TOTP）", "login.uris": "URL",
  "login.fido2Credentials": "パスキー", card: "カード", identity: "個人情報", sshKey: "SSH鍵", secureNote: "メモの種類",
  folder: "フォルダ", type: "種類",
};
const SECRET = new Set(["login.password", "login.totp", "login.fido2Credentials", "card", "sshKey", "fields"]);
// Rows every card shows (when the item has them), in this order; other differing fields are added after
const ROWS = ["login.username", "login.uris", "folder", "login.password", "login.totp", "login.fido2Credentials", "notes",
  "fields", "card", "identity", "sshKey"];
const KIND = { differ: "違う", onlyA: "Aだけ", onlyB: "Bだけ", same: "同じ" };

function get(item, path) {
  return path.split(".").reduce((o, k) => (o == null ? o : o[k]), item);
}

function isEmpty(v) {
  return v == null || v === "" || (Array.isArray(v) && !v.length) || (typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);
}

function show1(item, field, exp) {
  if (field === "folder") return (exp?.folders ?? []).find((f) => f.id === item.folderId)?.name ?? "";
  const v = get(item, field);
  if (isEmpty(v)) return "";
  if (field === "login.uris") return v.map((u) => u?.uri).filter(Boolean).join("\n");
  if (field === "login.fido2Credentials") return `パスキー ${v.length} 個` + (reveal ? "\n" + v.map((c) => c.rpId ?? "").join("\n") : "");
  if (field === "fields") return reveal ? v.map((f) => `${f.name ?? ""}: ${f.value ?? ""}`).join("\n") : `${v.length} 個（` + v.map((f) => f.name ?? "").join("、") + "）";
  if (SECRET.has(field) && !reveal) return typeof v === "string" ? `●●●●（${[...v].length}文字）` : "●●●●";
  if (typeof v === "string") return v.length > 200 ? v.slice(0, 200) + "…" : v;
  if (typeof v === "boolean") return v ? "はい" : "";
  return JSON.stringify(v).slice(0, 200);
}

function card(item, exp, diffs, selected, onpick) {
  if (!item) return el("div", { class: "card empty", text: "（なし）" });
  const c = el("div", { class: "card" + (selected ? " sel" : ""), title: "押すと、こちらを残します", onclick: onpick });
  c.append(el("div", {}, selected ? el("span", { class: "keep", text: "✔ 残す" }) : null, el("span", { class: "t", text: item.name ?? "（名前なし）" })));
  const grid = el("div", { class: "f" });
  const fields = [...ROWS, ...diffs.filter((d) => !ROWS.includes(d) && d !== "name")];
  for (const f of fields) {
    const v = show1(item, f, exp);
    const d = diffs.includes(f);
    if (!v && !d) continue;
    grid.append(el("div", { class: d ? "d" : "mute", text: LABEL[f] ?? f }), el("div", { class: d ? "d" : "", text: v || "（なし）" }));
  }
  grid.append(el("div", { class: "mute", text: "更新日" }), el("div", { class: "mute", text: item.revisionDate ? item.revisionDate.slice(0, 16).replace("T", " ") : "不明" }));
  c.append(grid);
  return c;
}

function pairRow(p) {
  const diffs = p.diffs.includes("name") ? p.diffs : p.diffs;
  const pick = (v) => () => { p.choice = v; refresh(); };
  const selA = p.choice === "a" || p.choice === "both";
  const selB = p.choice === "b" || p.choice === "both";
  const mid = el("div", { class: "mid" }, el("span", { class: "kind", text: KIND[p.kind] }));
  if (p.a && p.b) mid.append(el("button", { class: p.choice === "both" ? "on" : "", text: "両方", onclick: pick("both") }));
  mid.append(el("button", { class: p.choice === "none" ? "on" : "", text: "捨てる", onclick: pick(p.choice === "none" ? (p.a ? "a" : "b") : "none") }));
  return el("div", { class: "drow" },
    card(p.a, sides.A, diffs, selA, p.a ? pick("a") : null),
    mid,
    card(p.b, sides.B, diffs, selB, p.b ? pick("b") : null));
}

function counts() {
  let fromA = 0, fromB = 0, total = 0;
  for (const p of pairs) {
    if (p.choice === "a") { fromA++; total++; } else if (p.choice === "b") { fromB++; total++; } else if (p.choice === "both") { fromA++; fromB++; total += 2; }
  }
  return { fromA, fromB, total };
}

function refresh() {
  const s = mg.summary(pairs);
  const changes = s.differ + s.onlyA + s.onlyB;
  if (show === null) show = changes ? "changes" : "same";
  // Filter chips
  const chips = $("chips");
  chips.replaceChildren();
  for (const [k, label, n] of [["changes", "違いのあるもの", changes], ["differ", "違う", s.differ], ["onlyA", "Aだけ", s.onlyA],
    ["onlyB", "Bだけ", s.onlyB], ["same", "同じ", s.same]]) {
    chips.append(el("button", { class: "chip" + (show === k ? " on" : ""), text: `${label} ${n}`, onclick: () => { show = k; refresh(); } }));
  }
  // What saving would produce
  const c = counts();
  let folders = 0;
  try { folders = mg.build(sides.A ?? { items: [], folders: [] }, sides.B ?? { items: [], folders: [] }, pairs).folders.length; } catch { /* shown on save */ }
  $("preview").textContent = `全部まとめると: 項目 ${c.total} 件（Aから ${c.fromA}、Bから ${c.fromB}）、フォルダ ${folders} 個`;
  // The two ways of saving, with what each would produce
  $("allInfo").textContent = `項目 ${c.total} 件（Aから ${c.fromA}、Bから ${c.fromB}）、フォルダ ${folders} 個`;
  const both = Boolean(sides.A && sides.B);
  $("optDelta").classList.toggle("off", !both);
  for (const side of ["a", "b"]) {
    const S = side.toUpperCase();
    const label = $("to" + S + "Label");
    if (both) {
      const d = mg.buildDelta(sides.A, sides.B, pairs, side);
      label.textContent = `${S}${names[S] ? `（${names[S]}）` : ""}に入れる: 追加 ${d.plain.items.length} 件、手で消す ${d.remove.length} 件`;
    } else label.textContent = `${S}に入れる`;
  }
  if (!both && outMode === "delta") outMode = "all";
  $("optAll").classList.toggle("sel", outMode === "all");
  $("optDelta").classList.toggle("sel", outMode === "delta");
  $("toA").checked = deltaTo === "a";
  $("toB").checked = deltaTo === "b";
  $("save").textContent = outMode === "all" ? "全部まとめて保存" : `${deltaTo.toUpperCase()}に足りない分を保存`;
  // Banner
  const banner = $("banner");
  if (!sides.A || !sides.B) {
    banner.className = "banner hi";
    banner.textContent = "片方だけ開いています。このまま保存すると、インポートできる形に変えるだけになります。";
  } else if (!changes) {
    banner.className = "banner ok";
    banner.textContent = `差分なし: ${s.same} 件すべて同じです。`;
  } else {
    banner.className = "banner hi";
    banner.textContent = `違いがあります: 違う ${s.differ} 件、Aだけ ${s.onlyA} 件、Bだけ ${s.onlyB} 件（同じ ${s.same} 件）`;
  }
  $("labelA").textContent = "A" + (names.A ? `: ${names.A}` : "");
  $("labelB").textContent = "B" + (names.B ? `: ${names.B}` : "");
  // Rows
  const rows = $("rows");
  rows.replaceChildren();
  const want = (p) => show === "changes" ? p.kind !== "same" : p.kind === show;
  const order = { differ: 0, onlyA: 1, onlyB: 2, same: 3 };
  const list = pairs.filter(want).sort((x, y) => order[x.kind] - order[y.kind]);
  if (!list.length) { rows.append(el("p", { class: "mute", text: "ここに出すものはありません。" })); return; }
  // Grouped by folder (A's folder name, else B's), each group can be folded
  const groups = new Map();
  for (const p of list) {
    const f = folderOf(p);
    if (!groups.has(f)) groups.set(f, []);
    groups.get(f).push(p);
  }
  const folderNames = [...groups.keys()].sort((x, y) => (x === "" ? 1 : y === "" ? -1 : x.localeCompare(y, "ja")));
  for (const f of folderNames) {
    const ps = groups.get(f);
    const n = { differ: 0, onlyA: 0, onlyB: 0, same: 0 };
    ps.forEach((p) => n[p.kind]++);
    const counts = [["differ", "違う"], ["onlyA", "Aだけ"], ["onlyB", "Bだけ"], ["same", "同じ"]].filter(([k]) => n[k]).map(([k, l]) => `${l} ${n[k]}`).join("、");
    const box = el("details", { class: "folder" });
    box.open = !closed.has(f);
    box.addEventListener("toggle", () => { if (box.open) closed.delete(f); else closed.add(f); });
    const bulk = n.differ ? el("span", { class: "bar" }, el("span", { class: "mute", text: "このフォルダの「違う」を:" }),
      ...[["newer", "新しい方"], ["a", "A"], ["b", "B"]].map(([v, t]) => el("button", {
        text: t, onclick: (e) => { e.preventDefault(); for (const p of ps) if (p.kind === "differ") p.choice = v === "newer" ? mg.newer(p.a, p.b) : v; refresh(); },
      }))) : null;
    box.append(el("summary", {}, el("b", { text: f || "（フォルダなし）" }), el("span", { class: "mute", text: `  ${ps.length} 件（${counts}）` })));
    if (bulk) box.append(bulk);
    for (const p of ps) box.append(pairRow(p));
    rows.append(box);
  }
}

const closed = new Set(); // folders the person folded

function folderOf(p) {
  const name = (exp, item) => (item?.folderId ? (exp?.folders ?? []).find((f) => f.id === item.folderId)?.name : null);
  return name(sides.A, p.a) ?? name(sides.B, p.b) ?? "";
}

function update() {
  const ready = sides.A || sides.B;
  $("cmp").hidden = !ready;
  $("out").hidden = !ready;
  if (!ready) return;
  // One side only: everything is "only", which turns the page into a converter
  pairs = mg.compare(sides.A ?? { items: [], folders: [] }, sides.B ?? { items: [], folders: [] });
  show = null;
  refresh();
}

for (const b of document.querySelectorAll("[data-all]")) {
  b.onclick = () => {
    for (const p of pairs) if (p.kind === "differ") p.choice = b.dataset.all === "newer" ? mg.newer(p.a, p.b) : b.dataset.all;
    refresh();
  };
}
$("reveal").onclick = () => { reveal = !reveal; $("reveal").textContent = reveal ? "隠す" : "隠した値を見せる"; refresh(); };

// ---------------------------------------------------------------- saving

// mode: "all" (everything, for an empty account) | "a" | "b" (only what that side lacks, to import into it)
async function save(mode) {
  const om = $("om"), p1 = $("op1"), p2 = $("op2");
  const buttons = [$("save")];
  if (mode !== "all" && !(sides.A && sides.B)) { om.textContent = "足りない分を出すには、AとBの両方を開いてください。"; return; }
  if (p1.value.length < 12) { om.textContent = "ファイルのパスワードは12文字以上にしてください。"; return; }
  if (p1.value !== p2.value) { om.textContent = "2つのパスワードが違います。"; return; }
  buttons.forEach((b) => { b.disabled = true; });
  $("removeBox").hidden = true;
  try {
    const A = sides.A ?? { items: [], folders: [] }, B = sides.B ?? { items: [], folders: [] };
    let out, remove = [];
    if (mode === "all") out = mg.build(A, B, pairs);
    else ({ plain: out, remove } = mg.buildDelta(A, B, pairs, mode));
    if (!out.items.length && !remove.length) { om.textContent = "足りない分はありません。保存するものがないので、ファイルは作っていません。"; return; }
    const kdfCfg = $("okdf").value === "pbkdf2" ? { kdfType: tw.KDF_PBKDF2, iterations: 600000 } : tw.ARGON2ID_DEFAULT;
    const doc = await tw.makeProtectedExport(out, p1.value, kdfCfg, (x) => { om.textContent = `暗号化中… ${Math.round(x * 100)}%`; });
    // Check the file opens before handing it over
    om.textContent = "開けるか確かめています…";
    const back = await tw.openProtectedExport(doc, p1.value, () => {});
    if (back.items.length !== out.items.length) throw new Error("確かめたら件数が合いませんでした");
    p1.value = p2.value = "";
    if (out.items.length) {
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const d = new Date(), z = (n) => String(n).padStart(2, "0");
      const tag = mode === "all" ? "merged" : `for-${mode.toUpperCase()}`;
      const a = el("a", { href: URL.createObjectURL(blob), download: `tinywarden-${tag}-${d.getFullYear()}${z(d.getMonth() + 1)}${z(d.getDate())}.json` });
      document.body.append(a);
      a.click();
      a.remove();
    }
    const where = mode === "all" ? "空のアカウント" : `${mode.toUpperCase()}（${names[mode.toUpperCase()] || "今のアカウント"}）`;
    om.textContent = (out.items.length ? `保存しました: 項目 ${out.items.length} 件、フォルダ ${out.folders.length} 個。${where}で、インポートの形式に「Bitwarden (json)」を選び、このファイルのパスワードを入れてください。` : "インポートするものはありません。")
      + (remove.length ? ` そのあと、下の ${remove.length} 件を手で消してください。` : "");
    if (remove.length) {
      $("removeTitle").textContent = `${mode.toUpperCase()}で手で消す項目（${remove.length} 件）`;
      $("removeList").replaceChildren(...remove.map((r) => el("li", { text: [r.name ?? "（名前なし）", r.username ? ` / ${r.username}` : "", r.folder ? `（フォルダ: ${r.folder}）` : ""].join("") })));
      $("removeBox").hidden = false;
    }
  } catch (e) {
    om.textContent = "保存できませんでした: " + (e.message || e);
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}
$("save").onclick = () => save(outMode === "all" ? "all" : deltaTo);
$("optAll").onclick = () => { outMode = "all"; refresh(); };
$("optDelta").onclick = (e) => { if (!(sides.A && sides.B)) return; outMode = "delta"; if (e.target.name === "to") deltaTo = e.target.value; refresh(); };

buildSide("A");
buildSide("B");
