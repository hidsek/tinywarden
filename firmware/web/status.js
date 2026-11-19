// Buttons on the status page (/). The page sets a Content-Security-Policy that allows only scripts
// from the board itself, so the page's behaviour lives here instead of inline.
const $ = (id) => document.getElementById(id);

// The board answers in English (the same messages the apps get); show them in Japanese here
const JA = {
  "Missing confirmation": "確認のヘッダーがありません（ページを読み直してください）",
  "Email and master password are required": "メールとマスターパスワードが要ります",
  "Button not pressed within 30 seconds": "30秒以内にBOOTボタンが押されませんでした",
  "Too many failed attempts. This tinywarden has been erased": "失敗が多すぎたので、tinywardenの中身を全部消しました",
  "Email or master password is incorrect": "メールかマスターパスワードが違います（失敗の回数に数えました）",
  "No user": "アカウントがありません",
  "Start again: the confirmation expired (2 minutes) or was used": "最初からやり直してください（BOOTを押してから2分が過ぎたか、もう使った確認です）",
  "Invalid KDF settings, key or hash": "KDFの設定か、包み直した鍵の形が正しくありません",
  "Could not save": "保存できませんでした",
};
const ja = (m) => JA[m] ?? m;

// ---------------------------------------------------------------- 控えを保存
$("bb").onclick = async () => {
  const bb = $("bb"), bm = $("bm"), be = $("be"), bp = $("bp");
  const email = be.value.trim().toLowerCase(), pw = bp.value;
  if (!email || !pw) { bm.textContent = "メールとマスターパスワードを入れてください。"; return; }
  bb.disabled = true;
  try {
    bm.textContent = "準備中…";
    // Loaded only when needed: Argon2id is about 55 KB
    const tw = await import("./twcrypto.js");
    const pr = await fetch("/identity/accounts/prelogin", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }),
    });
    const pre = await pr.json();
    const name = pre.kdf === tw.KDF_ARGON2ID ? "Argon2id" : "PBKDF2";
    bm.textContent = `マスターパスワードを計算中（${name}）…`;
    const mk = await tw.masterKey(pw, email, pre, (p) => { bm.textContent = `マスターパスワードを計算中（${name}）… ${Math.round(p * 100)}%`; });
    const mph = await tw.masterPasswordHash(mk, pw);
    bp.value = "";
    bm.textContent = "基板のLEDが光っているあいだ（30秒以内）にBOOTボタンを押してください。";
    const r = await fetch("/tw/backup", {
      method: "POST", headers: { "X-tinywarden-Confirm": "backup", "Content-Type": "application/json" },
      body: JSON.stringify({ email, masterPasswordHash: mph }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      bm.textContent = "保存していません: " + ja(j.message || String(r.status));
      return;
    }
    bm.textContent = "読み出し中…";
    const blob = await r.blob();
    const d = new Date(), p2 = (n) => String(n).padStart(2, "0");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `tinywarden-backup-${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    bm.textContent = `保存しました（${Math.round(blob.size / 1024)} KB）。`;
  } catch (e) {
    bm.textContent = "失敗しました: " + e;
  } finally {
    bb.disabled = false;
  }
};

// ---------------------------------------------------------------- 鍵を作る計算を変える
const TARGETS = {
  argon2id: { kdf: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4, label: "Argon2id" },
  pbkdf2: { kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null, label: "PBKDF2" },
};

$("kb").onclick = async () => {
  const kb = $("kb"), km = $("km"), ke = $("ke"), kp = $("kp");
  const email = ke.value.trim().toLowerCase(), pw = kp.value;
  const target = TARGETS[$("kt").value];
  if (!email || !pw) { km.textContent = "メールとマスターパスワードを入れてください。"; return; }
  kb.disabled = true;
  try {
    km.textContent = "準備中…";
    const tw = await import("./twcrypto.js");
    const post = async (path, body) => {
      const r = await fetch(path, {
        method: "POST", headers: { "X-tinywarden-Confirm": "kdf", "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(ja(j.message || j.ErrorModel?.Message || String(r.status)));
      return j;
    };
    const pre = await (await fetch("/identity/accounts/prelogin", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }),
    })).json();
    const progress = (what) => (p) => { km.textContent = `${what} ${Math.round(p * 100)}%`; };
    km.textContent = "今のマスターキーを計算中…";
    const oldMk = await tw.masterKey(pw, email, pre, progress("今のマスターキーを計算中…"));
    const oldHash = await tw.masterPasswordHash(oldMk, pw);

    km.textContent = "基板のLEDが光っているあいだ（30秒以内）にBOOTボタンを押してください。";
    const cur = await post("/tw/kdf/key", { email, masterPasswordHash: oldHash });
    if (cur.kdf === target.kdf && cur.kdfIterations === target.kdfIterations &&
        (target.kdf === 0 || (cur.kdfMemory === target.kdfMemory && cur.kdfParallelism === target.kdfParallelism))) {
      km.textContent = `もう${target.label}の同じ設定です。変えていません。`;
      return;
    }
    // From here on there are 2 minutes before the board forgets the confirmation
    const userKey = await tw.decBytes(cur.key, await tw.stretch(oldMk));
    if (userKey.length !== 64) throw new Error("保管庫の鍵の形が想定と違います");
    km.textContent = `新しいマスターキーを計算中（${target.label}）…`;
    const newMk = await tw.masterKey(pw, email, target, progress(`新しいマスターキーを計算中（${target.label}）…`));
    const newKeys = await tw.stretch(newMk);
    const wrapped = await tw.enc(userKey, newKeys);
    // Check before sending: the new wrapping must open to the same user key
    const back = await tw.decBytes(wrapped, newKeys);
    if (back.length !== 64 || back.some((v, i) => v !== userKey[i])) throw new Error("包み直した鍵の確認に失敗しました");
    const newHash = await tw.masterPasswordHash(newMk, pw);
    kp.value = "";
    km.textContent = "保存中…";
    await post("/tw/kdf", {
      token: cur.token, masterPasswordHash: newHash, key: wrapped,
      kdf: target.kdf, kdfIterations: target.kdfIterations, kdfMemory: target.kdfMemory, kdfParallelism: target.kdfParallelism,
    });
    km.textContent = `${target.label}に変えました。すべての機器がログアウトします。ログインし直してください。`;
    setTimeout(() => location.reload(), 3000);
  } catch (e) {
    km.textContent = "変えていません: " + (e.message || e);
  } finally {
    kb.disabled = false;
  }
};

// ---------------------------------------------------------------- 全部消す
{
  const c = $("wc"), b = $("wb"), m = $("wm");
  c.oninput = () => { b.disabled = c.value !== "消去"; };
  b.onclick = async () => {
    b.disabled = true;
    c.disabled = true;
    m.textContent = "基板のLEDが光っているあいだ（30秒以内）にBOOTボタンを押してください。押すと消去が始まります（30秒ほどかかります）。";
    try {
      const r = await fetch("/tw/wipe", { method: "POST", headers: { "X-tinywarden-Confirm": "wipe-all" } });
      const j = await r.json().catch(() => ({}));
      m.textContent = r.ok ? "消しました。拡張機能はログアウトされます。アカウントを作り直してください。" : "消していません: " + ja(j.message || String(r.status));
      if (r.ok) setTimeout(() => location.reload(), 1500);
      else { c.disabled = false; c.value = ""; }
    } catch (e) {
      m.textContent = "通信に失敗しました: " + e;
      c.disabled = false;
    }
  };
}
