// The locked page (/ before unlocking). Served without a session, so it says nothing about what the
// device is: only the hash the apps send at login is computed here (same rules as twcrypto.js, which is
// served only after unlocking), then POST /s/unlock checks it like a login (button, failure counter).
// Before an account exists, the page asks for the one-time code instead.
import { argon2idAsync } from "./vendor/noble-hashes/argon2.js";

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

async function pbkdf2(password, salt, iterations) {
  const k = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, k, 256));
}

function b64(u8) {
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}

// pre: the prelogin answer {kdf, kdfIterations, kdfMemory, kdfParallelism}
export async function loginHash(username, password, pre, onProgress) {
  const pw = te.encode(password);
  const salt = te.encode(username.trim().toLowerCase());
  let mk;
  if (pre.kdf === 1) {
    const ok = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
    if (!ok(pre.kdfIterations, 2, 10) || !ok(pre.kdfMemory, 16, 1024) || !ok(pre.kdfParallelism, 1, 16)) throw new Error("設定が範囲外です");
    const s = new Uint8Array(await subtle.digest("SHA-256", salt));
    mk = await argon2idAsync(pw, s, { t: pre.kdfIterations, m: pre.kdfMemory * 1024, p: pre.kdfParallelism, dkLen: 32, onProgress });
  } else {
    if (!Number.isInteger(pre.kdfIterations) || pre.kdfIterations < 5000 || pre.kdfIterations > 2000000) throw new Error("設定が範囲外です");
    mk = await pbkdf2(pw, salt, pre.kdfIterations);
  }
  return b64(await pbkdf2(mk, pw, 1));
}

const MSG = {
  "Button not pressed within 30 seconds": "30秒以内に本体のボタンが押されませんでした",
  "Username or master password is incorrect": "ユーザー名かパスワードが違います（失敗の回数に数えました）",
  "Too many failed attempts. The device has been erased": "失敗が多すぎたので、中身を全部消しました",
  "Old format. Erase the device and set it up again": "古い形式です。消して作り直してください",
};

const $ = (id) => document.getElementById(id);

async function post(body) {
  return fetch("/s/unlock", {
    method: "POST", headers: { "X-Confirm": "unlock", "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
}

if ($("ub")) {
  $("ub").onclick = async () => {
    const ub = $("ub"), um = $("um");
    const codeMode = !!$("uc");
    ub.disabled = true;
    try {
      let r;
      if (codeMode) {
        // Before an account exists: the one-time code shown when the firmware was written
        const code = $("uc").value.trim();
        if (!code) { um.textContent = "コードを入れてください。"; return; }
        um.textContent = "30秒以内に本体のボタンを押してください。";
        r = await post({ setupCode: code });
      } else {
        const uu = $("uu"), up = $("up");
        const username = uu.value.trim().toLowerCase(), password = up.value;
        if (!username || !password) { um.textContent = "ユーザー名とパスワードを入れてください。"; return; }
        um.textContent = "計算中…";
        const pre = await (await fetch("/identity/accounts/prelogin", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: username }),
        })).json();
        const hash = await loginHash(username, password, pre, (p) => { um.textContent = `計算中… ${Math.round(p * 100)}%`; });
        up.value = "";
        um.textContent = "30秒以内に本体のボタンを押してください。";
        r = await post({ masterPasswordHash: hash });
      }
      if (r.ok) { location.reload(); return; }
      const j = await r.json().catch(() => ({}));
      um.textContent = codeMode && j.message === "Username or master password is incorrect"
        ? "コードが違います。" : MSG[j.message] ?? j.message ?? String(r.status);
    } catch (e) {
      um.textContent = "失敗しました: " + e;
    } finally {
      ub.disabled = false;
    }
  };
}
