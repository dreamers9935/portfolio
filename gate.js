/* Password gate: PBKDF2-SHA256 -> AES-256-GCM. Files are [12-byte IV][ciphertext+tag]. */
(function () {
  const BASE = document.documentElement.dataset.base || "p/";
  const MODE = document.documentElement.dataset.mode || "site"; // "site" | "reel"
  const $ = id => document.getElementById(id);
  const form = $("g-form"), pw = $("g-pw"), msg = $("g-msg"), btn = $("g-btn"), bar = $("g-bar");

  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = u => btoa(String.fromCharCode(...new Uint8Array(u)));
  const say = (t, err) => { msg.textContent = t; msg.classList.toggle("err", !!err); };
  const progress = p => { bar.style.setProperty("--p", Math.max(0, Math.min(1, p)).toFixed(3)); };

  async function getBin(url, onp) {
    const r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error("HTTP " + r.status + " for " + url);
    const total = +(r.headers.get("content-length") || 0);
    if (!r.body || !onp) return new Uint8Array(await r.arrayBuffer());
    const rd = r.body.getReader(), parts = []; let n = 0;
    for (;;) { const { done, value } = await rd.read(); if (done) break; parts.push(value); n += value.length; if (total) onp(Math.min(n / total, 1)); }
    const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const open = async (key, buf) => new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.subarray(0, 12) }, key, buf.subarray(12)));

  async function derive(pass) {
    const m = await (await fetch(BASE + "meta.json", { cache: "no-cache" })).json();
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(m.salt), iterations: m.iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function verify(key) {
    const t = new TextDecoder().decode(await open(key, await getBin(BASE + "check.bin")));
    if (t !== "ok") throw new Error("bad check");
  }
  const loadReel = key => async onp => {
    const buf = await getBin(BASE + "reel.bin", onp);
    return URL.createObjectURL(new Blob([await open(key, buf)], { type: "video/mp4" }));
  };

  async function showSite(key) {
    say("Unlocking…");
    const plain = await open(key, await getBin(BASE + "site.bin", p => progress(p * 0.9)));
    const n = new DataView(plain.buffer, plain.byteOffset, 4).getUint32(0, true);
    const head = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + n)));
    const data = 4 + n, assets = {};
    for (const [path, off, len, type] of head.files) assets[path] = URL.createObjectURL(new Blob([plain.subarray(data + off, data + off + len)], { type }));
    window.__ASSETS = assets;
    window.__loadReel = loadReel(key);
    progress(1);
    document.open(); document.write(head.html); document.close();
  }

  async function showReel(key) {
    say("Decrypting the reel…");
    const url = await loadReel(key)(p => { progress(p); say("Decrypting the reel… " + Math.round(p * 100) + "%"); });
    const v = $("g-video");
    v.src = url;
    document.body.classList.add("reel-ready");
    say("");
    try { await v.play(); } catch (e) { /* needs a tap; controls are visible */ }
  }

  async function go(key, remembered) {
    try {
      btn.disabled = true; document.body.classList.add("busy");
      await verify(key);
      try { sessionStorage.setItem("pf-key", toB64(await crypto.subtle.exportKey("raw", key))); } catch (e) {}
      if (MODE === "reel") await showReel(key); else await showSite(key);
    } catch (e) {
      btn.disabled = false; document.body.classList.remove("busy"); progress(0);
      try { sessionStorage.removeItem("pf-key"); } catch (_) {}
      if (!remembered) say(e && e.name === "OperationError" ? "That password doesn't match." : "Couldn't unlock: " + (e.message || e), true);
      pw.focus(); pw.select();
    }
  }

  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    if (!pw.value) return;
    say("Checking…");
    try { await go(await derive(pw.value), false); } catch (e) { say("Couldn't unlock: " + (e.message || e), true); btn.disabled = false; }
  });

  // same-tab reloads stay unlocked
  (async () => {
    let raw = null; try { raw = sessionStorage.getItem("pf-key"); } catch (e) {}
    if (!raw) return;
    try { const key = await crypto.subtle.importKey("raw", b64(raw), { name: "AES-GCM" }, true, ["decrypt"]); await go(key, true); } catch (e) {}
  })();
})();
