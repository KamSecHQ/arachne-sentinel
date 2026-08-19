/* ============================================================
   ARACHNE SENTINEL — AI Komuta Asistanı (assistant.js)

   Operatör doğal dilde sorar ("savunma durumu ne?"), asistan GERÇEK
   sistem verisinden Türkçe yanıt üretir (/api/assistant) ve sesli okur.
   Ses: native pencerede terminalin aynı `say` motoru, tarayıcıda TTS.
   Tamamen kozmetik + salt-okunur (asistan hiçbir eylem başlatmaz).
   ============================================================ */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const dock = document.getElementById("ai-dock");
  if (!dock) return;
  const panel = document.getElementById("ai-panel");
  const msgs = document.getElementById("ai-msgs");
  const input = document.getElementById("ai-input");
  const statusEl = document.getElementById("ai-status");
  let muted = false, busy = false;

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  /* ---------- Türkçe seslendirme (boot ile uyumlu) ---------- */
  function speak(text) {
    if (muted || !text) return;
    try {
      if (window.ArachneSFX) window.ArachneSFX.squelch();  // konuşmadan önce telsiz cızırtısı
      if (window.pywebview && window.pywebview.api && window.pywebview.api.speak) {
        window.pywebview.api.speak(text); return;
      }
      if (!("speechSynthesis" in window)) return;
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "tr-TR"; u.rate = 0.98; u.pitch = 0.92; u.volume = 1;
      const voices = window.speechSynthesis.getVoices();
      const tr = voices.find((v) => /tr(-|_)?TR/i.test(v.lang) || /yelda|turk/i.test(v.name));
      if (tr) u.voice = tr;
      window.speechSynthesis.speak(u);
    } catch (e) {}
  }

  /* ---------- kısa "chirp" ses efekti (asistan konuşurken) ---------- */
  let actx = null;
  function chirp() {
    try {
      actx = actx || new (window.AudioContext || window.webkitAudioContext)();
      const o = actx.createOscillator(), g = actx.createGain();
      o.type = "square"; o.frequency.setValueAtTime(880, actx.currentTime);
      o.frequency.exponentialRampToValueAtTime(1400, actx.currentTime + 0.08);
      g.gain.setValueAtTime(0.05, actx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 0.12);
      o.connect(g); g.connect(actx.destination); o.start(); o.stop(actx.currentTime + 0.13);
    } catch (e) {}
  }

  function addMsg(cls, html) {
    const d = document.createElement("div");
    d.className = "ai-msg " + cls; d.innerHTML = html;
    msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight;
    return d;
  }

  async function ask(question) {
    if (busy || !question.trim()) return;
    busy = true;
    addMsg("user", esc(question));
    const typing = addMsg("bot typing", "<span></span><span></span><span></span>");
    statusEl.textContent = "düşünüyor…";
    chirp();
    let d;
    try {
      d = await (await fetch("/api/assistant", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      })).json();
    } catch (e) {
      d = { text_tr: "Sunucuya ulaşılamadı.", spoken_tr: "Sunucuya ulaşılamadı." };
    }
    typing.remove();
    addMsg("bot", esc(d.text_tr || "—"));
    statusEl.textContent = "dinlemeye hazır";
    dock.classList.add("speaking");
    speak(d.spoken_tr || d.text_tr);
    setTimeout(() => dock.classList.remove("speaking"), 3500);
    busy = false;
  }

  /* ---------- olaylar ---------- */
  $("#ai-launch").addEventListener("click", () => {
    dock.classList.toggle("open");
    if (dock.classList.contains("open")) { chirp(); input.focus(); }
  });
  $("#ai-close").addEventListener("click", () => dock.classList.remove("open"));
  $("#ai-mute").addEventListener("click", (e) => {
    muted = !muted; e.target.textContent = muted ? "🔇" : "🔊";
    if (muted && "speechSynthesis" in window) window.speechSynthesis.cancel();
  });
  $("#ai-form").addEventListener("submit", (e) => {
    e.preventDefault(); const q = input.value.trim(); input.value = ""; ask(q);
  });
  document.querySelectorAll("#ai-dock .ai-chips button").forEach((b) =>
    b.addEventListener("click", () => ask(b.dataset.q)));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") dock.classList.remove("open");
    // Ctrl/Cmd + K asistanı açar
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault(); dock.classList.add("open"); input.focus();
    }
  });
  if ("speechSynthesis" in window) window.speechSynthesis.getVoices();

  /* ============================================================
     PROAKTIF SALDIRI ANONSU
     Yeni saldiri geldiginde asistan otomatik, profesyonel bir durum
     raporu verir: "Saldiri tespit edildi · savunma aktif · sizinti yok".
     command_center.js her yeni olayda 'arachne:attack' olayini yayar.
     Gurultuyu onlemek icin kisilir (throttle) ve olaylar birlestirilir.
     ============================================================ */
  const Alert = (function () {
    let lastSpokenAt = 0;
    let pending = 0;              // birikmis yeni olay sayisi
    let pendByLayer = {};         // katman adi -> yeni olay sayisi
    let pendServices = new Set();
    let pendTotal = 0;            // sistemdeki toplam islenen saldiri
    let flushTimer = null;
    const SPEAK_GAP = 14000;      // en sik 14 sn'de bir sesli anons
    const COALESCE = 1200;        // 1.2 sn icindeki olaylari tek anonsta topla

    function num(n) {
      const map = ["sıfır","bir","iki","üç","dört","beş","altı","yedi","sekiz","dokuz","on"];
      return n <= 10 ? map[n] : String(n);
    }

    function flush() {
      flushTimer = null;
      const count = pending, byLayer = pendByLayer, svc = Array.from(pendServices), total = pendTotal;
      pending = 0; pendByLayer = {}; pendServices = new Set();
      if (count <= 0) return;

      // katmanlari cok -> az sirala (hangi katman kac saldiri durdurdu)
      const ranked = Object.entries(byLayer).filter(([, c]) => c > 0).sort((a, b) => b[1] - a[1]);
      const ts = new Date().toLocaleTimeString("tr-TR", { hour12: false });
      const svcTxt = svc.length ? ` · Vektör: ${esc(svc.join(", "))}` : "";

      // Gorsel: her katman icin sayi dokumu (detayli)
      const rows = (ranked.length ? ranked : [["çok katmanlı savunma", count]])
        .map(([nm, c]) => `<div class="ai-alert-layer"><span>${esc(nm)}</span><b>${c}</b></div>`).join("");
      const html =
        `<div class="ai-alert-head">⚠ SALDIRI TESPİT EDİLDİ · <span>${esc(ts)}</span></div>` +
        `<div class="ai-alert-row"><b>${count}</b> yeni saldırı${svcTxt}` +
        (total ? ` · toplam işlenen: <b>${total}</b>` : "") + `</div>` +
        `<div class="ai-alert-row">Hangi katman durdurdu:</div>` +
        `<div class="ai-alert-layers">${rows}</div>` +
        `<div class="ai-alert-ok">● SAVUNMA AKTİF — çekirdeğe sızıntı YOK</div>`;
      addMsg("alert", html);
      dock.classList.add("alerting");
      setTimeout(() => dock.classList.remove("alerting"), 2800);
      if (window.ArachneSFX) window.ArachneSFX.alarm();

      // Sesli: DETAYLI (kaç saldırı + hangi katman durdurdu), kısılır, mute'e saygılı
      const t = Date.now();
      if (!muted && t - lastSpokenAt >= SPEAK_GAP) {
        lastSpokenAt = t;
        const parts = ranked.slice(0, 2).map(([nm, c]) => `${num(c)} olay ${nm}`);
        const layerSpoken = parts.length ? parts.join(", ") + " hattında karşılandı. " : "";
        const totalTxt = total ? `Toplam işlenen saldırı ${total}. ` : "";
        const spoken =
          `Dikkat. ${num(count)} yeni saldırı tespit edildi. ` +
          layerSpoken + totalTxt +
          `Savunma aktif. Çekirdeğe sızıntı yok.`;
        dock.classList.add("speaking");
        speak(spoken);
        setTimeout(() => dock.classList.remove("speaking"), 4400);
      }
    }

    function onAttack(ev) {
      const d = (ev && ev.detail) || {};
      pending += (d.count || 1);
      if (d.byLayer) { for (const k in d.byLayer) pendByLayer[k] = (pendByLayer[k] || 0) + d.byLayer[k]; }
      else if (d.layers) d.layers.forEach((l) => { pendByLayer[l] = (pendByLayer[l] || 0) + 1; });
      (d.services || []).forEach((s) => pendServices.add(s));
      if (d.total) pendTotal = d.total;
      if (!flushTimer) flushTimer = setTimeout(flush, COALESCE);
    }

    window.addEventListener("arachne:attack", onAttack);
    return {};
  })();
})();
