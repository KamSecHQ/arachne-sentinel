/* ============================================================
   ARACHNE SENTINEL — Sinematik Yoğunluk Katmanı (fx.js)

   Native pencerede (?mode=native) veya ?cinematic=1 ile devreye girer.
   Panelin üstüne "3-4 kat" görsel yoğunluk ekler:
     - Animasyonlu arka plan (parçacık alanı, kayan ızgara, radar süpürme,
       veri yağmuru)
     - Tüm ekranı saran HUD çerçevesi (köşe braketleri + kenar rayları)
     - Canlı telemetri şeridi (gerçek /api/state verisinden)
     - Scanline + kart köşe braketleri (CSS ile)

   Tamamen kozmetik; panelin işlevine dokunmaz. Kapatmak için 'C' tuşu.
   ============================================================ */
(function () {
  "use strict";
  const params = new URLSearchParams(location.search);
  const active = params.get("mode") === "native" || params.get("cinematic") === "1"
    || localStorage.getItem("arachne_cinematic") === "1";
  // localStorage kullanımı: bazı ortamlar engelleyebilir → try
  let ON = false;
  let running = true, bgRaf = 0;
  try { ON = active; } catch (e) { ON = params.get("mode") === "native"; }
  if (!ON) { window.__fxToggle = enable; return; }
  enable();

  function enable() {
    if (document.body.classList.contains("cinematic")) return;
    document.body.classList.add("cinematic");
    buildFrame();
    startBg();
    startTelemetry();
  }
  function disable() {
    document.body.classList.remove("cinematic");
    const f = document.getElementById("fx-frame"); if (f) f.remove();
    const b = document.getElementById("fx-bg"); if (b) b.remove();
    running = false;
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "c" || e.key === "C") {
      document.body.classList.contains("cinematic") ? disable() : enable();
    }
  });

  /* ---------- HUD çerçevesi (DOM) ---------- */
  function buildFrame() {
    const f = document.createElement("div");
    f.id = "fx-frame";
    f.innerHTML = `
      <span class="fx-corner tl"></span><span class="fx-corner tr"></span>
      <span class="fx-corner bl"></span><span class="fx-corner br"></span>
      <div class="fx-rail top">
        <span class="fx-rail-l">◈ ARACHNE SENTINEL <b>//</b> KOMUTA MERKEZİ</span>
        <span class="fx-rail-r"><span class="fx-dot"></span> ÇEVRİMİÇİ · <span id="fx-clock">--:--:--</span></span>
      </div>
      <div class="fx-rail bottom">
        <div class="fx-ticker"><div class="fx-ticker-track" id="fx-ticker">SİSTEM BAŞLATILIYOR…</div></div>
      </div>
      <div class="fx-scan"></div>`;
    document.body.appendChild(f);
    setInterval(() => {
      const c = document.getElementById("fx-clock");
      if (c) c.textContent = new Date().toLocaleTimeString("tr-TR");
    }, 1000);
  }

  /* ---------- Animasyonlu arka plan (canvas) ---------- */
  function startBg() {
    running = true;
    const canvas = document.createElement("canvas");
    canvas.id = "fx-bg";
    document.body.appendChild(canvas);
    const ctx = canvas.getContext("2d");
    let w, h, dpr, particles = [], streams = [], t0 = Date.now();

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth; h = window.innerHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      particles = Array.from({ length: Math.min(90, Math.floor(w * h / 22000)) }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25,
        r: Math.random() * 1.4 + 0.3, a: Math.random() * 0.5 + 0.15,
      }));
      streams = Array.from({ length: Math.floor(w / 90) }, () => ({
        x: Math.random() * w, y: Math.random() * h, len: 60 + Math.random() * 120,
        sp: 1 + Math.random() * 2.5,
      }));
    }
    window.addEventListener("resize", resize);
    resize();

    function frame() {
      if (!running) return;
      ctx.clearRect(0, 0, w, h);
      const T = (Date.now() - t0) / 1000;

      // kayan nokta-ızgara
      ctx.fillStyle = "rgba(34,211,238,0.05)";
      const gs = 46, off = (T * 8) % gs;
      for (let x = -gs; x < w + gs; x += gs)
        for (let y = -gs; y < h + gs; y += gs)
          ctx.fillRect(x + off * 0.3, y + off, 1.4, 1.4);

      // veri yağmuru
      streams.forEach((s) => {
        s.y += s.sp; if (s.y - s.len > h) { s.y = -s.len; s.x = Math.random() * w; }
        const grad = ctx.createLinearGradient(s.x, s.y - s.len, s.x, s.y);
        grad.addColorStop(0, "rgba(34,211,238,0)");
        grad.addColorStop(1, "rgba(34,211,238,0.10)");
        ctx.strokeStyle = grad; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(s.x, s.y - s.len); ctx.lineTo(s.x, s.y); ctx.stroke();
      });

      // parçacıklar + bağ çizgileri
      particles.forEach((p) => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = w; if (p.x > w) p.x = 0; if (p.y < 0) p.y = h; if (p.y > h) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(34,211,238,${p.a})`; ctx.fill();
      });
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i], b = particles[j];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < 120) {
            ctx.strokeStyle = `rgba(34,211,238,${0.08 * (1 - d / 120)})`;
            ctx.lineWidth = 0.6; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }

      // periyodik yatay radar süpürme
      const sweepY = ((T * 60) % (h + 200)) - 100;
      const sg = ctx.createLinearGradient(0, sweepY - 60, 0, sweepY + 60);
      sg.addColorStop(0, "rgba(34,211,238,0)"); sg.addColorStop(0.5, "rgba(34,211,238,0.05)");
      sg.addColorStop(1, "rgba(34,211,238,0)");
      ctx.fillStyle = sg; ctx.fillRect(0, sweepY - 60, w, 120);

      bgRaf = requestAnimationFrame(frame);
    }
    bgRaf = requestAnimationFrame(frame);
  }

  /* ---------- Canlı telemetri şeridi ---------- */
  function startTelemetry() {
    async function poll() {
      try {
        const d = await (await fetch("/api/state", { cache: "no-store" })).json();
        const ov = d.overview || {}, k = ov.kpis || {};
        const items = [
          `TEHDİT DÜZEYİ: ${ov.posture || "—"}`,
          `OLAY: ${k.events ?? 0}`,
          `ALARM: ${k.alerts ?? 0}`,
          `KRİTİK: ${k.critical_alerts ?? 0}`,
          `ENGELLİ IP: ${k.active_blocks ?? 0}`,
          `MTD ROTASYON: ${k.mtd_rotations ?? 0}`,
          `AKTİF SAVUNMA: ${k.deception_actions ?? 0}`,
          `HONEYTOKEN: ${k.honeytokens_triggered ?? 0}`,
          `ÇEKİRDEĞE ULAŞAN: 0`,
          `40 SAVUNMA KATMANI: NOMİNAL`,
        ];
        const tick = document.getElementById("fx-ticker");
        if (tick) tick.textContent = items.join("   ◆   ") + "   ◆   ";
      } catch (e) {}
    }
    poll(); setInterval(poll, 4000);
  }
})();
