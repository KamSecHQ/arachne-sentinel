/* ============================================================
   ARACHNE SENTINEL — Sinematik açılış (JARVIS-vari boot)

   Tam ekran HUD: nabız atan çekirdek (arc-reactor), dönen tarama
   halkaları, hex ızgara, akan boot log, scanline. Güç düğmesine
   basınca Web Audio ses efektleri + Türkçe TTS anonsu başlar,
   ~7 sn sonra panele eriyerek geçer.

   Ses için güç düğmesi şart: tarayıcılar kullanıcı etkileşimi
   olmadan sesi otomatik başlatmaz (autoplay politikası).
   Tamamen kozmetiktir; panelin işlevine dokunmaz.
   ============================================================ */
(function () {
  "use strict";
  const boot = document.getElementById("boot");
  if (!boot) return;
  const canvas = document.getElementById("boot-canvas");
  const ctx = canvas.getContext("2d");
  const TAU = Math.PI * 2;
  let w = 0, h = 0, dpr = 1, cx = 0, cy = 0, raf = 0, running = true;
  let progress = 0, targetProgress = 0, t0 = Date.now();
  let booting = false, done = false;
  let coreLevel = 0.32, coreTarget = 0.32;   // güç düğmesine basınca 1.0'a ısınır

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cx = w / 2; cy = h * 0.42;
  }
  window.addEventListener("resize", resize);
  resize();

  /* ---------- Web Audio: MAKS sentetik sci-fi ses motoru ----------
     master -> [dry + convolver reverb] -> compressor -> out
     Sub-bass impact, reverb kuyruğu, ring-mod shimmer, dijital glitch,
     "iletişim" band-pass squelch. Hepsi prosedürel, dosyasız. */
  const Audio = (function () {
    let actx = null, master = null, reverb = null, comp = null, drone = null;
    function ensure() {
      if (actx) return actx;
      try { actx = new (window.AudioContext || window.webkitAudioContext)(); }
      catch (e) { actx = null; return null; }
      comp = actx.createDynamicsCompressor();
      comp.threshold.value = -18; comp.ratio.value = 4; comp.attack.value = 0.003;
      master = actx.createGain(); master.gain.value = 0.9;
      // sentetik reverb: gürültü-decay impulse
      reverb = actx.createConvolver();
      const len = actx.sampleRate * 2.4, buf = actx.createBuffer(2, len, actx.sampleRate);
      for (let ch = 0; ch < 2; ch++) {
        const d = buf.getChannelData(ch);
        for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / len, 2.6);
      }
      reverb.buffer = buf;
      const wet = actx.createGain(); wet.gain.value = 0.32;
      master.connect(comp); master.connect(reverb); reverb.connect(wet); wet.connect(comp);
      comp.connect(actx.destination);
      return actx;
    }
    function osc(type, freq) { const o = actx.createOscillator(); o.type = type; o.frequency.value = freq; return o; }
    function env(g, peak, a, d, t0) {
      t0 = t0 || actx.currentTime;
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(peak, t0 + a);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + a + d);
    }
    function beep(freq, dur, type, vol) {
      if (!ensure()) return;
      const o = osc(type || "square", freq), g = actx.createGain();
      const flt = actx.createBiquadFilter(); flt.type = "bandpass"; flt.frequency.value = freq; flt.Q.value = 6;
      env(g, vol || 0.07, 0.006, dur || 0.1);
      o.connect(flt); flt.connect(g); g.connect(master);
      o.start(); o.stop(actx.currentTime + (dur || 0.1) + 0.05);
    }
    function impact() { // power-on: derin sub-bass patlama
      if (!ensure()) return;
      const o = osc("sine", 90), g = actx.createGain();
      o.frequency.setValueAtTime(120, actx.currentTime);
      o.frequency.exponentialRampToValueAtTime(32, actx.currentTime + 0.9);
      env(g, 0.9, 0.01, 1.1); o.connect(g); g.connect(master);
      o.start(); o.stop(actx.currentTime + 1.2);
      // üstüne parlak kıvılcım
      const o2 = osc("sawtooth", 200), g2 = actx.createGain();
      o2.frequency.exponentialRampToValueAtTime(2400, actx.currentTime + 0.5);
      const f = actx.createBiquadFilter(); f.type = "lowpass"; f.frequency.value = 2600;
      env(g2, 0.14, 0.02, 0.7); o2.connect(f); f.connect(g2); g2.connect(master);
      o2.start(); o2.stop(actx.currentTime + 0.8);
    }
    function sweep(f1, f2, dur, vol) {
      if (!ensure()) return;
      const o = osc("sawtooth", f1), g = actx.createGain();
      o.frequency.exponentialRampToValueAtTime(f2, actx.currentTime + dur);
      const flt = actx.createBiquadFilter(); flt.type = "lowpass"; flt.frequency.value = 2200;
      env(g, vol || 0.12, dur * 0.3, dur * 0.8); o.connect(flt); flt.connect(g); g.connect(master);
      o.start(); o.stop(actx.currentTime + dur + 0.1);
    }
    function glitch() { // kısa dijital cızırtı
      if (!ensure()) return;
      const len = actx.sampleRate * 0.09, buf = actx.createBuffer(1, len, actx.sampleRate);
      const d = buf.getChannelData(0);
      for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * (i % 7 < 3 ? 1 : 0.2);
      const s = actx.createBufferSource(); s.buffer = buf;
      const f = actx.createBiquadFilter(); f.type = "bandpass"; f.frequency.value = 1400 + Math.random() * 1200; f.Q.value = 9;
      const g = actx.createGain(); env(g, 0.05, 0.005, 0.08);
      s.connect(f); f.connect(g); g.connect(master); s.start();
    }
    function squelch() { // "iletişim açıldı" radyo cızırtısı (voice öncesi)
      if (!ensure()) return;
      glitch(); setTimeout(glitch, 40);
      beep(1100, 0.05, "square", 0.05);
    }
    function startDrone() {
      if (!ensure() || drone) return;
      const a = osc("sine", 42), b = osc("sine", 63), c = osc("triangle", 84);
      const g = actx.createGain(); g.gain.setValueAtTime(0.0001, actx.currentTime);
      g.gain.linearRampToValueAtTime(0.06, actx.currentTime + 1.4);
      // yavaş LFO ile "nefes"
      const lfo = osc("sine", 0.12), lg = actx.createGain(); lg.gain.value = 0.02;
      lfo.connect(lg); lg.connect(g.gain);
      a.connect(g); b.connect(g); c.connect(g); g.connect(master);
      a.start(); b.start(); c.start(); lfo.start();
      drone = { nodes: [a, b, c, lfo], g };
    }
    function stopDrone() {
      if (!actx || !drone) return;
      try {
        drone.g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime + 1.0);
        drone.nodes.forEach((n) => n.stop(actx.currentTime + 1.1));
      } catch (e) {}
      drone = null;
    }
    function resume() { if (ensure() && actx.state === "suspended") actx.resume(); }
    return { beep, impact, sweep, glitch, squelch, startDrone, stopDrone, resume };
  })();

  /* ---------- Derin SENTETİK erkek anons ----------
     Native pencerede terminalin AYNI `say` motorunu kullanır (birebir aynı
     ses). Tarayıcıda ise derin/erkek TTS'e düşer. Öncesinde "iletişim açıldı"
     cızırtısı + altına glitch dokusu = sentetik AI hissi. */
  function speak(text) {
    try {
      Audio.squelch();               // konuşmadan önce radyo cızırtısı
      setTimeout(() => Audio.glitch(), 120);

      // 1) Native pencere: terminalle birebir aynı `say` motoru
      if (window.pywebview && window.pywebview.api && window.pywebview.api.speak) {
        window.pywebview.api.speak(text);
        return;
      }
      // 2) Tarayıcı fallback: NET Türkçe TTS.
      //    Türkçe metni İngilizce bir sesle okutmak ı/i, ş/s, ç/c'yi bozuyordu;
      //    bu yüzden DAİMA gerçek Türkçe sesi (Yelda vb.) seçip doğal perdede
      //    okuyoruz — anlaşılırlık, "sentetik derinlik"ten önce gelir.
      if (!("speechSynthesis" in window)) return;
      window.speechSynthesis.cancel();   // TEK KONUSMACI: öncekini kes, üst üste binme yok
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "tr-TR";
      u.rate = 0.98;
      u.pitch = 0.92;                // doğal perde = net ı/i ayrımı
      u.volume = 1;
      const voices = window.speechSynthesis.getVoices();
      const tr = voices.find((v) => /tr(-|_)?TR/i.test(v.lang))
             || voices.find((v) => /yelda|turk|türk/i.test(v.name));
      u.voice = tr || null;
      window.speechSynthesis.speak(u);
    } catch (e) {}
  }

  /* ---------- HUD çizimi ---------- */
  const sparks = [];
  function drawHex() {
    ctx.strokeStyle = "rgba(34,211,238,0.05)";
    ctx.lineWidth = 1;
    const s = 34, hgt = s * Math.sqrt(3);
    for (let y = -hgt; y < h + hgt; y += hgt) {
      for (let x = -s; x < w + s; x += s * 1.5) {
        const off = ((x / (s * 1.5)) % 2) * (hgt / 2);
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const a = (i / 6) * TAU + Math.PI / 6;
          const px = x + Math.cos(a) * s * 0.5, py = y + off + Math.sin(a) * s * 0.5;
          i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
        }
        ctx.closePath(); ctx.stroke();
      }
    }
  }
  function ring(r, seg, gap, speed, width, alpha, dir) {
    const t = (Date.now() - t0) / 1000 * speed * (dir || 1);
    ctx.lineWidth = width;
    for (let i = 0; i < seg; i++) {
      const a0 = (i / seg) * TAU + t;
      ctx.beginPath();
      ctx.arc(cx, cy, r, a0, a0 + (TAU / seg) * (1 - gap));
      ctx.strokeStyle = `rgba(34,211,238,${alpha})`;
      ctx.stroke();
    }
  }
  function draw() {
    if (!running) return;
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "rgba(3,6,10,0.35)"; ctx.fillRect(0, 0, w, h);
    drawHex();

    const pulse = 0.5 + 0.5 * Math.sin((Date.now() - t0) / 380);
    const base = Math.min(w, h) * 0.16;

    // dış tarama halkaları
    ring(base * 2.15, 3, 0.35, 0.4, 2, 0.4, 1);
    ring(base * 1.75, 24, 0.5, -0.25, 1.5, 0.22, -1);
    ring(base * 1.4, 6, 0.28, 0.7, 2.5, 0.5, 1);
    ring(base * 1.08, 40, 0.55, 0.5, 1, 0.18, -1);

    // ilerleme yayı
    ctx.beginPath();
    ctx.arc(cx, cy, base * 2.4, -Math.PI / 2, -Math.PI / 2 + TAU * (progress / 100));
    ctx.strokeStyle = "rgba(34,211,238,0.9)"; ctx.lineWidth = 3; ctx.stroke();

    // çekirdek (arc reactor) — güç açılınca ısınır (coreLevel)
    coreLevel += (coreTarget - coreLevel) * 0.06;
    const L = coreLevel;
    const cr = base * (0.4 + pulse * 0.06) * (0.7 + L * 0.3);
    const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, cr * 2.2);
    g.addColorStop(0, `rgba(120,240,255,${0.95 * L})`);
    g.addColorStop(0.35, `rgba(34,211,238,${0.55 * L})`);
    g.addColorStop(1, "rgba(34,211,238,0)");
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, cr * 2.2, 0, TAU); ctx.fill();
    ctx.beginPath(); ctx.arc(cx, cy, cr * 0.5 * (0.6 + L * 0.4), 0, TAU);
    ctx.fillStyle = `rgba(220,250,255,${0.55 + 0.4 * L})`; ctx.fill();

    // çekirdek etrafı üçgen çentikler
    ctx.save(); ctx.translate(cx, cy);
    ctx.rotate((Date.now() - t0) / 2400);
    for (let i = 0; i < 12; i++) {
      ctx.rotate(TAU / 12);
      ctx.beginPath(); ctx.moveTo(cr * 0.72, 0); ctx.lineTo(cr * 0.92, 5); ctx.lineTo(cr * 0.92, -5);
      ctx.closePath(); ctx.fillStyle = `rgba(34,211,238,${0.4 + pulse * 0.3})`; ctx.fill();
    }
    ctx.restore();

    // kıvılcımlar (boot sırasında)
    if (booting && Math.random() < 0.4) {
      const a = Math.random() * TAU, r = base * (1 + Math.random());
      sparks.push({ x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r, vx: Math.cos(a) * 1.5, vy: Math.sin(a) * 1.5, life: 1 });
    }
    for (let i = sparks.length - 1; i >= 0; i--) {
      const s = sparks[i]; s.x += s.vx; s.y += s.vy; s.life -= 0.02;
      if (s.life <= 0) { sparks.splice(i, 1); continue; }
      ctx.beginPath(); ctx.arc(s.x, s.y, 1.6, 0, TAU);
      ctx.fillStyle = `rgba(120,240,255,${s.life})`; ctx.fill();
    }

    // ilerlemeyi yumuşat
    progress += (targetProgress - progress) * 0.08;
    raf = requestAnimationFrame(draw);
  }
  raf = requestAnimationFrame(draw);

  /* ---------- Boot dizisi ---------- */
  const LINES = [
    ["ÇEKİRDEK", "Bilişsel çekirdek başlatılıyor", 8],
    ["BELLEK", "Yerel vektör bellek senkronize", 16],
    ["SENSÖR", "Sensör ağı + sağlık telemetrisi bağlandı", 26],
    ["SIEM", "Normalizasyon hattı açık", 36],
    ["SAVUNMA", "18 savunma halkası / 70 faz yüklendi", 52],
    ["ADAPTİF", "Ko-evrim motorları kalibre", 64],
    ["SOAR", "Otonom müdahale hazır", 74],
    ["BÜTÜNLÜK", "Kurcalama-kanıtı zincir doğrulandı", 84],
    ["KUBBE", "Çelik Kubbe 18 halka aktif", 94],
    ["ÇEVRİMİÇİ", "Tüm savunma katmanları nominal", 100],
  ];
  // Terminal + native pencere + asistan ile BİREBİR aynı ses (Türkçe, uyumlu).
  const VOICE_LINE = "Komuta merkezi devrede. Yetmiş faz aktif. " +
    "Tüm savunma katmanları çevrimiçi. Sistem hazır.";
  const logEl = document.getElementById("boot-log");
  const barEl = document.getElementById("boot-bar-fill");
  const statusEl = document.getElementById("boot-status");

  function addLog(tag, desc) {
    const line = document.createElement("div");
    line.className = "bl-line";
    line.innerHTML = `<span class="bl-tag">[${tag}]</span> <span class="bl-desc">${desc}</span> <span class="bl-ok">[OK]</span>`;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function startBoot() {
    if (booting) return;
    booting = true;
    coreTarget = 1.0;   // çekirdek ateşlenir
    document.getElementById("boot-power").classList.add("hidden");
    document.getElementById("boot-console").classList.add("show");
    Audio.resume();
    Audio.impact();                 // derin sub-bass patlama
    Audio.sweep(70, 1600, 1.3, 0.14);
    setTimeout(() => Audio.startDrone(), 300);

    // sesli anons (terminalle aynı cümle, aynı motor)
    setTimeout(() => speak(VOICE_LINE), 450);

    // boot satırları
    let i = 0;
    const step = () => {
      if (i >= LINES.length) { finish(); return; }
      const [tag, desc, pct] = LINES[i];
      addLog(tag, desc);
      targetProgress = pct;
      barEl.style.width = pct + "%";
      statusEl.textContent = `${tag} · %${pct}`;
      Audio.beep(440 + i * 55, 0.08, "square", 0.06);
      if (i % 2) Audio.glitch();
      i++;
      setTimeout(step, 560);
    };
    setTimeout(step, 520);
  }

  function finish() {
    statusEl.textContent = "● SİSTEM ÇEVRİMİÇİ — tüm katmanlar nominal";
    Audio.impact();
    Audio.beep(660, 0.16, "sine", 0.12);
    setTimeout(() => Audio.beep(990, 0.22, "sine", 0.12), 130);
    setTimeout(() => Audio.beep(1320, 0.3, "sine", 0.1), 260);
    setTimeout(dismiss, 1700);
  }

  function dismiss() {
    if (done) return; done = true;
    Audio.stopDrone();
    boot.classList.add("boot-out");
    setTimeout(() => {
      running = false; cancelAnimationFrame(raf);
      boot.style.display = "none";
      window.dispatchEvent(new Event("resize")); // paneli yeniden boyutlandır
    }, 1100);
  }

  /* ---------- Global SFX köprüsü ----------
     Komuta merkezinin her yerinden (nav, asistan, olaylar) çağrılabilen
     ortak radyo/telsiz ses motoru. Giriş sesiyle AYNI Audio motorunu
     kullanır; böylece tüm arayüz sessel olarak uyumlu kalır. */
  window.ArachneSFX = (function () {
    let last = 0;
    function throttle(ms) { const t = Date.now(); if (t - last < ms) return false; last = t; return true; }
    return {
      resume() { Audio.resume(); },
      // nav geçişi: kısa telsiz cızırtısı + yükselen blip ("kanal değişti")
      radioBlip() {
        Audio.resume();
        Audio.glitch();
        Audio.beep(760, 0.05, "square", 0.05);
        setTimeout(() => Audio.beep(1180, 0.07, "sine", 0.06), 55);
      },
      // yumuşak dokunuş tıkı (hover / küçük etkileşim)
      tick() {
        if (!throttle(40)) return;
        Audio.resume();
        Audio.beep(1500, 0.03, "square", 0.025);
      },
      // onay: iki-ton yükseliş (buton / gönder)
      confirm() {
        Audio.resume();
        Audio.beep(680, 0.06, "sine", 0.06);
        setTimeout(() => Audio.beep(1020, 0.09, "sine", 0.06), 70);
      },
      // "iletişim açıldı" telsiz cızırtısı (asistan konuşmadan önce)
      squelch() { Audio.resume(); Audio.squelch(); },
      // kritik uyarı: alçalan klakson
      alarm() {
        Audio.resume();
        Audio.sweep(900, 240, 0.5, 0.10);
        setTimeout(() => Audio.glitch(), 120);
      },
      // ham erişim
      beep: Audio.beep, glitch: Audio.glitch, impact: Audio.impact,
    };
  })();

  // Chrome'da voices geç yüklenir; tetikle
  if ("speechSynthesis" in window) window.speechSynthesis.getVoices();

  document.getElementById("boot-power").addEventListener("click", startBoot);
  document.getElementById("boot-skip").addEventListener("click", () => { Audio.resume(); dismiss(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") dismiss(); });
})();
