/* Arachne Sentinel — Faz 10 + Faz 45-47: Celik Kubbe Komuta Merkezi (SINEMATIK)
 *
 * Iki buyuk gorsellestirme, sinema kalitesinde gercek-zamanli animasyonla:
 *   1. IronDome  — 18 katmanli savunma simulasyonu. Atmosferik gokkubbe,
 *                  donen radar tarama huzmesi, enerji kalkani parildamasi,
 *                  akkor mermiler + cok katmanli sok dalgalari, reaktor cekirdek.
 *   2. AttackMap — canli dunya haritasi. Parlayan kiyi seritleri, nabizli
 *                  tehdit dugumleri, kayan enerji yaylari, sonar darbeleri.
 *
 * HICBIR SAHTE VERI URETILMEZ. Her mermi /api/live'daki gercek bir
 * veritabani kaydidir; carptigi halka, o kaydi gercekten isleyen savunma
 * katmanidir. Konum bilgisi cevrimdisi bolge tahminidir ve arayuzde acikca
 * oyle etiketlenir. Animasyon yogunlugu KOZMETIKTIR - altindaki sayilar
 * (interceptions, event_count, severity) tamamen gercektir.
 *
 * Harici kutuphane kullanilmaz - sadece Canvas 2D.
 */
(function () {
  "use strict";

  const TAU = Math.PI * 2;
  const now = () => (window.performance ? performance.now() : Date.now());

  /* ==========================================================
   * 1) CELIK KUBBE — katmanli savunma simulasyonu (sinematik)
   * ========================================================== */
  const IronDome = (function () {
    const canvas = document.getElementById("dome-canvas");
    if (!canvas) return { update() {}, fire() {} };
    // 3B radar (dome3d.js) bu canvas'ta WebGL baglamini ele gecirdiyse 2B
    // getContext('2d') null doner -> 2B kubbeyi tamamen atla (3B devrede).
    const ctx = canvas.getContext("2d");
    if (!ctx || window.__DOME3D) return { update() {}, fire() {} };

    let w = 0, h = 0, cx = 0, cy = 0, maxR = 0;
    let layers = [];
    const projectiles = [];   // ucusta olan mermiler
    const bursts = [];        // patlama efektleri
    const ripples = [];       // katman halkasi dalgalanmasi
    const shields = [];       // kalkan parildamasi (dis kubbede)
    const callouts = [];      // "hangi katman durdurdu" ucucu etiketleri
    const stars = [];         // atmosferik toz parcaciklari
    let seenIds = new Set();
    let firstLoad = true;
    let stats = { total: 0, reachedCore: 0 };
    let sweepAng = Math.PI;   // donen radar huzmesi acisi

    function layout() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = w / 2;
      // Cekirdek alt-ortada: gelen saldirilar yukaridan gelir, kubbe onlari
      // karsilar. Buyuk, ferah kubbe - etiketler kosegen boyunca yayilir.
      cy = h * 0.86;
      maxR = Math.min(w * 0.40, h * 0.82);
      seedStars();
    }
    window.addEventListener("resize", layout);

    function seedStars() {
      stars.length = 0;
      const n = Math.min(90, Math.floor((w * h) / 12000));
      for (let i = 0; i < n; i++) {
        stars.push({
          x: Math.random() * w,
          y: Math.random() * (cy),
          r: Math.random() * 1.3 + 0.2,
          a: Math.random() * 0.5 + 0.1,
          tw: Math.random() * TAU,
          vy: Math.random() * 0.06 + 0.01,
        });
      }
    }

    /** Yeni mermi ates et: kenardan gelip ilgili katmanda durdurulur. */
    function fire(projectile) {
      const layer = layers.find((l) => l.id === projectile.intercepted_by);
      const targetR = layer ? layer.radius * maxR : 0;

      // Gelis acisi: kaynak IP'den TURETILIR (deterministik) - ayni saldirgan
      // hep ayni yonden gelir, boylece gorsel okunabilir kalir.
      const ip = projectile.source_ip || "";
      let hash = 0;
      for (let i = 0; i < ip.length; i++) hash = (hash * 31 + ip.charCodeAt(i)) | 0;
      const spread = Math.PI * 0.86;
      const angle = -Math.PI / 2 - spread / 2 + (Math.abs(hash) % 1000) / 1000 * spread;

      const startR = maxR * 1.55;
      projectiles.push({
        angle,
        r: startR,
        targetR,
        speed: startR * 0.0095,
        layerId: projectile.intercepted_by,
        color: (layer && layer.color) || "255,255,255",
        label: (layer && layer.name) || projectile.label || "",
        trail: [],
        spin: Math.random() * TAU,
      });
    }

    function update(dome) {
      if (!dome) return;
      layers = dome.layers || [];
      stats = {
        total: dome.total_projectiles || 0,
        reachedCore: dome.reached_core || 0,
      };
      if (!maxR) layout();

      const incoming = dome.projectiles || [];
      if (firstLoad) {
        // Ilk yuklemede gecmis olaylarin tamamini birden atesleme -
        // sadece son birkacini goster, sonra canli akisa gec.
        incoming.slice(0, 8).forEach((p, i) => setTimeout(() => fire(p), i * 160));
        incoming.forEach((p) => seenIds.add(p.id));
        firstLoad = false;
        return;
      }
      // Sadece YENI olaylari atesle
      const fresh = incoming.filter((p) => !seenIds.has(p.id));
      fresh.forEach((p, i) => {
        seenIds.add(p.id);
        setTimeout(() => fire(p), i * 110);
      });
      if (seenIds.size > 4000) seenIds = new Set(incoming.map((p) => p.id));

      // --- YENI saldiri: AI asistana proaktif uyari olayi gonder ---
      // (asistan.js dinler, profesyonel Turkce sesli+gorsel anons yapar).
      // Sizinti = cekirdege ulasan; bu mimaride her zaman 0 (aldatma yuzeyi).
      if (fresh.length > 0) {
        const byLayer = {};
        fresh.forEach((p) => {
          const nm = p.label || (layers.find((l) => l.id === p.intercepted_by) || {}).name || p.intercepted_by;
          byLayer[nm] = (byLayer[nm] || 0) + 1;
        });
        // en cok mudahale eden 2 hatti sirala
        const topLayers = Object.entries(byLayer)
          .sort((a, b) => b[1] - a[1]).slice(0, 2).map((e) => e[0]);
        const services = Array.from(new Set(fresh.map((p) => p.service).filter(Boolean))).slice(0, 3);
        try {
          window.dispatchEvent(new CustomEvent("arachne:attack", { detail: {
            count: fresh.length,
            layers: topLayers,
            services,
            reachedCore: stats.reachedCore || 0,
            total: stats.total || 0,
          }}));
        } catch (e) {}
      }
    }

    /* ---------- atmosfer: derin gradyan gok + toz ---------- */
    function drawSky() {
      const g = ctx.createRadialGradient(cx, cy, maxR * 0.1, cx, cy, maxR * 1.5);
      g.addColorStop(0, "rgba(12,26,32,0.55)");
      g.addColorStop(0.55, "rgba(6,14,22,0.28)");
      g.addColorStop(1, "rgba(2,5,9,0)");
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(cx, cy, maxR * 1.5, Math.PI, TAU);
      ctx.fill();

      const t = now();
      for (const s of stars) {
        s.y -= s.vy;
        if (s.y < 0) { s.y = cy; s.x = Math.random() * w; }
        const tw = 0.5 + 0.5 * Math.sin(t / 900 + s.tw);
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.r, 0, TAU);
        ctx.fillStyle = `rgba(120,200,220,${s.a * tw})`;
        ctx.fill();
      }
    }

    /* ---------- donen radar tarama huzmesi ---------- */
    function drawSweep() {
      sweepAng += 0.006;
      const a = Math.PI + (sweepAng % Math.PI);  // sadece yarim kubbede gez
      ctx.save();
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      grad.addColorStop(0, "rgba(45,212,191,0.10)");
      grad.addColorStop(1, "rgba(45,212,191,0)");
      // huzme dilimi (tarayici izi)
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR, a - 0.28, a);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      // parlak on kenar
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(a) * maxR, cy + Math.sin(a) * maxR);
      ctx.strokeStyle = "rgba(94,234,212,0.28)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.restore();
    }

    function drawDome() {
      // Zemin: hafif tarama izgarasi (radar hissi)
      ctx.save();
      ctx.strokeStyle = "rgba(45,212,191,0.05)";
      ctx.lineWidth = 1;
      for (let a = 0; a <= 6; a++) {
        const ang = Math.PI + (a / 6) * Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(ang) * maxR * 1.02, cy + Math.sin(ang) * maxR * 1.02);
        ctx.stroke();
      }
      ctx.restore();

      // Etiket acilari: isim ust-solda, sayi ust-sagda - her ikisi de kosegen
      // boyunca yayilir, boylece 18 halka etiketi HIC sikismaz.
      const NAME_ANG = Math.PI * 1.15;   // ~207° (ust-sol)
      const CNT_ANG = Math.PI * 1.85;    // ~333° (ust-sag)
      const t = now();

      // Katman halkalari (yarim kubbe) - disaridan iceriye
      layers.forEach((layer, li) => {
        const r = layer.radius * maxR;
        const on = layer.active;
        // aktif halkalar hafifce "nefes alir" (canli his)
        const breathe = on ? 0.5 + 0.14 * Math.sin(t / 1100 + li * 0.5) : 0.13;
        const alpha = breathe;

        // Ic dolgu (cok soluk)
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, TAU);
        ctx.closePath();
        ctx.fillStyle = `rgba(${layer.color},${on ? 0.028 : 0.010})`;
        ctx.fill();

        // Halka cizgisi (aktifse hafif glow)
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, TAU);
        ctx.strokeStyle = `rgba(${layer.color},${alpha})`;
        ctx.lineWidth = on ? 2 : 1;
        ctx.setLineDash(on ? [] : [3, 7]);
        if (on) { ctx.shadowColor = `rgba(${layer.color},0.5)`; ctx.shadowBlur = 8; }
        ctx.stroke();
        ctx.shadowBlur = 0;
        ctx.setLineDash([]);

        // aktif halkada kayan enerji noktalari (akan his)
        if (on) {
          const dots = 3;
          for (let k = 0; k < dots; k++) {
            const pa = Math.PI + ((t / 2600 + k / dots + li * 0.13) % 1) * Math.PI;
            const px = cx + Math.cos(pa) * r;
            const py = cy + Math.sin(pa) * r;
            ctx.beginPath();
            ctx.arc(px, py, 1.6, 0, TAU);
            ctx.fillStyle = `rgba(${layer.color},0.85)`;
            ctx.shadowColor = `rgba(${layer.color},0.9)`;
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }

        // --- Isim etiketi (ust-sol kosegen), lider cizgisiyle ---
        const nx = cx + Math.cos(NAME_ANG) * r;
        const ny = cy + Math.sin(NAME_ANG) * r;
        ctx.beginPath();
        ctx.arc(nx, ny, on ? 2.6 : 1.8, 0, TAU);
        ctx.fillStyle = `rgba(${layer.color},${on ? 1 : 0.5})`;
        ctx.fill();
        ctx.beginPath();
        ctx.moveTo(nx, ny);
        ctx.lineTo(nx - 10, ny);
        ctx.strokeStyle = `rgba(${layer.color},${on ? 0.5 : 0.2})`;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.font = on ? "600 11px 'JetBrains Mono', monospace"
                      : "500 10px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        ctx.textBaseline = "middle";
        ctx.shadowColor = "rgba(3,5,8,0.95)";
        ctx.shadowBlur = 6;
        ctx.fillStyle = `rgba(${layer.color},${on ? 0.98 : 0.42})`;
        ctx.fillText(layer.name, nx - 14, ny);
        ctx.shadowBlur = 0;

        // --- Sayi rozeti (ust-sag kosegen) ---
        const qx = cx + Math.cos(CNT_ANG) * r;
        const qy = cy + Math.sin(CNT_ANG) * r;
        const label = String(layer.interceptions);
        ctx.font = "700 11px 'JetBrains Mono', monospace";
        const pw = ctx.measureText(label).width + 14;
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(qx + 8, qy - 9, pw, 18, 9);
        else ctx.rect(qx + 8, qy - 9, pw, 18);
        ctx.fillStyle = on ? `rgba(${layer.color},0.16)` : "rgba(255,255,255,0.02)";
        ctx.fill();
        ctx.strokeStyle = `rgba(${layer.color},${on ? 0.55 : 0.18})`;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.textAlign = "center";
        ctx.fillStyle = `rgba(${layer.color},${on ? 1 : 0.45})`;
        ctx.fillText(label, qx + 8 + pw / 2, qy + 1);
        ctx.beginPath();
        ctx.moveTo(qx, qy);
        ctx.lineTo(qx + 7, qy);
        ctx.strokeStyle = `rgba(${layer.color},${on ? 0.5 : 0.2})`;
        ctx.stroke();

        ctx.textBaseline = "alphabetic";
      });

      // En dis kubbe: enerji kalkani kaviligi (hafif parlayan cember)
      const outer = (layers[0] ? layers[0].radius : 1) * maxR;
      ctx.beginPath();
      ctx.arc(cx, cy, outer + 4, Math.PI, TAU);
      ctx.strokeStyle = `rgba(94,234,212,${0.10 + 0.05 * Math.sin(t / 800)})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Katman dalgalanmalari (bir mudahale oldugunda)
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rp = ripples[i];
        rp.t += 0.05;
        if (rp.t >= 1) { ripples.splice(i, 1); continue; }
        ctx.beginPath();
        ctx.arc(cx, cy, rp.r + rp.t * 16, Math.PI, TAU);
        ctx.strokeStyle = `rgba(${rp.color},${(1 - rp.t) * 0.7})`;
        ctx.lineWidth = 2.5 * (1 - rp.t);
        ctx.stroke();
      }
    }

    /* ---------- kalkan parildamasi: dis kubbeye carpma dokusu ---------- */
    function drawShields() {
      for (let i = shields.length - 1; i >= 0; i--) {
        const s = shields[i];
        s.t += 0.035;
        if (s.t >= 1) { shields.splice(i, 1); continue; }
        const a = (1 - s.t) * 0.5;
        // altigen kalkan hucreleri (carpma noktasinda)
        ctx.save();
        ctx.translate(s.x, s.y);
        ctx.strokeStyle = `rgba(94,234,212,${a})`;
        ctx.lineWidth = 1;
        for (let ring = 0; ring < 2; ring++) {
          const rr = 10 + ring * 9 + s.t * 20;
          ctx.beginPath();
          for (let k = 0; k <= 6; k++) {
            const ang = (k / 6) * TAU + s.t;
            const px = Math.cos(ang) * rr, py = Math.sin(ang) * rr;
            if (k === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
          }
          ctx.closePath();
          ctx.stroke();
        }
        ctx.restore();
      }
    }

    function drawCallouts() {
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      for (let i = callouts.length - 1; i >= 0; i--) {
        const c = callouts[i];
        c.t += 0.014;
        if (c.t >= 1) { callouts.splice(i, 1); continue; }
        const a = c.t < 0.15 ? c.t / 0.15 : (1 - (c.t - 0.15) / 0.85);
        const yy = c.y - c.t * 26;
        ctx.font = "700 11px 'JetBrains Mono', monospace";
        const tw = ctx.measureText(c.name).width;
        ctx.fillStyle = `rgba(8,11,17,${a * 0.85})`;
        const bx = c.x + 8, bw = tw + 20;
        if (ctx.roundRect) { ctx.beginPath(); ctx.roundRect(bx, yy - 9, bw, 18, 5); ctx.fill(); }
        else ctx.fillRect(bx, yy - 9, bw, 18);
        ctx.strokeStyle = `rgba(${c.color},${a * 0.7})`;
        ctx.lineWidth = 1; ctx.stroke();
        ctx.beginPath();
        ctx.arc(bx + 9, yy, 2.5, 0, TAU);
        ctx.fillStyle = `rgba(${c.color},${a})`;
        ctx.fill();
        ctx.fillStyle = `rgba(233,237,245,${a})`;
        ctx.fillText(c.name, bx + 16, yy + 0.5);
      }
      ctx.textBaseline = "alphabetic";
    }

    /* ---------- reaktor cekirdek: donen segmentler + enerji ---------- */
    function drawCore() {
      const t = now();
      const pulse = 1 + Math.sin(t / 620) * 0.09;
      const r = 17 * pulse;

      // dis akkor halesi
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, r * 3.0);
      grad.addColorStop(0, "rgba(34,197,94,0.42)");
      grad.addColorStop(0.5, "rgba(34,197,94,0.12)");
      grad.addColorStop(1, "rgba(34,197,94,0)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(cx, cy, r * 3.0, 0, TAU);
      ctx.fill();

      // donen dis segment halkasi
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate((t / 3000) % TAU);
      ctx.strokeStyle = "rgba(34,197,94,0.55)";
      ctx.lineWidth = 2;
      for (let k = 0; k < 8; k++) {
        const a0 = (k / 8) * TAU + 0.1;
        const a1 = a0 + 0.5;
        ctx.beginPath();
        ctx.arc(0, 0, r * 1.7, a0, a1);
        ctx.stroke();
      }
      ctx.restore();

      // ters yonde donen ic segmentler
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-(t / 2100) % TAU);
      ctx.strokeStyle = "rgba(94,234,212,0.5)";
      ctx.lineWidth = 1.5;
      for (let k = 0; k < 6; k++) {
        const a0 = (k / 6) * TAU;
        ctx.beginPath();
        ctx.arc(0, 0, r * 1.25, a0, a0 + 0.35);
        ctx.stroke();
      }
      ctx.restore();

      // cekirdek golu
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, TAU);
      ctx.fillStyle = "rgba(34,197,94,0.22)";
      ctx.fill();
      ctx.strokeStyle = "rgba(34,197,94,0.95)";
      ctx.lineWidth = 2;
      ctx.stroke();

      // parlak cekirdek noktasi
      ctx.beginPath();
      ctx.arc(cx, cy, r * 0.4 * pulse, 0, TAU);
      ctx.fillStyle = "rgba(190,255,214,0.9)";
      ctx.shadowColor = "rgba(34,197,94,1)";
      ctx.shadowBlur = 16;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(233,237,245,0.92)";
      ctx.textAlign = "center";
      ctx.fillText("KORUNAN VARLIK", cx, cy + 16);
    }

    function drawProjectiles() {
      for (let i = projectiles.length - 1; i >= 0; i--) {
        const p = projectiles[i];
        p.r -= p.speed;

        const x = cx + Math.cos(p.angle) * p.r;
        const y = cy + Math.sin(p.angle) * p.r;

        p.trail.push({ x, y });
        if (p.trail.length > 18) p.trail.shift();

        // Akkor kuyruk (parlayan gradyan)
        for (let ti = 0; ti < p.trail.length; ti++) {
          const pt = p.trail[ti];
          const a = (ti / p.trail.length) * 0.6;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 1.8 * (ti / p.trail.length) + 0.4, 0, TAU);
          ctx.fillStyle = `rgba(255,110,90,${a})`;
          ctx.fill();
        }

        // Mermi basi + hedefleme parlamasi
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, TAU);
        ctx.fillStyle = "rgba(255,140,120,1)";
        ctx.shadowColor = "rgba(255,80,80,0.95)";
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Katmana ulasti mi? -> mudahale
        if (p.r <= p.targetR) {
          bursts.push({ x, y, t: 0, color: p.color });
          ripples.push({ r: p.targetR, t: 0, color: p.color });
          shields.push({ x, y, t: 0 });
          if (p.label) callouts.push({ x, y, name: p.label, color: p.color, t: 0 });
          if (callouts.length > 10) callouts.shift();
          projectiles.splice(i, 1);
        } else if (p.r <= 0) {
          projectiles.splice(i, 1);
        }
      }
    }

    function drawBursts() {
      for (let i = bursts.length - 1; i >= 0; i--) {
        const b = bursts[i];
        b.t += 0.04;
        if (b.t >= 1) { bursts.splice(i, 1); continue; }

        // parlak ilk flash
        if (b.t < 0.2) {
          ctx.beginPath();
          ctx.arc(b.x, b.y, 4 + b.t * 40, 0, TAU);
          ctx.fillStyle = `rgba(255,255,255,${(0.2 - b.t) * 1.5})`;
          ctx.fill();
        }

        const r = 3 + b.t * 30;
        // ana sok halkasi
        ctx.beginPath();
        ctx.arc(b.x, b.y, r, 0, TAU);
        ctx.strokeStyle = `rgba(${b.color},${1 - b.t})`;
        ctx.lineWidth = 2.6 * (1 - b.t);
        ctx.stroke();
        // ikinci gecikmeli halka
        ctx.beginPath();
        ctx.arc(b.x, b.y, r * 0.6, 0, TAU);
        ctx.strokeStyle = `rgba(${b.color},${(1 - b.t) * 0.6})`;
        ctx.lineWidth = 1.5 * (1 - b.t);
        ctx.stroke();
        // ic parlama
        ctx.beginPath();
        ctx.arc(b.x, b.y, r * 0.42, 0, TAU);
        ctx.fillStyle = `rgba(${b.color},${(1 - b.t) * 0.42})`;
        ctx.fill();

        // Kivilcimlar (daha fazla + degisken)
        for (let s = 0; s < 7; s++) {
          const a = (s / 7) * TAU + b.t * 1.6;
          const d = r * (1.1 + (s % 3) * 0.18);
          ctx.beginPath();
          ctx.arc(b.x + Math.cos(a) * d, b.y + Math.sin(a) * d, 1.4 * (1 - b.t), 0, TAU);
          ctx.fillStyle = `rgba(${b.color},${1 - b.t})`;
          ctx.fill();
        }
      }
    }

    function drawHud() {
      ctx.font = "600 10px 'JetBrains Mono', monospace";
      ctx.textAlign = "right";
      const x = w - 12;
      ctx.fillStyle = "rgba(139,149,168,0.9)";
      ctx.fillText(`Islenen saldiri: ${stats.total}`, x, 18);
      ctx.fillStyle = "rgba(34,197,94,0.95)";
      ctx.fillText(`Cekirdege ulasan: ${stats.reachedCore}`, x, 33);
      ctx.fillStyle = "rgba(255,90,90,0.9)";
      ctx.fillText(`Ucusta: ${projectiles.length}`, x, 48);
      // aktif katman sayaci
      const activeN = layers.filter((l) => l.active).length;
      ctx.fillStyle = "rgba(94,234,212,0.9)";
      ctx.fillText(`Aktif halka: ${activeN}/${layers.length}`, x, 63);
    }

    function frame() {
      if (!w) layout();
      ctx.clearRect(0, 0, w, h);
      drawSky();
      drawSweep();
      drawDome();
      drawShields();
      drawCore();
      drawProjectiles();
      drawBursts();
      drawCallouts();
      drawHud();
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);

    return { update, fire };
  })();

  /* ==========================================================
   * 2) DUNYA HARITASI — saldiri yaylari (sinematik)
   * ========================================================== */
  const AttackMap = (function () {
    const canvas = document.getElementById("map-canvas");
    if (!canvas) return { update() {} };
    // 3B dünya (globe3d.js) bu canvas'ta WebGL baglamini aldiysa 2B haritayi atla.
    const ctx = canvas.getContext("2d");
    if (!ctx || window.__GLOBE3D) return { update() {} };

    let w = 0, h = 0;
    let nodes = [];
    let asset = { lat: 41, lon: 29 };
    const arcs = [];
    const impacts = [];   // hedefte sonar darbeleri
    let seen = new Set();
    let firstLoad = true;

    function layout() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    window.addEventListener("resize", layout);

    function project(lat, lon) {
      return {
        x: ((lon + 180) / 360) * w,
        y: ((90 - lat) / 180) * h,
      };
    }

    const LAND = [
      [[-168,66],[-158,71],[-130,70],[-95,70],[-80,73],[-60,60],[-55,50],[-65,45],
       [-70,42],[-75,35],[-81,25],[-97,26],[-107,23],[-115,30],[-124,40],[-125,48],
       [-135,57],[-150,60],[-168,66]],
      [[-81,10],[-72,12],[-60,5],[-50,0],[-35,-6],[-38,-16],[-48,-25],[-58,-35],
       [-63,-42],[-70,-52],[-75,-50],[-73,-40],[-71,-30],[-70,-18],[-77,-6],[-81,10]],
      [[-17,15],[0,15],[15,12],[32,15],[43,12],[51,12],[42,-2],[40,-15],[35,-24],
       [25,-34],[18,-34],[12,-18],[9,-1],[5,5],[-8,5],[-17,15]],
      [[-10,36],[-9,44],[-2,48],[2,51],[5,53],[8,55],[11,58],[18,60],[24,60],
       [30,60],[40,58],[40,48],[36,45],[28,41],[23,38],[15,38],[12,45],[3,43],[-10,36]],
      [[40,58],[60,62],[80,65],[100,68],[120,70],[140,68],[145,60],[142,50],
       [135,45],[128,38],[121,32],[110,20],[100,12],[95,17],[88,22],[80,10],
       [72,20],[62,25],[55,28],[48,30],[45,40],[40,48],[40,58]],
      [[113,-22],[122,-18],[131,-12],[142,-11],[147,-18],[153,-27],[150,-37],
       [141,-38],[131,-32],[123,-34],[115,-34],[113,-22]],
    ];

    function drawWorld() {
      const t = now();
      // Okyanus gradyani (derinlik hissi)
      const g = ctx.createLinearGradient(0, 0, 0, h);
      g.addColorStop(0, "rgba(10,20,34,0.5)");
      g.addColorStop(0.5, "rgba(8,16,28,0.32)");
      g.addColorStop(1, "rgba(6,12,22,0.5)");
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);

      // Izgara (enlem/boylam) - hafif kayan tarama parlamasi
      ctx.strokeStyle = "rgba(120,150,180,0.055)";
      ctx.lineWidth = 1;
      for (let lon = -180; lon <= 180; lon += 30) {
        const p = project(0, lon);
        ctx.beginPath(); ctx.moveTo(p.x, 0); ctx.lineTo(p.x, h); ctx.stroke();
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const p = project(lat, 0);
        ctx.beginPath(); ctx.moveTo(0, p.y); ctx.lineTo(w, p.y); ctx.stroke();
      }

      // Yatay tarama huzmesi (soldan saga kayar)
      const sweepX = ((t / 6000) % 1) * w;
      const sg = ctx.createLinearGradient(sweepX - 60, 0, sweepX + 60, 0);
      sg.addColorStop(0, "rgba(45,212,191,0)");
      sg.addColorStop(0.5, "rgba(45,212,191,0.06)");
      sg.addColorStop(1, "rgba(45,212,191,0)");
      ctx.fillStyle = sg;
      ctx.fillRect(sweepX - 60, 0, 120, h);

      // Kita dis hatlari (parlayan kiyi)
      LAND.forEach((poly) => {
        ctx.beginPath();
        poly.forEach(([lon, lat], i) => {
          const p = project(lat, lon);
          if (i === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
        });
        ctx.closePath();
        ctx.fillStyle = "rgba(90,120,150,0.075)";
        ctx.fill();
        ctx.strokeStyle = "rgba(120,170,210,0.28)";
        ctx.lineWidth = 1;
        ctx.shadowColor = "rgba(80,160,200,0.4)";
        ctx.shadowBlur = 5;
        ctx.stroke();
        ctx.shadowBlur = 0;
      });
    }

    function launchArc(node) {
      arcs.push({ node, t: 0, speed: 0.010 + Math.random() * 0.006 });
    }

    function update(mapData) {
      if (!mapData) return;
      nodes = mapData.nodes || [];
      asset = mapData.defended_asset || asset;
      if (!w) layout();

      const ids = new Set(nodes.map((n) => n.ip));
      if (firstLoad) {
        nodes.slice(0, 6).forEach((n, i) => setTimeout(() => launchArc(n), i * 260));
        seen = ids;
        firstLoad = false;
        return;
      }
      nodes.forEach((n) => {
        if (!seen.has(n.ip)) launchArc(n);
      });
      if (nodes.length && Math.random() < 0.35) {
        launchArc(nodes[Math.floor(Math.random() * Math.min(nodes.length, 6))]);
      }
      seen = ids;
    }

    function severityColor(node) {
      if (node.blocked) return "148,163,184";
      switch (node.severity) {
        case "critical": return "255,59,69";
        case "high": return "255,122,69";
        case "medium": return "245,166,35";
        case "low": return "77,163,255";
        default: return "34,211,238";
      }
    }

    function drawArcs() {
      const target = project(asset.lat, asset.lon);

      for (let i = arcs.length - 1; i >= 0; i--) {
        const arc = arcs[i];
        arc.t += arc.speed;
        if (arc.t >= 1.25) { arcs.splice(i, 1); continue; }

        const src = project(arc.node.lat, arc.node.lon);
        const color = severityColor(arc.node);
        const t = Math.min(arc.t, 1);

        const mx = (src.x + target.x) / 2;
        const my = (src.y + target.y) / 2;
        const dist = Math.hypot(target.x - src.x, target.y - src.y);
        const cpx = mx;
        const cpy = my - Math.min(dist * 0.42, h * 0.4);

        // Yayin cizilen kismi (parlayan)
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        const steps = 30;
        for (let s = 1; s <= steps * t; s++) {
          const u = s / steps;
          const x = (1 - u) ** 2 * src.x + 2 * (1 - u) * u * cpx + u * u * target.x;
          const y = (1 - u) ** 2 * src.y + 2 * (1 - u) * u * cpy + u * u * target.y;
          ctx.lineTo(x, y);
        }
        ctx.strokeStyle = `rgba(${color},${0.5 * (1 - Math.max(0, arc.t - 1) * 4)})`;
        ctx.lineWidth = 1.4;
        ctx.shadowColor = `rgba(${color},0.6)`;
        ctx.shadowBlur = 4;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Ucan nokta (comet) + kisa parlak kuyruk
        if (t < 1) {
          const u = t;
          const x = (1 - u) ** 2 * src.x + 2 * (1 - u) * u * cpx + u * u * target.x;
          const y = (1 - u) ** 2 * src.y + 2 * (1 - u) * u * cpy + u * u * target.y;
          ctx.beginPath();
          ctx.arc(x, y, 2.8, 0, TAU);
          ctx.fillStyle = `rgba(${color},1)`;
          ctx.shadowColor = `rgba(${color},1)`;
          ctx.shadowBlur = 11;
          ctx.fill();
          ctx.shadowBlur = 0;
        } else if (!arc.hit) {
          // hedefe ulasti -> sonar darbesi baslat (bir kez)
          arc.hit = true;
          impacts.push({ x: target.x, y: target.y, t: 0 });
        }
      }
    }

    function drawImpacts() {
      for (let i = impacts.length - 1; i >= 0; i--) {
        const im = impacts[i];
        im.t += 0.03;
        if (im.t >= 1) { impacts.splice(i, 1); continue; }
        ctx.beginPath();
        ctx.arc(im.x, im.y, 4 + im.t * 26, 0, TAU);
        ctx.strokeStyle = `rgba(34,197,94,${1 - im.t})`;
        ctx.lineWidth = 2 * (1 - im.t);
        ctx.stroke();
      }
    }

    function drawNodes() {
      const t = now();
      nodes.forEach((node) => {
        const p = project(node.lat, node.lon);
        const color = severityColor(node);
        const r = 2.6 + Math.min(4, Math.log2((node.event_count || 1) + 1));

        // Nabiz halkasi
        const pulse = (t / 1000 + p.x * 0.01) % 2 / 2;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + pulse * 13, 0, TAU);
        ctx.strokeStyle = `rgba(${color},${(1 - pulse) * 0.35})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, TAU);
        ctx.fillStyle = `rgba(${color},0.95)`;
        ctx.shadowColor = `rgba(${color},0.85)`;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;

        if (node.blocked) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, r + 4, 0, TAU);
          ctx.strokeStyle = "rgba(148,163,184,0.9)";
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }
      });
    }

    function drawAsset() {
      const t = now();
      const p = project(asset.lat, asset.lon);

      // sonar nabzi (surekli yayilan halka)
      const ph = (t / 1600) % 1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, 6 + ph * 30, 0, TAU);
      ctx.strokeStyle = `rgba(34,197,94,${(1 - ph) * 0.4})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // donen kalkan halkasi
      ctx.save();
      ctx.translate(p.x, p.y);
      ctx.rotate((t / 2400) % TAU);
      ctx.strokeStyle = "rgba(34,197,94,0.7)";
      ctx.lineWidth = 1.5;
      for (let k = 0; k < 4; k++) {
        const a0 = (k / 4) * TAU;
        ctx.beginPath();
        ctx.arc(0, 0, 11, a0, a0 + 0.6);
        ctx.stroke();
      }
      ctx.restore();

      ctx.beginPath();
      ctx.arc(p.x, p.y, 6, 0, TAU);
      ctx.fillStyle = "rgba(34,197,94,0.25)";
      ctx.fill();
      ctx.strokeStyle = "rgba(34,197,94,1)";
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(34,197,94,0.95)";
      ctx.textAlign = "center";
      ctx.fillText("KORUNAN", p.x, p.y - 14);
    }

    function frame() {
      if (!w) layout();
      ctx.clearRect(0, 0, w, h);
      drawWorld();
      drawArcs();
      drawImpacts();
      drawNodes();
      drawAsset();
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);

    return { update };
  })();

  /* ==========================================================
   * 3) Katman saglik kartlari + dis dunyaya acilan API
   * ========================================================== */
  function renderLayerHealth(health) {
    const root = document.getElementById("layer-health");
    if (!root || !health) return;
    const order = ["soar", "mtd", "waf", "deception", "detection", "mesh", "ai"];
    root.innerHTML = order.map((key) => {
      const layer = health[key];
      if (!layer) return "";
      const state = layer.operational ? "ok" : "idle";
      return `
        <div class="layer-card ${state}">
          <div class="lc-head">
            <span class="lc-dot"></span>
            <span class="lc-name">${escapeHtml(layer.label)}</span>
            <span class="lc-phase">${escapeHtml(layer.phase)}</span>
          </div>
          <div class="lc-metric">${layer.metric}<span>${escapeHtml(layer.metric_label)}</span></div>
          <div class="lc-detail">${escapeHtml(layer.detail)}</div>
        </div>`;
    }).join("");
  }

  function renderDomeLegend(dome) {
    const root = document.getElementById("dome-legend");
    if (!root || !dome || !dome.layers) return;
    root.innerHTML = dome.layers.map((layer) => `
      <div class="dome-legend-item ${layer.active ? "active" : ""}"
           title="${escapeHtml(layer.description_tr)}">
        <span class="dl-sw" style="background:rgb(${layer.color})"></span>
        <span class="dl-name">${escapeHtml(layer.name)}</span>
        <span class="dl-phase">${escapeHtml(layer.phase)}</span>
        <span class="dl-count">${layer.interceptions}</span>
      </div>`).join("");
  }

  function renderMapLegend(mapData) {
    const root = document.getElementById("map-stats");
    if (!root || !mapData) return;
    const scopes = mapData.by_scope || {};
    const labels = {
      loopback: "Yerel lab", private: "Ozel ag", documentation: "Senaryo (RFC 5737)",
      public: "Genel internet", reserved: "Ayrilmis", invalid: "Gecersiz",
    };
    const rows = Object.entries(scopes).map(([scope, count]) =>
      `<div class="ms-row"><span>${escapeHtml(labels[scope] || scope)}</span>
       <b>${count}</b></div>`).join("");
    root.innerHTML = rows || '<div class="ms-row"><span>Henuz kaynak yok</span></div>';
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
  }

  /* ==========================================================
   * YENI SALDIRI ALGISI (2B/3B'den BAGIMSIZ)
   * ----------------------------------------------------------
   * `arachne:attack` olayini BURADA yayariz — boylece 2B IronDome
   * (3B aktifken atlaniyor) ya da 3B radar hangisi cizerse cizsin,
   * AI asistanin proaktif sesli anonsu HER ZAMAN tetiklenir.
   * Asistana kac yeni saldiri geldigini ve HANGI KATMANLARIN
   * karsiladigini iletir (detayli, gercek veriden).
   * ========================================================== */
  let _attackSeen = new Set();
  let _attackFirst = true;
  function detectAndDispatchAttack(dome) {
    if (!dome) return;
    const incoming = dome.projectiles || [];
    if (_attackFirst) {                       // ilk yukleme: gecmisi anons etme
      incoming.forEach((p) => _attackSeen.add(p.id));
      _attackFirst = false;
      return;
    }
    const fresh = incoming.filter((p) => !_attackSeen.has(p.id));
    fresh.forEach((p) => _attackSeen.add(p.id));
    if (_attackSeen.size > 4000) _attackSeen = new Set(incoming.map((p) => p.id));
    if (!fresh.length) return;

    const layersArr = dome.layers || [];
    const byLayer = {};
    fresh.forEach((p) => {
      const nm = p.label ||
        (layersArr.find((l) => l.id === p.intercepted_by) || {}).name || p.intercepted_by;
      byLayer[nm] = (byLayer[nm] || 0) + 1;
    });
    const topLayers = Object.entries(byLayer)
      .sort((a, b) => b[1] - a[1]).slice(0, 3).map((e) => e[0]);
    const services = Array.from(new Set(fresh.map((p) => p.service).filter(Boolean))).slice(0, 3);
    try {
      window.dispatchEvent(new CustomEvent("arachne:attack", { detail: {
        count: fresh.length,
        layers: topLayers,
        byLayer,
        services,
        reachedCore: dome.reached_core || 0,
        total: dome.total_projectiles || 0,
      }}));
    } catch (e) {}
  }

  // dashboard.js her poll'da bunu cagirir
  window.ArachneCommandCenter = {
    update(data) {
      if (!data) return;
      // Saldiri algisi ONCE (cizim yolundan bagimsiz, her zaman calisir)
      detectAndDispatchAttack(data.dome);
      // 3B radar aktifse kubbe verisini ona yolla; degilse 2B kubbeye.
      if (window.__DOME3D && window.ArachneDome3D) window.ArachneDome3D.update(data.dome);
      else IronDome.update(data.dome);
      if (window.__GLOBE3D && window.ArachneGlobe3D) window.ArachneGlobe3D.update(data.attack_map);
      else AttackMap.update(data.attack_map);
      renderLayerHealth(data.layer_health);
      renderDomeLegend(data.dome);
      renderMapLegend(data.attack_map);
    },
  };
})();
