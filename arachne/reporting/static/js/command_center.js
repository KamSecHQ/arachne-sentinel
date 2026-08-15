/* Arachne Sentinel — Faz 10: Celik Kubbe Komuta Merkezi
 *
 * Iki buyuk gorsellestirme:
 *   1. IronDome  — katmanli savunma simulasyonu (gelen saldirilar, katman
 *                  halkalari, gercek mudahale noktalarinda patlama)
 *   2. AttackMap — dunya haritasi uzerinde saldiri yaylari
 *
 * HICBIR SAHTE VERI URETILMEZ. Her mermi /api/live'daki gercek bir
 * veritabani kaydidir; carptigi halka, o kaydi gercekten isleyen savunma
 * katmanidir. Konum bilgisi cevrimdisi bolge tahminidir ve arayuzde
 * acikca oyle etiketlenir.
 *
 * Harici kutuphane kullanilmaz - sadece Canvas 2D.
 */
(function () {
  "use strict";

  const TAU = Math.PI * 2;

  /* ==========================================================
   * 1) CELIK KUBBE — katmanli savunma simulasyonu
   * ========================================================== */
  const IronDome = (function () {
    const canvas = document.getElementById("dome-canvas");
    if (!canvas) return { update() {}, fire() {} };
    const ctx = canvas.getContext("2d");

    let w = 0, h = 0, cx = 0, cy = 0, maxR = 0;
    let layers = [];
    const projectiles = [];   // ucusta olan mermiler
    const bursts = [];        // patlama efektleri
    const ripples = [];       // katman halkasi dalgalanmasi
    const callouts = [];      // "hangi katman durdurdu" ucucu etiketleri
    let seenIds = new Set();
    let firstLoad = true;
    let stats = { total: 0, reachedCore: 0 };

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
    }
    window.addEventListener("resize", layout);

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

      const startR = maxR * 1.5;
      projectiles.push({
        angle,
        r: startR,
        targetR,
        speed: startR * 0.010,
        layerId: projectile.intercepted_by,
        color: (layer && layer.color) || "255,255,255",
        label: (layer && layer.name) || projectile.label || "",
        trail: [],
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
      // boyunca yayilir, boylece 14 halka etiketi HIC sikismaz.
      const NAME_ANG = Math.PI * 1.15;   // ~207° (ust-sol)
      const CNT_ANG = Math.PI * 1.85;    // ~333° (ust-sag)

      // Katman halkalari (yarim kubbe) - disaridan iceriye
      layers.forEach((layer) => {
        const r = layer.radius * maxR;
        const on = layer.active;
        const alpha = on ? 0.5 : 0.14;

        // Ic dolgu (cok soluk) - once ki cizgiler ustte kalsin
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, TAU);
        ctx.closePath();
        ctx.fillStyle = `rgba(${layer.color},${on ? 0.03 : 0.012})`;
        ctx.fill();

        // Halka cizgisi
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, TAU);
        ctx.strokeStyle = `rgba(${layer.color},${alpha})`;
        ctx.lineWidth = on ? 2 : 1;
        ctx.setLineDash(on ? [] : [3, 7]);
        ctx.stroke();
        ctx.setLineDash([]);

        // --- Isim etiketi (ust-sol kosegen), lider cizgisiyle ---
        const nx = cx + Math.cos(NAME_ANG) * r;
        const ny = cy + Math.sin(NAME_ANG) * r;
        ctx.beginPath();
        ctx.arc(nx, ny, on ? 2.6 : 1.8, 0, TAU);
        ctx.fillStyle = `rgba(${layer.color},${on ? 1 : 0.5})`;
        ctx.fill();
        // lider cizgi
        ctx.beginPath();
        ctx.moveTo(nx, ny);
        ctx.lineTo(nx - 10, ny);
        ctx.strokeStyle = `rgba(${layer.color},${on ? 0.5 : 0.2})`;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.font = on ? "600 12px 'JetBrains Mono', monospace"
                      : "500 11px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        ctx.textBaseline = "middle";
        // koyu hale: etiket halkalarin uzerinde net okunsun
        ctx.shadowColor = "rgba(3,5,8,0.95)";
        ctx.shadowBlur = 6;
        ctx.fillStyle = `rgba(${layer.color},${on ? 0.98 : 0.42})`;
        ctx.fillText(layer.name, nx - 14, ny);
        ctx.shadowBlur = 0;

        // --- Sayi rozeti (ust-sag kosegen) ---
        const qx = cx + Math.cos(CNT_ANG) * r;
        const qy = cy + Math.sin(CNT_ANG) * r;
        const label = String(layer.interceptions);
        ctx.font = "700 12px 'JetBrains Mono', monospace";
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
        // lider cizgi rozetten halkaya
        ctx.beginPath();
        ctx.moveTo(qx, qy);
        ctx.lineTo(qx + 7, qy);
        ctx.strokeStyle = `rgba(${layer.color},${on ? 0.5 : 0.2})`;
        ctx.stroke();

        ctx.textBaseline = "alphabetic";
      });

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
        // arka plan
        ctx.fillStyle = `rgba(8,11,17,${a * 0.85})`;
        const bx = c.x + 8, bw = tw + 20;
        if (ctx.roundRect) { ctx.beginPath(); ctx.roundRect(bx, yy - 9, bw, 18, 5); ctx.fill(); }
        else ctx.fillRect(bx, yy - 9, bw, 18);
        ctx.strokeStyle = `rgba(${c.color},${a * 0.7})`;
        ctx.lineWidth = 1; ctx.stroke();
        // nokta + metin
        ctx.beginPath();
        ctx.arc(bx + 9, yy, 2.5, 0, TAU);
        ctx.fillStyle = `rgba(${c.color},${a})`;
        ctx.fill();
        ctx.fillStyle = `rgba(233,237,245,${a})`;
        ctx.fillText(c.name, bx + 16, yy + 0.5);
      }
      ctx.textBaseline = "alphabetic";
    }

    function drawCore() {
      const pulse = 1 + Math.sin(Date.now() / 620) * 0.09;
      const r = 16 * pulse;

      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, r * 2.6);
      grad.addColorStop(0, "rgba(34,197,94,0.42)");
      grad.addColorStop(1, "rgba(34,197,94,0)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(cx, cy, r * 2.6, 0, TAU);
      ctx.fill();

      ctx.beginPath();
      ctx.arc(cx, cy, r, Math.PI, TAU);
      ctx.closePath();
      ctx.fillStyle = "rgba(34,197,94,0.2)";
      ctx.fill();
      ctx.strokeStyle = "rgba(34,197,94,0.95)";
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(233,237,245,0.92)";
      ctx.textAlign = "center";
      ctx.fillText("KORUNAN VARLIK", cx, cy + 14);
    }

    function drawProjectiles() {
      for (let i = projectiles.length - 1; i >= 0; i--) {
        const p = projectiles[i];
        p.r -= p.speed;

        const x = cx + Math.cos(p.angle) * p.r;
        const y = cy + Math.sin(p.angle) * p.r;

        p.trail.push({ x, y });
        if (p.trail.length > 14) p.trail.shift();

        // Kuyruk
        for (let t = 0; t < p.trail.length; t++) {
          const pt = p.trail[t];
          const a = (t / p.trail.length) * 0.55;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 1.6 * (t / p.trail.length) + 0.4, 0, TAU);
          ctx.fillStyle = `rgba(255,90,90,${a})`;
          ctx.fill();
        }

        // Mermi basi
        ctx.beginPath();
        ctx.arc(x, y, 2.6, 0, TAU);
        ctx.fillStyle = "rgba(255,120,110,1)";
        ctx.shadowColor = "rgba(255,80,80,0.9)";
        ctx.shadowBlur = 9;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Katmana ulasti mi? -> mudahale (hangi katmanin durdurdugunu goster)
        if (p.r <= p.targetR) {
          bursts.push({ x, y, t: 0, color: p.color });
          ripples.push({ r: p.targetR, t: 0, color: p.color });
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
        b.t += 0.045;
        if (b.t >= 1) { bursts.splice(i, 1); continue; }

        const r = 3 + b.t * 26;
        ctx.beginPath();
        ctx.arc(b.x, b.y, r, 0, TAU);
        ctx.strokeStyle = `rgba(${b.color},${1 - b.t})`;
        ctx.lineWidth = 2.4 * (1 - b.t);
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(b.x, b.y, r * 0.42, 0, TAU);
        ctx.fillStyle = `rgba(${b.color},${(1 - b.t) * 0.42})`;
        ctx.fill();

        // Kivilcimlar
        for (let s = 0; s < 5; s++) {
          const a = (s / 5) * TAU + b.t * 1.6;
          const d = r * 1.25;
          ctx.beginPath();
          ctx.arc(b.x + Math.cos(a) * d, b.y + Math.sin(a) * d, 1.3 * (1 - b.t), 0, TAU);
          ctx.fillStyle = `rgba(${b.color},${1 - b.t})`;
          ctx.fill();
        }
      }
    }

    function drawHud() {
      // Sag ust kose: panel basligi sol ustte oldugu icin cakisma olmaz
      ctx.font = "600 10px 'JetBrains Mono', monospace";
      ctx.textAlign = "right";
      const x = w - 12;
      ctx.fillStyle = "rgba(139,149,168,0.9)";
      ctx.fillText(`Islenen saldiri: ${stats.total}`, x, 18);
      ctx.fillStyle = "rgba(34,197,94,0.95)";
      ctx.fillText(`Cekirdege ulasan: ${stats.reachedCore}`, x, 33);
      ctx.fillStyle = "rgba(255,90,90,0.9)";
      ctx.fillText(`Ucusta: ${projectiles.length}`, x, 48);
    }

    function frame() {
      if (!w) layout();
      ctx.clearRect(0, 0, w, h);
      drawDome();
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
   * 2) DUNYA HARITASI — saldiri yaylari
   * ========================================================== */
  const AttackMap = (function () {
    const canvas = document.getElementById("map-canvas");
    if (!canvas) return { update() {} };
    const ctx = canvas.getContext("2d");

    let w = 0, h = 0;
    let nodes = [];
    let asset = { lat: 41, lon: 29 };
    const arcs = [];
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

    /** Equirectangular projeksiyon: basit, hizli ve amacimiz icin yeterli. */
    function project(lat, lon) {
      return {
        x: ((lon + 180) / 360) * w,
        y: ((90 - lat) / 180) * h,
      };
    }

    /* Kitalarin cok kaba dis hatlari. Amac cografi dogruluk degil,
     * bakan kisinin "bu bir dunya haritasi" diye tanimasi. Harici bir
     * GeoJSON dosyasi eklemek yerine bu yolu sectik: bagimlilik yok,
     * dosya boyutu yok, cevrimdisi calisir. */
    const LAND = [
      // Kuzey Amerika
      [[-168,66],[-158,71],[-130,70],[-95,70],[-80,73],[-60,60],[-55,50],[-65,45],
       [-70,42],[-75,35],[-81,25],[-97,26],[-107,23],[-115,30],[-124,40],[-125,48],
       [-135,57],[-150,60],[-168,66]],
      // Guney Amerika
      [[-81,10],[-72,12],[-60,5],[-50,0],[-35,-6],[-38,-16],[-48,-25],[-58,-35],
       [-63,-42],[-70,-52],[-75,-50],[-73,-40],[-71,-30],[-70,-18],[-77,-6],[-81,10]],
      // Afrika
      [[-17,15],[0,15],[15,12],[32,15],[43,12],[51,12],[42,-2],[40,-15],[35,-24],
       [25,-34],[18,-34],[12,-18],[9,-1],[5,5],[-8,5],[-17,15]],
      // Avrupa
      [[-10,36],[-9,44],[-2,48],[2,51],[5,53],[8,55],[11,58],[18,60],[24,60],
       [30,60],[40,58],[40,48],[36,45],[28,41],[23,38],[15,38],[12,45],[3,43],[-10,36]],
      // Asya
      [[40,58],[60,62],[80,65],[100,68],[120,70],[140,68],[145,60],[142,50],
       [135,45],[128,38],[121,32],[110,20],[100,12],[95,17],[88,22],[80,10],
       [72,20],[62,25],[55,28],[48,30],[45,40],[40,48],[40,58]],
      // Avustralya
      [[113,-22],[122,-18],[131,-12],[142,-11],[147,-18],[153,-27],[150,-37],
       [141,-38],[131,-32],[123,-34],[115,-34],[113,-22]],
    ];

    function drawWorld() {
      // Izgara (enlem/boylam)
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

      // Kita dis hatlari
      LAND.forEach((poly) => {
        ctx.beginPath();
        poly.forEach(([lon, lat], i) => {
          const p = project(lat, lon);
          if (i === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y);
        });
        ctx.closePath();
        ctx.fillStyle = "rgba(90,120,150,0.075)";
        ctx.fill();
        ctx.strokeStyle = "rgba(120,160,200,0.22)";
        ctx.lineWidth = 1;
        ctx.stroke();
      });
    }

    function launchArc(node) {
      arcs.push({ node, t: 0, speed: 0.011 + Math.random() * 0.006 });
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
      // Aktif dugumlerden periyodik yay: canli his verir ama veri gercek
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

        // Kontrol noktasi: yayin yuksekligi mesafeyle orantili
        const mx = (src.x + target.x) / 2;
        const my = (src.y + target.y) / 2;
        const dist = Math.hypot(target.x - src.x, target.y - src.y);
        const cpx = mx;
        const cpy = my - Math.min(dist * 0.42, h * 0.4);

        // Yayin cizilen kismi
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        const steps = 26;
        for (let s = 1; s <= steps * t; s++) {
          const u = s / steps;
          const x = (1 - u) ** 2 * src.x + 2 * (1 - u) * u * cpx + u * u * target.x;
          const y = (1 - u) ** 2 * src.y + 2 * (1 - u) * u * cpy + u * u * target.y;
          ctx.lineTo(x, y);
        }
        ctx.strokeStyle = `rgba(${color},${0.55 * (1 - Math.max(0, arc.t - 1) * 4)})`;
        ctx.lineWidth = 1.3;
        ctx.stroke();

        // Ucan nokta
        if (t < 1) {
          const u = t;
          const x = (1 - u) ** 2 * src.x + 2 * (1 - u) * u * cpx + u * u * target.x;
          const y = (1 - u) ** 2 * src.y + 2 * (1 - u) * u * cpy + u * u * target.y;
          ctx.beginPath();
          ctx.arc(x, y, 2.6, 0, TAU);
          ctx.fillStyle = `rgba(${color},1)`;
          ctx.shadowColor = `rgba(${color},1)`;
          ctx.shadowBlur = 9;
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          // Hedefte carpma dalgasi
          const impact = (arc.t - 1) * 4;
          ctx.beginPath();
          ctx.arc(target.x, target.y, 4 + impact * 20, 0, TAU);
          ctx.strokeStyle = `rgba(34,197,94,${1 - impact})`;
          ctx.lineWidth = 2 * (1 - impact);
          ctx.stroke();
        }
      }
    }

    function drawNodes() {
      nodes.forEach((node) => {
        const p = project(node.lat, node.lon);
        const color = severityColor(node);
        const r = 2.6 + Math.min(4, Math.log2((node.event_count || 1) + 1));

        // Nabiz halkasi
        const pulse = (Date.now() / 1000 + p.x * 0.01) % 2 / 2;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + pulse * 12, 0, TAU);
        ctx.strokeStyle = `rgba(${color},${(1 - pulse) * 0.35})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, TAU);
        ctx.fillStyle = `rgba(${color},0.95)`;
        ctx.shadowColor = `rgba(${color},0.8)`;
        ctx.shadowBlur = 7;
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
      const p = project(asset.lat, asset.lon);
      ctx.beginPath();
      ctx.arc(p.x, p.y, 6, 0, TAU);
      ctx.fillStyle = "rgba(34,197,94,0.25)";
      ctx.fill();
      ctx.strokeStyle = "rgba(34,197,94,1)";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Kalkan isareti
      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(34,197,94,0.95)";
      ctx.textAlign = "center";
      ctx.fillText("KORUNAN", p.x, p.y - 12);
    }

    function frame() {
      if (!w) layout();
      ctx.clearRect(0, 0, w, h);
      drawWorld();
      drawArcs();
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

  // dashboard.js her poll'da bunu cagirir
  window.ArachneCommandCenter = {
    update(data) {
      if (!data) return;
      IronDome.update(data.dome);
      AttackMap.update(data.attack_map);
      renderLayerHealth(data.layer_health);
      renderDomeLegend(data.dome);
      renderMapLegend(data.attack_map);
    },
  };
})();
