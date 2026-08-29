/* ============================================================
   ARACHNE SENTINEL — "Şebeke" görünümü (webnet.js)

   Instagram'da görülen bir AI-ajan orbital arayüzünden ilham alındı, ama
   burada süs değil: aynı Çelik Kubbe'yi besleyen GERÇEK veriyi (18 gerçek
   savunma katmanı, gerçek olay sayıları — bkz. command_center.py
   DEFENSE_LAYERS / build_dome_state) farklı bir geometriyle çizer. Kubbe
   iç içe halkalar çiziyor; burada aynı katmanlar merkeze bağlı "ağ
   ipliği" düğümleri olarak, örümcek ağı motifiyle gösteriliyor.

   Veri kaynağı: /api/state -> dome (app.js zaten her 4 sn'de bir çekiyor).
   Hiçbir yeni sahte deger uretilmez; dugum boyutu/parlakligi GERCEK
   `interceptions` sayisina, cekirdek rengi GERCEK `posture` degerine baglidir.
   ============================================================ */
(function () {
  "use strict";
  const canvas = document.getElementById("web-canvas");
  if (!canvas) { window.ArachneWebNet = { update() {} }; return; }
  const ctx = canvas.getContext("2d");
  const detailEl = document.getElementById("web-detail");
  const legendEl = document.getElementById("web-legend");

  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  let W = 0, H = 0;
  let nodes = [];          // {layer, x, y, angle, dist}
  let particles = [];      // {fromX,fromY,toX,toY,t,color}
  let seenProjectileIds = new Set();
  let posture = { level: "NORMAL", tone: "calm" };
  let hoverNode = null;
  let pinnedNode = null;
  let t0 = performance.now();

  const POSTURE_COLOR = {
    calm: "34,211,238", elevated: "245,166,35", high: "255,122,69", critical: "255,59,69",
  };

  function resize() {
    const rect = canvas.getBoundingClientRect();
    W = Math.max(rect.width, 200); H = Math.max(rect.height, 200);
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    layout();
  }
  window.addEventListener("resize", resize);

  function layout() {
    if (!nodes.length) return;
    const cx = W / 2, cy = H / 2;
    const maxR = Math.min(W, H) * 0.44;
    const minR = Math.min(W, H) * 0.14;
    const n = nodes.length;
    nodes.forEach((node, i) => {
      const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
      // katmanin var olan "radius" alanini (1.0 disarida -> 0.09 cekirdege
      // yakin, ayni Celik Kubbe'de kullanilan gercek deger) mesafeye cevir.
      const dist = minR + (node.layer.radius) * (maxR - minR);
      node.angle = angle; node.dist = dist;
      node.x = cx + Math.cos(angle) * dist;
      node.y = cy + Math.sin(angle) * dist;
    });
  }

  function nodeRadius(layer) {
    const base = 4.5;
    const boost = Math.min(Math.log2((layer.interceptions || 0) + 1) * 3.2, 16);
    return base + boost;
  }

  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H / 2;
    const breathe = 0.5 + 0.5 * Math.sin(now * 0.0016);
    const pColor = POSTURE_COLOR[posture.tone] || POSTURE_COLOR.calm;

    // ambient dust
    for (let i = 0; i < 26; i++) {
      const a = (i / 26) * Math.PI * 2 + now * 0.00005;
      const r = Math.min(W, H) * (0.15 + 0.35 * ((i * 37) % 100) / 100);
      ctx.beginPath();
      ctx.arc(cx + Math.cos(a) * r, cy + Math.sin(a) * r, 1, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${pColor},${0.12 + 0.1 * Math.sin(now * 0.001 + i)})`;
      ctx.fill();
    }

    // threads (core -> node)
    nodes.forEach((node) => {
      const active = node.layer.interceptions > 0;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      // hafif egri iplik (spider silk) - kontrol noktasi orta yaricapta
      const midX = cx + (node.x - cx) * 0.5 + Math.cos(node.angle + Math.PI / 2) * 10;
      const midY = cy + (node.y - cy) * 0.5 + Math.sin(node.angle + Math.PI / 2) * 10;
      ctx.quadraticCurveTo(midX, midY, node.x, node.y);
      ctx.strokeStyle = active ? `rgba(${node.layer.color},0.55)` : "rgba(140,150,170,0.14)";
      ctx.lineWidth = active ? 1.4 : 1;
      ctx.stroke();
    });

    // concentric guide rings (spider-web cross-threads) - salt gorsel rehber
    const ringCount = 4;
    for (let i = 1; i <= ringCount; i++) {
      const r = (Math.min(W, H) * 0.14) + (i / ringCount) * (Math.min(W, H) * 0.3);
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(140,150,170,0.07)";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // particles (yeni olaylar - kenardan dugume akar)
    particles = particles.filter((p) => now - p.start < p.dur);
    particles.forEach((p) => {
      const tt = (now - p.start) / p.dur;
      const ease = 1 - Math.pow(1 - tt, 3);
      const x = p.fromX + (p.toX - p.fromX) * ease;
      const y = p.fromY + (p.toY - p.fromY) * ease;
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = `rgb(${p.color})`;
      ctx.shadowColor = `rgb(${p.color})`; ctx.shadowBlur = 10;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // nodes
    nodes.forEach((node) => {
      const r = nodeRadius(node.layer);
      const isHover = hoverNode === node || pinnedNode === node;
      ctx.beginPath();
      ctx.arc(node.x, node.y, r + (isHover ? 4 : 0), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${node.layer.color},${node.layer.interceptions > 0 ? 0.9 : 0.35})`;
      if (node.layer.interceptions > 0 || isHover) {
        ctx.shadowColor = `rgb(${node.layer.color})`;
        ctx.shadowBlur = isHover ? 22 : 12;
      }
      ctx.fill();
      ctx.shadowBlur = 0;
      if (isHover) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, r + 7, 0, Math.PI * 2);
        ctx.strokeStyle = `rgb(${node.layer.color})`;
        ctx.lineWidth = 1.4;
        ctx.stroke();
      }
      // etiket
      ctx.font = "600 10px 'JetBrains Mono', monospace";
      ctx.fillStyle = isHover ? "#e9edf5" : "rgba(180,190,205,0.75)";
      const labelX = node.x + Math.cos(node.angle) * (r + 14);
      const labelY = node.y + Math.sin(node.angle) * (r + 14);
      ctx.textAlign = Math.cos(node.angle) > 0.15 ? "left" : (Math.cos(node.angle) < -0.15 ? "right" : "center");
      ctx.textBaseline = "middle";
      ctx.fillText(node.layer.name, labelX, labelY);
    });

    // core (korunan varlik / cekirdek)
    const coreR = 22 + breathe * 4;
    ctx.beginPath();
    ctx.arc(cx, cy, coreR + 10, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${pColor},0.10)`;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(cx, cy, coreR, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${pColor},0.9)`;
    ctx.shadowColor = `rgb(${pColor})`; ctx.shadowBlur = 24;
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.font = "700 9px 'JetBrains Mono', monospace";
    ctx.fillStyle = "#05070a";
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText("ÇEKİRDEK", cx, cy);
  }

  function loop(now) {
    draw(now);
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);

  /* ---------- etkilesim: hover/tik ile katman detayi ---------- */
  function pick(mx, my) {
    let best = null, bestD = 22;
    nodes.forEach((node) => {
      const d = Math.hypot(node.x - mx, node.y - my);
      if (d < bestD) { bestD = d; best = node; }
    });
    return best;
  }
  function showDetail(node) {
    if (!detailEl) return;
    if (!node) { detailEl.classList.remove("open"); return; }
    const l = node.layer;
    detailEl.innerHTML =
      `<div class="wd-head" style="color:rgb(${l.color})">${l.name} <small>${l.phase}</small></div>` +
      `<div class="wd-count">${l.interceptions} <span>olay bu oturumda</span></div>` +
      `<div class="wd-desc">${l.description_tr || ""}</div>`;
    detailEl.classList.add("open");
  }
  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    hoverNode = pick(e.clientX - rect.left, e.clientY - rect.top);
    canvas.style.cursor = hoverNode ? "pointer" : "default";
    if (!pinnedNode) showDetail(hoverNode);
  });
  canvas.addEventListener("mouseleave", () => { hoverNode = null; if (!pinnedNode) showDetail(null); });
  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const picked = pick(e.clientX - rect.left, e.clientY - rect.top);
    pinnedNode = pinnedNode === picked ? null : picked;
    showDetail(pinnedNode || hoverNode);
  });

  /* ---------- legend (gercek sayaclarla) ---------- */
  function renderLegend() {
    if (!legendEl) return;
    legendEl.innerHTML = nodes
      .slice()
      .sort((a, b) => (b.layer.interceptions || 0) - (a.layer.interceptions || 0))
      .map((node) => {
        const l = node.layer;
        return `<div class="dome-legend-item ${l.active ? "active" : ""}" title="${l.description_tr || ""}">` +
          `<span class="dl-sw" style="background:rgb(${l.color})"></span>` +
          `<span class="dl-name">${l.name}</span>` +
          `<span class="dl-count">${l.interceptions}</span></div>`;
      }).join("");
  }

  /* ---------- disariya acilan API: app.js her /api/state tikinde cagirir ---------- */
  function update(dome) {
    if (!dome || !dome.layers) return;
    const layerMap = new Map(nodes.map((n) => [n.layer.id, n]));
    nodes = dome.layers.map((layer) => layerMap.get(layer.id) || { layer, x: 0, y: 0 });
    nodes.forEach((n) => { n.layer = dome.layers.find((l) => l.id === n.layer.id) || n.layer; });
    layout();
    renderLegend();
    posture = { level: dome.posture && dome.posture.level, tone: (dome.posture && dome.posture.tone) || "calm" };

    // yeni mermileri (projectiles) yakala -> kenardan dugume akan parcacik
    (dome.projectiles || []).forEach((p) => {
      if (seenProjectileIds.has(p.id)) return;
      seenProjectileIds.add(p.id);
      const node = nodes.find((n) => n.layer.id === p.intercepted_by);
      if (!node) return;
      const cx = W / 2, cy = H / 2;
      const edgeAngle = node.angle;
      particles.push({
        fromX: cx + Math.cos(edgeAngle) * (Math.max(W, H) * 0.6),
        fromY: cy + Math.sin(edgeAngle) * (Math.max(W, H) * 0.6),
        toX: node.x, toY: node.y,
        start: performance.now(), dur: 650,
        color: node.layer.color,
      });
    });
    // bellek sismesin - eski gorulen id'leri sinirla
    if (seenProjectileIds.size > 400) {
      seenProjectileIds = new Set(Array.from(seenProjectileIds).slice(-200));
    }
  }

  resize();
  window.ArachneWebNet = { update };
})();
