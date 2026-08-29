/* ============================================================
   ARACHNE SENTINEL — tanıtım sitesi "Şebeke" mini-görselleştirmesi

   Gerçek dashboard'daki (arachne/reporting) radyal görünümün küçültülmüş,
   bu sitenin KENDİ gerçek WAF olay kaydına bağlı hali. Sahte satır yok:
   /api/waf-live bu sitenin dogfooding WAFMiddleware'ının gerçekten
   işlediği isteklerden sayım döner. Trafik yoksa düğümler dürüstçe sönük
   kalır — 0 ise 0 gösterilir.
   ============================================================ */
(function () {
  "use strict";
  const canvas = document.getElementById("web-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const legendEl = document.getElementById("web-legend");
  const voiceBtn = document.getElementById("web-voice-toggle");
  const micBtn = document.getElementById("web-mic");

  const SILK = "82,221,199", EMBER = "240,130,74", DUST = "138,150,176";
  const NODE_COLORS = {
    "SQL Injection": "240,130,74", "XSS": "245,166,35", "Path Traversal": "234,179,8",
    "Command Injection": "255,59,69", "SSTI": "163,230,53",
  };

  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  let W = 0, H = 0;
  let nodes = [];
  let particles = [];
  let seenIds = new Set();
  let totals = { total_requests: 0, blocked_requests: 0 };
  let firstLoad = true;

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
    const cx = W / 2, cy = H / 2;
    const r = Math.min(W, H) * 0.36;
    const n = nodes.length || 1;
    nodes.forEach((node, i) => {
      const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
      node.angle = angle;
      node.x = cx + Math.cos(angle) * r;
      node.y = cy + Math.sin(angle) * r;
    });
  }

  function nodeRadius(count) {
    return 5 + Math.min(Math.log2(count + 1) * 3, 14);
  }

  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    const cx = W / 2, cy = H / 2;
    const breathe = 0.5 + 0.5 * Math.sin(now * 0.0016);

    nodes.forEach((node) => {
      const active = node.count > 0;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      const midX = cx + (node.x - cx) * 0.5 + Math.cos(node.angle + Math.PI / 2) * 8;
      const midY = cy + (node.y - cy) * 0.5 + Math.sin(node.angle + Math.PI / 2) * 8;
      ctx.quadraticCurveTo(midX, midY, node.x, node.y);
      ctx.strokeStyle = active ? `rgba(${node.color},0.55)` : "rgba(120,130,150,0.16)";
      ctx.lineWidth = active ? 1.3 : 1;
      ctx.stroke();
    });

    particles = particles.filter((p) => now - p.start < p.dur);
    particles.forEach((p) => {
      const tt = (now - p.start) / p.dur;
      const ease = 1 - Math.pow(1 - tt, 3);
      const x = p.fromX + (p.toX - p.fromX) * ease;
      const y = p.fromY + (p.toY - p.fromY) * ease;
      ctx.beginPath(); ctx.arc(x, y, 2.6, 0, Math.PI * 2);
      ctx.fillStyle = `rgb(${p.color})`;
      ctx.shadowColor = `rgb(${p.color})`; ctx.shadowBlur = 9;
      ctx.fill(); ctx.shadowBlur = 0;
    });

    nodes.forEach((node) => {
      const r = nodeRadius(node.count);
      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${node.color},${node.count > 0 ? 0.9 : 0.3})`;
      if (node.count > 0) { ctx.shadowColor = `rgb(${node.color})`; ctx.shadowBlur = 14; }
      ctx.fill(); ctx.shadowBlur = 0;
      ctx.font = "600 10px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(200,208,222,0.85)";
      const lx = node.x + Math.cos(node.angle) * (r + 12);
      const ly = node.y + Math.sin(node.angle) * (r + 12);
      ctx.textAlign = Math.cos(node.angle) > 0.15 ? "left" : (Math.cos(node.angle) < -0.15 ? "right" : "center");
      ctx.textBaseline = "middle";
      ctx.fillText(node.label, lx, ly);
    });

    const coreR = 18 + breathe * 3;
    ctx.beginPath(); ctx.arc(cx, cy, coreR + 8, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${SILK},0.12)`; ctx.fill();
    ctx.beginPath(); ctx.arc(cx, cy, coreR, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(${SILK},0.9)`;
    ctx.shadowColor = `rgb(${SILK})`; ctx.shadowBlur = 18; ctx.fill(); ctx.shadowBlur = 0;
    ctx.font = "700 9px 'JetBrains Mono', monospace";
    ctx.fillStyle = "#0a0e16"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText("SİTE", cx, cy);
  }

  function loop(now) { draw(now); requestAnimationFrame(loop); }
  requestAnimationFrame(loop);

  function renderLegend() {
    if (!legendEl) return;
    legendEl.innerHTML = nodes.map((n) =>
      `<div class="dome-legend-item ${n.count > 0 ? "active" : ""}">` +
      `<span class="dl-sw" style="background:rgb(${n.color})"></span>` +
      `<span class="dl-name">${n.label}</span><span class="dl-count">${n.count}</span></div>`
    ).join("") +
    `<div class="dome-legend-item"><span class="dl-name">Toplam istek</span><span class="dl-count">${totals.total_requests}</span></div>` +
    `<div class="dome-legend-item active"><span class="dl-name">Engellenen</span><span class="dl-count">${totals.blocked_requests}</span></div>`;
  }

  /* ---------- sesli anons (Web Speech API, tarayici-ici) ---------- */
  let voiceOn = false;
  function speak(text) {
    if (!voiceOn || !("speechSynthesis" in window)) return;
    try {
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "tr-TR"; u.rate = 1; u.pitch = 1;
      window.speechSynthesis.speak(u);
    } catch (e) {}
  }
  if (voiceBtn) {
    voiceBtn.addEventListener("click", () => {
      voiceOn = !voiceOn;
      voiceBtn.textContent = voiceOn ? "🔊 Sesli anlatım açık" : "🔇 Sesli anlatım";
      voiceBtn.classList.toggle("on", voiceOn);
      if (voiceOn) speak("Sesli anlatım açık. Bu sitenin gerçek WAF olaylarını anons edeceğim.");
    });
  }

  /* ---------- basit sesli soru-cevap (gercek, sabit istatistikler) ---------- */
  if (micBtn) {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { micBtn.style.display = "none"; }
    else {
      const rec = new SR();
      rec.lang = "tr-TR"; rec.interimResults = false;
      rec.addEventListener("start", () => micBtn.classList.add("listening"));
      rec.addEventListener("end", () => micBtn.classList.remove("listening"));
      rec.addEventListener("result", (e) => {
        const q = (e.results[0][0].transcript || "").toLowerCase();
        let answer = "Bunu şu an yanıtlayamıyorum — web sitesinden veya carousel'den bakabilirsiniz.";
        if (/kaç test|test sayısı/.test(q)) answer = "Depoda 802 otomatik test var, hepsi geçiyor.";
        else if (/f1|skor/.test(q)) answer = "Ölçülen F1 skoru 0 nokta 9 7 6.";
        else if (/kaç saldırı|engellen|blok/.test(q)) answer = `Bu sitede şu ana kadar ${totals.blocked_requests} istek engellendi, toplam ${totals.total_requests} istekten.`;
        else if (/faz/.test(q)) answer = "113 geliştirme fazı tamamlandı.";
        voiceOn = true; speak(answer);
      });
      micBtn.addEventListener("click", () => { try { rec.start(); } catch (e) {} });
    }
  }

  async function poll() {
    let d;
    try { d = await (await fetch("/api/waf-live", { cache: "no-store" })).json(); }
    catch (e) { return; }
    totals = { total_requests: d.total_requests || 0, blocked_requests: d.blocked_requests || 0 };
    const prevCounts = new Map(nodes.map((n) => [n.id, n.count]));
    nodes = (d.nodes || []).map((n) => ({
      id: n.id, label: n.label, count: n.count, color: NODE_COLORS[n.id] || DUST,
    }));
    layout();
    renderLegend();

    if (!firstLoad) {
      nodes.forEach((n) => {
        const prev = prevCounts.get(n.id) || 0;
        if (n.count > prev) {
          const cx = W / 2, cy = H / 2;
          particles.push({
            fromX: cx + Math.cos(n.angle) * Math.max(W, H), fromY: cy + Math.sin(n.angle) * Math.max(W, H),
            toX: n.x, toY: n.y, start: performance.now(), dur: 550, color: n.color,
          });
          speak(`Gerçek zamanlı olay: ${n.label} denemesi tespit edildi ve engellendi.`);
        }
      });
    }
    firstLoad = false;
  }

  resize();
  poll();
  setInterval(poll, 5000);
})();
