/* ============================================================
   ARACHNE SENTINEL — Komuta Merkezi SPA denetleyicisi (Faz 20)

   Sorumluluk:
     - Gorunum yonlendirme (sidebar sekmeleri)
     - /api/state (hizli, 4sn) ve /api/deep (yavas, 20sn) poll
     - Her gorunumun render'i
     - Canli akis (feed) + radar + kritik alarm ses/toast

   Dome + harita gorsellestirmesi command_center.js'te; buradan beslenir.
   Tum veri gercektir - hicbir sahte deger uretilmez.
   ============================================================ */
(function () {
  "use strict";

  const STATE_POLL = 4000;
  const DEEP_POLL = 20000;
  const TAU = Math.PI * 2;

  const VIEW_META = {
    overview: ["Genel Bakış", "Sistemin canlı durumu ve tehdit özeti"],
    command: ["Çelik Kubbe", "Katmanlı savunma simülasyonu ve küresel harita"],
    feed: ["Canlı Akış", "Gerçek zamanlı olay radarı ve akış terminali"],
    threats: ["Tehdit İstihbaratı", "AI durum raporu, risk sıralı profiller, saldırı grafiği"],
    reverse: ["Tersine Mühendislik", "Yük analiz laboratuvarı — kodlama çözümü ve ATT&CK"],
    rules: ["Kurallar & Bütünlük", "İmza motoru, otomatik imza üretimi, denetim zinciri"],
    soar: ["SOAR & Aktif Savunma", "Otonom müdahale, tarpit/aldatma, honeytoken tuzakları"],
    mesh: ["Sensör Ağı", "Dağıtık, HMAC imzalı sensör ağı"],
    adaptive: ["Adaptif Savunma", "Ko-evrim · D3FEND/CSF kapsamı · oyun teorisi · kolektif bağışıklık"],
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);
  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function timePart(ts) { const p = String(ts || "").split(" "); return esc(p[1] || ts || ""); }
  function sevBadge(s) { return `<span class="badge badge-${esc(s || "info")}">${esc(s || "-")}</span>`; }

  /* ---------- routing ---------- */
  let currentView = "overview";
  function switchView(view) {
    if (!VIEW_META[view]) return;
    currentView = view;
    $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
    $$(".view").forEach((v) => v.classList.remove("active"));
    const el = $("#view-" + view);
    if (el) el.classList.add("active");
    $("#view-title").textContent = VIEW_META[view][0];
    $("#view-sub").textContent = VIEW_META[view][1];
    // Gizli canvas'lar aktif olunca yeniden boyutlanmali
    window.dispatchEvent(new Event("resize"));
    // Derin veri gerektiren gorunumler acilinca hemen cek
    if ((view === "threats" || view === "rules" || view === "adaptive") && !deepData) fetchDeep();
    if (view === "threats" && deepData) renderThreats(deepData.threats);
    if (view === "rules" && deepData) renderRules(deepData.rules_integrity);
    if (view === "adaptive" && deepData) renderAdaptive(deepData.adaptive);
  }
  $$(".nav-item").forEach((n) => n.addEventListener("click", () => switchView(n.dataset.view)));

  /* ============================================================
     RADAR (canli akis gorunumu)
     ============================================================ */
  const Radar = (function () {
    const canvas = $("#radar-canvas");
    if (!canvas) return { pulse() {} };
    const ctx = canvas.getContext("2d");
    let w, h, cx, cy, radius, rot = 0;
    const NODES = [
      { key: "ssh", label: "SSH", color: "34,211,238" },
      { key: "ftp", label: "FTP", color: "34,211,238" },
      { key: "mysql", label: "MySQL", color: "34,211,238" },
      { key: "http-admin", label: "HTTP-Admin", color: "34,211,238" },
      { key: "waf", label: "WAF", color: "245,166,35" },
      { key: "mtd", label: "MTD", color: "45,212,191" },
      { key: "defense", label: "Aktif Savunma", color: "167,139,250" },
    ];
    const pulses = [];
    function layout() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth; h = canvas.clientHeight;
      if (!w) return;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = w / 2; cy = h / 2; radius = Math.min(w, h) * 0.36;
    }
    window.addEventListener("resize", layout);
    function pos(i) { const a = (i / NODES.length) * TAU + rot; return { x: cx + Math.cos(a) * radius, y: cy + Math.sin(a) * radius, a }; }
    function pulse(key) { const i = NODES.findIndex((n) => n.key === key); if (i >= 0) pulses.push({ i, t: 0 }); }
    function frame() {
      if (!w) layout();
      if (!w) { requestAnimationFrame(frame); return; }
      ctx.clearRect(0, 0, w, h); rot += 0.0009;
      const sweep = (Date.now() / 3200) % TAU;
      ctx.save(); ctx.beginPath(); ctx.arc(cx, cy, radius * 1.3, sweep, sweep + 0.9); ctx.lineTo(cx, cy);
      ctx.closePath(); ctx.fillStyle = "rgba(34,211,238,0.045)"; ctx.fill(); ctx.restore();
      ctx.strokeStyle = "rgba(120,150,180,0.12)"; ctx.lineWidth = 1;
      [0.45, 0.75, 1.05].forEach((f) => { ctx.beginPath(); ctx.arc(cx, cy, radius * f, 0, TAU); ctx.stroke(); });
      NODES.forEach((n, i) => { const p = pos(i); ctx.strokeStyle = "rgba(120,150,180,0.14)"; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(p.x, p.y); ctx.stroke(); });
      ctx.beginPath(); ctx.arc(cx, cy, 14, 0, TAU); ctx.fillStyle = "rgba(255,59,69,0.14)"; ctx.fill();
      ctx.strokeStyle = "rgba(255,59,69,0.85)"; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.font = "700 8px 'JetBrains Mono',monospace"; ctx.fillStyle = "rgba(233,237,245,0.85)"; ctx.textAlign = "center"; ctx.fillText("CORE", cx, cy + 3);
      NODES.forEach((n, i) => {
        const p = pos(i);
        ctx.beginPath(); ctx.arc(p.x, p.y, 5, 0, TAU); ctx.fillStyle = `rgba(${n.color},0.9)`; ctx.shadowColor = `rgba(${n.color},0.9)`; ctx.shadowBlur = 7; ctx.fill(); ctx.shadowBlur = 0;
        ctx.font = "600 9px 'JetBrains Mono',monospace"; ctx.fillStyle = "rgba(200,210,225,0.75)";
        const al = Math.cos(p.a) > 0.15 ? "left" : Math.cos(p.a) < -0.15 ? "right" : "center"; ctx.textAlign = al;
        const off = al === "left" ? 9 : al === "right" ? -9 : 0;
        ctx.fillText(n.label, p.x + off, p.y + (Math.sin(p.a) > 0 ? 14 : -9));
      });
      for (let k = pulses.length - 1; k >= 0; k--) {
        const pu = pulses[k]; pu.t += 0.028; if (pu.t >= 1) { pulses.splice(k, 1); continue; }
        const p = pos(pu.i); const x = p.x + (cx - p.x) * pu.t, y = p.y + (cy - p.y) * pu.t; const n = NODES[pu.i];
        ctx.beginPath(); ctx.arc(p.x, p.y, 5 + pu.t * 20, 0, TAU); ctx.strokeStyle = `rgba(${n.color},${1 - pu.t})`; ctx.lineWidth = 2; ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y, 3, 0, TAU); ctx.fillStyle = `rgba(${n.color},1)`; ctx.shadowColor = `rgba(${n.color},1)`; ctx.shadowBlur = 9; ctx.fill(); ctx.shadowBlur = 0;
      }
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
    return { pulse };
  })();

  /* ============================================================
     CANLI AKIS + kritik alarm ses/toast
     ============================================================ */
  const seen = { alerts: new Set(), events: new Set(), waf: new Set(), mtd: new Set(), def: new Set() };
  let firstFeed = true, feedNewCount = 0;
  function pushFeed(html) {
    const body = $("#feed-body"); if (!body) return;
    const empty = body.querySelector(".feed-empty"); if (empty) empty.remove();
    const line = document.createElement("div"); line.className = "feed-line"; line.innerHTML = html;
    body.prepend(line);
    while (body.children.length > 80) body.removeChild(body.lastChild);
    if (currentView !== "feed") { feedNewCount++; updateBadge("badge-feed", feedNewCount); }
  }
  function nodeForService(s) { s = (s || "").toLowerCase(); if (s.includes("ssh")) return "ssh"; if (s.includes("ftp")) return "ftp"; if (s.includes("mysql")) return "mysql"; if (s.includes("admin")) return "http-admin"; return null; }

  const Sound = (function () {
    const btn = $("#sound-toggle"); let ac = null, on = false;
    if (btn) btn.addEventListener("click", () => {
      on = !on; btn.textContent = on ? "🔊 Ses" : "🔇 Ses";
      if (on && !ac) { try { ac = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) {} }
      if (ac && ac.state === "suspended") ac.resume();
    });
    function beep() {
      if (!on || !ac) return; const t = ac.currentTime; const o = ac.createOscillator(), g = ac.createGain();
      o.type = "square"; o.frequency.setValueAtTime(880, t); o.frequency.exponentialRampToValueAtTime(440, t + 0.18);
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.06, t + 0.01); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.22);
      o.connect(g).connect(ac.destination); o.start(t); o.stop(t + 0.24);
    }
    return { beep };
  })();
  function toast(title, body) {
    const root = $("#toast-root"); if (!root) return;
    const el = document.createElement("div"); el.className = "card"; el.style.cssText = "border-color:var(--accent);min-width:260px;animation:fade .3s ease;";
    el.innerHTML = `<div style="color:var(--accent);font-family:var(--font-mono);font-size:.72rem;font-weight:700;">${title}</div><div style="font-size:.8rem;margin-top:.25rem;">${body}</div>`;
    root.appendChild(el); setTimeout(() => el.remove(), 5000);
  }

  function updateBadge(id, n) { const b = $("#" + id); if (!b) return; b.textContent = n; b.classList.toggle("zero", !n); }

  /* ============================================================
     OVERVIEW render
     ============================================================ */
  const KPI_DEFS = [
    ["events", "Honeypot Olayı", "c-cyan", ""],
    ["alerts", "Alarm", "c-red", ""],
    ["active_blocks", "Aktif Engelleme", "c-red", "SOAR kısıtlaması"],
    ["mtd_rotations", "MTD Rotasyonu", "c-teal", "kimlik değişimi"],
    ["deception_actions", "Aktif Savunma", "c-purple", "aldatma eylemi"],
    ["honeytokens_triggered", "Tetiklenen Tuzak", "c-pink", "honeytoken"],
    ["sensors_online", "Çevrimiçi Sensör", "c-green", ""],
    ["awaiting_approval", "İnsan Onayı Bekleyen", "c-amber", "SOAR eylemi"],
  ];
  function animateCount(el, to) {
    if (!el) return; const from = parseInt(el.textContent.replace(/[^\d-]/g, ""), 10) || 0;
    if (from === to) { el.textContent = to; return; }
    const dur = 600, start = performance.now();
    function step(now) { const p = Math.min(1, (now - start) / dur); el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step); else el.textContent = to; }
    requestAnimationFrame(step);
  }
  let kpiBuilt = false;
  function renderOverview(ov) {
    if (!ov) return;
    const tone = ov.posture_tone || "calm";
    const box = $("#ov-posture"); box.className = "posture-box " + tone;
    $("#ov-posture-val").textContent = ov.posture;
    const k = ov.kpis;
    $("#ov-summary").textContent = summaryText(ov);
    const chips = [
      ["Olay", k.events], ["Alarm", k.alerts], ["Kritik", k.critical_alerts],
      ["WAF", `${k.waf_blocked}/${k.waf_total}`], ["Engelli IP", k.active_blocks],
      ["Sensör", `${k.sensors_online}/${k.sensors_total}`], ["Tuzak", k.honeytokens_total],
    ];
    $("#ov-chips").innerHTML = chips.map(([l, v]) => `<span class="chip"><b>${v}</b> ${l}</span>`).join("");

    if (!kpiBuilt) {
      $("#ov-kpis").innerHTML = KPI_DEFS.map(([key, label, cls, sub]) =>
        `<div class="kpi card ${cls}"><div class="label">${label}</div><div class="val" id="kpi-${key}">0</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`).join("");
      kpiBuilt = true;
    }
    KPI_DEFS.forEach(([key]) => animateCount($("#kpi-" + key), k[key] || 0));
    drawTimeline(ov.alerts_timeline || []);
  }
  function summaryText(ov) {
    const k = ov.kpis;
    if (ov.posture === "SAKİN") return "Sistem gözlem modunda — henüz alarm üretilmedi. Tüm savunma katmanları hazır.";
    let t = `${k.alerts} alarm üretildi`;
    if (k.critical_alerts) t += `, bunların ${k.critical_alerts} tanesi kritik seviyede`;
    if (k.active_blocks) t += `. ${k.active_blocks} IP otomatik olarak engellendi`;
    if (k.honeytokens_triggered) t += `. ${k.honeytokens_triggered} honeytoken tuzağı tetiklendi (yüksek güvenli ihlal)`;
    return t + ".";
  }
  function drawTimeline(counts) {
    const c = $("#ov-timeline"); if (!c) return; const ctx = c.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2); const w = c.clientWidth, h = c.clientHeight;
    if (!w) return; c.width = w * dpr; c.height = h * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
    const n = counts.length || 12, max = Math.max(1, ...counts), bw = w / n, pad = 18;
    ctx.strokeStyle = "rgba(120,150,180,0.1)";
    [0.33, 0.66].forEach((f) => { const y = pad + (h - pad * 1.5) * f; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); });
    counts.forEach((v, i) => {
      const bh = v === 0 ? 0 : Math.max(3, (h - pad * 1.5) * v / max); const x = i * bw + bw * 0.2, bwid = bw * 0.6, y = h - pad - bh;
      const g = ctx.createLinearGradient(0, y, 0, h - pad); g.addColorStop(0, "rgba(255,59,69,0.9)"); g.addColorStop(1, "rgba(34,211,238,0.5)");
      ctx.fillStyle = v > 0 ? g : "rgba(120,150,180,0.13)"; ctx.fillRect(x, y, bwid, bh);
    });
    ctx.font = "500 9px 'JetBrains Mono',monospace"; ctx.fillStyle = "rgba(139,147,167,0.75)";
    ctx.textAlign = "left"; ctx.fillText("60 dk önce", 2, h - 4); ctx.textAlign = "right"; ctx.fillText("şimdi", w - 2, h - 4);
  }

  /* ============================================================
     DEFENSE LAYER HEALTH (command view)
     ============================================================ */
  const LAYER_ORDER = ["soar", "active_defense", "honeytokens", "mtd", "waf", "deception", "detection", "mesh", "ai"];
  function renderLayers(h) {
    const root = $("#layer-health"); if (!root || !h) return;
    root.innerHTML = LAYER_ORDER.map((key) => {
      const l = h[key]; if (!l) return "";
      return `<div class="layer-card ${l.operational ? "ok" : ""}">
        <div class="lc-head"><span class="lc-dot"></span><span class="lc-name">${esc(l.label)}</span><span class="lc-phase">${esc(l.phase)}</span></div>
        <div class="lc-metric">${l.metric}<span>${esc(l.metric_label)}</span></div>
        <div class="lc-detail">${esc(l.detail)}</div></div>`;
    }).join("");
  }

  /* ============================================================
     SOAR / AKTIF SAVUNMA / SENSOR render
     ============================================================ */
  function renderSoarView(ad, live) {
    // Bloklar
    const bl = $("#blocks-list");
    if (bl) bl.innerHTML = (ad.active_blocks || []).length
      ? `<div style="display:flex;flex-wrap:wrap;gap:.5rem;">` + ad.active_blocks.map((b) =>
          `<div class="chip" title="${esc(b.reason)}" style="border-color:rgba(255,59,69,.3);color:var(--accent);"><b>${esc(b.ip)}</b> ${b.remaining_seconds}sn</div>`).join("") + `</div>`
      : `<div class="card pad-sm"><div class="empty" style="padding:1rem;">Aktif kısıtlama yok</div></div>`;

    // Honeytokens
    const ht = $("#honeytokens-list");
    if (ht) ht.innerHTML = (ad.honeytokens || []).length
      ? ad.honeytokens.slice(0, 10).map((t) =>
          `<div class="token-row ${t.triggered ? "triggered" : ""}"><span class="token-type">${esc(t.token_type)}</span><span class="token-val">${esc(t.value)}</span>${t.triggered ? '<span class="badge badge-critical">TETİKLENDİ</span>' : '<span class="badge badge-info">bekliyor</span>'}</div>`).join("")
      : `<div class="empty" style="padding:1rem;">Tuzak yok<span class="hint">full-demo tuzakları yerleştirir</span></div>`;

    // SOAR audit
    const st = $("#soar-tbody");
    if (st) st.innerHTML = (ad.soar_actions || []).length
      ? ad.soar_actions.map((a) => `<tr><td class="mono muted">${timePart(a.timestamp)}</td><td class="mono">${esc(a.action)}</td><td class="mono">${esc(a.target)}</td><td class="mono muted">${esc(a.playbook || "—")}</td><td>${a.outcome === "onay-bekliyor" ? '<span class="badge badge-critical">onay bekliyor</span>' : '<span class="badge badge-ok">uygulandı</span>'}</td><td class="reasons">${esc(a.reason || "")}</td></tr>`).join("")
      : `<tr><td colspan="6" class="empty">Henüz müdahale yok<span class="hint">python main.py soar-demo</span></td></tr>`;

    // Active defense
    const dt = $("#defense-tbody");
    if (dt) dt.innerHTML = (ad.active_defense_log || []).length
      ? ad.active_defense_log.map((d) => `<tr><td class="mono muted">${timePart(d.timestamp)}</td><td class="mono">${esc(d.source_ip)}</td><td><span class="badge badge-info">${esc(d.technique)}</span></td><td class="reasons">${esc(d.detail || "")}</td></tr>`).join("")
      : `<tr><td colspan="4" class="empty">Henüz aktif savunma eylemi yok</td></tr>`;
  }
  function renderMesh(live) {
    const grid = $("#sensors-grid"); if (!grid) return;
    const sensors = live.sensors || [];
    const warn = $("#mesh-warn");
    if (warn) warn.innerHTML = (live.mesh_stats && live.mesh_stats.total_reports_rejected)
      ? `<div class="card pad-sm" style="border-color:rgba(245,166,35,.32);color:var(--warn);margin-bottom:1rem;font-size:.78rem;">⚠ ${live.mesh_stats.total_reports_rejected} sensör raporu kimlik doğrulamasından geçemedi ve reddedildi — başarısız doğrulama bir güvenlik sinyalidir.</div>` : "";
    grid.innerHTML = sensors.length
      ? sensors.map((s) => `<div class="layer-card ${s.online ? "ok" : ""}"><div class="lc-head"><span class="lc-dot"></span><span class="lc-name mono">${esc(s.sensor_id)}</span><span class="lc-phase">${esc(s.location || "—")}</span></div><div class="lc-detail">${s.total_events} olay raporladı<br>Son görülme: ${esc(s.last_seen)}<br>Sürüm: ${esc(s.version || "—")}</div></div>`).join("")
      : `<div class="empty">Sensör yok<span class="hint">python main.py mesh-demo --collector http://127.0.0.1:5001/mesh/ingest</span></div>`;
  }

  /* ============================================================
     THREATS (deep) render
     ============================================================ */
  function riskColor(band) { return { kritik: "var(--accent)", yuksek: "var(--high)", orta: "var(--med)", dusuk: "var(--low)", asgari: "var(--muted)" }[band] || "var(--muted)"; }
  function renderThreats(t) {
    if (!t) return;
    // SITREP
    const rep = t.report; const sr = $("#sitrep");
    if (sr && rep) {
      const tone = { "KRITIK": "critical", "YUKSEK": "high", "ORTA-YUKSEK": "high", "ORTA": "medium", "SAKIN": "calm" }[rep.posture] || "medium";
      const findings = (rep.findings || []).map((f) => `<div class="finding prio-${f.priority}"><div class="f-title"><span class="f-prio">P${f.priority}</span>${esc(f.title)}</div><div class="f-detail">${esc(f.detail)}</div></div>`).join("") || '<div class="feed-empty">Öncelikli bulgu yok</div>';
      const recs = (rep.recommendations || []).map((r) => `<li>${esc(r)}</li>`).join("");
      const snap = rep.stats_snapshot || {};
      const chips = [["Olay", snap.total_events], ["Alarm", snap.total_alerts], ["Kritik", snap.critical_alerts], ["Saldırgan", snap.unique_attackers], ["Kampanya", snap.campaigns]].map(([l, v]) => `<span class="chip"><b>${v || 0}</b> ${l}</span>`).join("");
      sr.innerHTML = `<div class="sitrep-head"><div class="posture-box ${tone}" style="min-width:150px;"><div class="pl">TEHDİT DÜZEYİ</div><div class="pv">${esc(rep.posture)}</div></div><div style="flex:1;"><p style="margin:0 0 .7rem;font-size:.88rem;line-height:1.55;">${esc(rep.posture_reason)}</p><div class="chips">${chips}</div><p style="margin:.6rem 0 0;font-size:.72rem;color:var(--muted);">Analiz motoru: <b>${esc((t.llm_status || {}).mode_tr || "-")}</b></p></div></div><div class="sitrep-body"><div><div class="mini-h" style="margin:0 0 .7rem;">Bulgular</div>${findings}</div><div><div class="mini-h" style="margin:0 0 .7rem;">Öneriler</div><ul class="rec-list">${recs}</ul></div></div>`;
    }
    // Risk table
    const tb = $("#threats-tbody");
    const profiles = t.profiles || [];
    if (tb) tb.innerHTML = profiles.length ? profiles.map((p) => {
      const r = p.risk || {}; const kc = p.kill_chain || {};
      return `<tr><td class="mono">${esc(p.source_ip)}${p.in_campaign ? ' <span class="badge badge-critical" style="font-size:.55rem;">KAMPANYA</span>' : ""}</td>
        <td><div class="risk-meter"><span class="risk-val" style="color:${riskColor(r.risk_band)}">${r.risk_score || 0}</span><div class="risk-track"><div class="risk-fill" style="width:${r.risk_score || 0}%;background:${riskColor(r.risk_band)}"></div></div></div></td>
        <td>${(p.attack_classes || []).slice(0, 2).map((c) => `<span class="badge badge-high" style="font-size:.58rem;">${esc(c)}</span>`).join(" ") || '<span class="muted">-</span>'}</td>
        <td class="mono">${p.event_count}</td><td class="mono">${esc(p.primary_tool || "-")}</td>
        <td class="mono">${(p.timing || {}).machine_like ? "makine" : "insan"}</td>
        <td><div class="kc-bar"><div class="kc-fill" style="width:${kc.progress_pct || 0}%"></div></div><div class="kc-label">${esc(kc.phase_tr || "-")}</div></td></tr>`;
    }).join("") : `<tr><td colspan="7" class="empty">Henüz saldırgan profili yok<span class="hint">python scripts/demo_global_attack.py</span></td></tr>`;

    // Attack graph (highest risk)
    const gc = $("#attack-graph-card");
    if (gc) {
      const top = profiles[0];
      if (top && top.attack_graph && top.attack_graph.node_count) {
        const g = top.attack_graph;
        const flow = (g.nodes || []).map((n) => `<span class="graph-node">${esc(n.phase_tr)} · ${n.event_count}</span>`).join('<span class="graph-arrow">→</span>');
        const pred = g.predicted_next_tr ? `<span class="graph-arrow">→</span><span class="graph-node predicted">${esc(g.predicted_next_tr)} (tahmin)</span>` : "";
        gc.innerHTML = `<div style="font-family:var(--font-mono);font-size:.8rem;margin-bottom:.3rem;">${esc(top.source_ip)} — risk ${(top.risk || {}).risk_score}</div><div class="graph-flow">${flow}${pred}</div><div class="storyline">${esc(g.storyline_tr)}</div>`;
      } else {
        gc.innerHTML = '<div class="empty">Saldırı grafiği için yeterli veri yok</div>';
      }
    }

    // Campaigns
    const cc = $("#campaigns");
    if (cc) cc.innerHTML = (t.campaigns || []).length ? t.campaigns.map((c) =>
      `<div class="campaign"><div class="c-head"><span class="c-id">${esc(c.campaign_id)}</span><span class="c-count">${c.member_count} IP</span><span class="muted" style="font-size:.72rem;">${esc((c.tools || []).join(", ") || "araç imzası yok")}</span></div><div class="c-ips">${(c.member_ips || []).map((ip) => `<span class="c-ip">${esc(ip)}</span>`).join("")}</div><p class="c-assess">${esc(c.assessment_tr)}</p></div>`).join("")
      : `<div class="card"><div class="empty">Korele kampanya tespit edilmedi — birden fazla IP aynı davranışsal parmak izini paylaştığında burada görünür.</div></div>`;
  }

  /* ============================================================
     RULES & INTEGRITY (deep) render
     ============================================================ */
  function renderRules(ri) {
    if (!ri) return;
    // Integrity
    const ic = $("#integrity-status");
    const integ = ri.integrity || {};
    if (ic) ic.innerHTML = `<div class="chain-status ${integ.chain_valid ? "valid" : "invalid"}"><div class="chain-icon">${integ.chain_valid ? "🔒" : "⚠️"}</div><div><div style="font-weight:700;font-size:.9rem;">${integ.chain_valid ? "Denetim zinciri SAĞLAM" : "KURCALAMA TESPİT EDİLDİ"}</div><div style="font-size:.78rem;color:var(--muted);margin-top:.2rem;">${esc(integ.assessment_tr || "")}</div><div class="chain-hash">Merkle kökü: ${esc(integ.merkle_root || "-")}</div></div></div>`;

    // Synth signatures
    const st = $("#synth-tbody");
    const synth = ri.synthesized_signatures || {};
    const cands = synth.candidates || [];
    if (st) st.innerHTML = cands.length ? cands.map((c) =>
      `<tr><td class="mono" style="color:var(--warn);">${esc(c.signature)}</td><td class="mono">%${Math.round(c.malicious_support * 100)}</td><td class="mono">%${Math.round(c.benign_support * 100)}</td><td class="mono">${c.discrimination_score}</td><td><span class="badge badge-info">aday</span></td></tr>`).join("")
      : `<tr><td colspan="5" class="empty">${esc(synth.note_tr || "Henüz imza üretilmedi")}</td></tr>`;

    // Rules
    const rt = $("#rules-tbody");
    if (rt) rt.innerHTML = (ri.rules || []).map((r) =>
      `<tr><td><b>${esc(r.name)}</b><br><span class="mono muted" style="font-size:.66rem;">${esc(r.id)}</span></td><td>${sevBadge(r.severity)}</td><td class="mono">${esc(r.condition)} / ${r.string_count} string</td><td class="mono" style="color:var(--purple);">${(r.attck || []).join(", ") || "-"}</td><td class="reasons">${esc(r.description)}</td></tr>`).join("");
  }

  /* ============================================================
     REVERSE — analiz laboratuvari
     ============================================================ */
  function setupAnalyzer() {
    const form = $("#analyzer-form"), input = $("#analyzer-input"), out = $("#analyzer-output");
    if (!form) return;
    $$(".sample-btn").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.s; form.dispatchEvent(new Event("submit")); }));
    form.addEventListener("submit", async (e) => {
      e.preventDefault(); const payload = input.value.trim(); if (!payload) return;
      out.innerHTML = '<div class="empty">Analiz ediliyor…</div>';
      let d; try { d = await (await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload }) })).json(); }
      catch (err) { out.innerHTML = '<div class="empty">Analiz başarısız</div>'; return; }
      if (d.error) { out.innerHTML = `<div class="empty">${esc(d.error)}</div>`; return; }
      renderAnalysis(out, d);
    });
  }
  function renderAnalysis(root, d) {
    const t = d.technical_analysis || {}, op = d.analyst_opinion || {}, deob = t.deobfuscation || {}, adv = t.advanced_decoding || {}, san = d.sanitization || {};
    const classes = (t.attack_classes || []).map((c) => { const hid = (t.hidden_attack_classes || []).includes(c); return `<span class="badge ${hid ? "badge-critical" : "badge-high"}">${esc(c)}${hid ? " (gizli)" : ""}</span>`; }).join(" ") || '<span class="badge badge-info">imza yok</span>';
    const steps = [...(deob.steps || []), ...(adv.steps || [])].map((s, i) => `<div class="deob-step"><span class="ds-method">${esc(s.method)}</span><span class="graph-arrow">→</span><code class="ds-after">${esc(s.after)}</code></div>`).join("");
    const chain = [deob.method_chain, adv.method_chain].filter((x) => x && x !== "yok" && x !== "duz metin").join(" → ");
    const techniques = (t.attck_techniques || []).map((x) => `<a class="attck-chip" href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.id)} <span>${esc(x.name)}</span></a>`).join("");
    const iocGroups = Object.entries(t.iocs || {}).filter(([, v]) => Array.isArray(v) && v.length).map(([k, v]) => `<div class="ioc-group"><span class="ig-key">${esc(k)}</span>${v.slice(0, 6).map((x) => `<code>${esc(x)}</code>`).join("")}</div>`).join("") || '<div class="feed-empty">IOC yok</div>';
    const kc = t.kill_chain || {};
    const entropyPct = Math.min(100, (t.entropy || 0) / 8 * 100);
    const poly = t.polyglot || {};
    const inj = san.injection_attempt ? `<div class="injection-alert"><b>⚠ PROMPT ENJEKSİYONU DENEMESİ</b><p>${esc(san.injection_assessment_tr)}</p><p style="border-top:1px solid rgba(255,59,69,.2);padding-top:.4rem;font-style:italic;">Datamarking (Spotlighting) savunması sayesinde talimat olarak değil <b>kanıt</b> olarak işlendi.</p></div>` : "";
    const polyBanner = poly.is_polyglot ? `<div class="injection-alert" style="border-color:rgba(245,166,35,.4);background:rgba(245,166,35,.08);"><b style="color:var(--warn);">⚠ POLYGLOT YÜK</b><p>${esc(poly.assessment_tr)}</p></div>` : "";
    root.innerHTML = `${inj}${polyBanner}<div class="an-grid">
      <div class="an-block"><h5>Tehdit Değerlendirmesi</h5><div class="verdict v-${esc(t.verdict || "temiz")}"><span class="v-score">${t.threat_score ?? 0}</span><span class="v-label">${esc(t.verdict || "temiz")}</span></div><div class="an-classes">${classes}</div><div class="kc-bar" style="height:8px;"><div class="kc-fill" style="width:${kc.progress_pct || 0}%"></div></div><div class="kc-label">Kill chain: ${esc(kc.phase_tr || "-")} (${kc.stage_index || 0}/${kc.total_stages || 7})</div><div style="margin-top:.6rem;"><span class="ig-key">Entropi: ${t.entropy || 0} bit</span><div class="entropy-bar"><div class="entropy-fill" style="width:${entropyPct}%"></div></div><div style="font-size:.68rem;color:var(--muted);">${esc(t.entropy_verdict || "")}</div></div></div>
      <div class="an-block"><h5>Kodlama Çözümü ${chain ? `<span class="badge badge-critical">${[...(deob.steps || []), ...(adv.steps || [])].length} adım</span>` : ""}</h5>${chain ? `<div class="deob-chain">${esc(chain)}</div>${steps}<div style="margin-top:.5rem;font-size:.72rem;"><span class="muted">Çözülmüş:</span> <code style="background:#060809;padding:.15rem .4rem;border-radius:4px;color:var(--ok);">${esc(adv.decoded || deob.decoded || "")}</code></div>` : '<div class="feed-empty">Yük kodlanmamış (düz metin).</div>'}</div>
      <div class="an-block"><h5>Analist Yorumu</h5><p style="font-size:.8rem;line-height:1.6;margin:0 0 .6rem;">${esc(op.summary)}</p><div style="font-size:.72rem;color:var(--muted);line-height:1.7;"><b style="color:var(--text);">Amaç:</b> ${esc(op.attacker_intent || "-")}<br><b style="color:var(--text);">Odak:</b> ${esc(op.recommended_focus || "-")}<br><b style="color:var(--text);">Kaynak:</b> ${esc(op._source || "-")}</div></div>
      <div class="an-block"><h5>MITRE ATT&CK</h5><div>${techniques || '<span class="muted">eşleşme yok</span>'}</div></div>
      <div class="an-block wide"><h5>Çıkarılan IOC'ler</h5>${iocGroups}</div></div>`;
  }

  /* ---------- Faz 21-30: Adaptif savunma gorunumu ---------- */
  function renderAdaptive(ad) {
    if (!ad || !ad.posture) return;

    // 1) Durus merdiveni
    const p = ad.posture;
    const ladder = $("#ad-posture-ladder");
    if (ladder) {
      ladder.innerHTML = (p.all_levels || []).map((l) =>
        `<div class="ap-step ${l.active ? "on" : ""} ${l.name === p.level ? "current" : ""}" style="--c:${l.color}">
           <span class="aps-name">${esc(l.name)}</span>
           <span class="aps-score">≥${l.enter_score}</span>
         </div>`).join('<span class="ap-arrow">→</span>');
    }
    const reason = $("#ad-posture-reason");
    if (reason) reason.innerHTML = `<b style="color:rgb(${p.color})">${esc(p.level)}</b> — ${esc(p.description_tr)} <span class="muted">(skor ${ad.posture_score ?? p.score})</span>`;
    const posBox = $("#ad-posture");
    if (posBox) posBox.style.setProperty("--pc", p.color);

    // 2) D3FEND & CSF kapsam
    const cov = ad.coverage || {};
    const covRoot = $("#ad-coverage");
    if (covRoot) {
      const d3 = cov.d3fend_covered || {};
      const d3rows = Object.keys(d3).map((t) => {
        const techs = d3[t] || [];
        const on = techs.length > 0;
        return `<div class="cov-row ${on ? "on" : ""}"><span class="cov-tac">${esc(t)}</span>
          <span class="cov-tech">${on ? techs.map((x) => esc(x)).join(", ") : "—"}</span></div>`;
      }).join("");
      const csf = cov.csf_covered || {};
      const csfChips = Object.keys(csf).map((f) =>
        `<span class="csf-chip ${(csf[f] || []).length ? "on" : ""}">${esc(f)} <b>${(csf[f] || []).length}</b></span>`).join("");
      covRoot.innerHTML = `
        <div class="cov-heads"><span>D3FEND <b>%${cov.d3fend_pct ?? 0}</b></span><span>NIST CSF 2.0 <b>%${cov.csf_pct ?? 0}</b></span></div>
        <div class="cov-list">${d3rows}</div>
        <div class="csf-row">${csfChips}</div>
        <p class="note" style="margin-top:.5rem;">${esc(cov.summary_tr || "")}</p>`;
    }

    // 3) Oyun-teorik ko-evrim
    const g = ad.coevolution || {}, st = ad.stackelberg || {};
    const gameRoot = $("#ad-game");
    if (gameRoot) {
      const hist = (g.history || []).map((h) =>
        `<div class="ge-round"><span class="ger-n">Tur ${h.round}</span>
          <span class="ger-cfg">Konuşlanan: <b>${esc(h.deployed_config || "-")}</b></span>
          <span class="ger-atk">Saldırgan: ${esc(h.attacker_action || "-")}</span>
          <span class="ger-u">fayda ${(h.defender_utility ?? 0).toFixed ? h.defender_utility.toFixed(2) : h.defender_utility}</span></div>`).join("");
      gameRoot.innerHTML = `
        <div class="ge-summary">${esc(st.reason || "")}</div>
        <div class="ge-verdict">Karışık (rastgele) strateji faydası <b>${(st.defender_utility ?? 0)}</b> · en iyi sabit strateji <b>${(st.best_pure_utility ?? 0)}</b> → ${st.is_pure ? "sabit yeterli" : "<b style='color:var(--ok)'>rastgeleleştirme kazanıyor (MTD)</b>"}</div>
        <div class="ge-hist">${hist}</div>
        <p class="note">${esc(g.summary_tr || "")}</p>`;
    }

    // 4) Aldatma agi topolojisi
    const grid = ad.deception_grid || {};
    const gridRoot = $("#ad-grid");
    if (gridRoot) {
      const byTier = grid.decoys_by_tier || {};
      const nodes = (grid.nodes || []);
      const chips = nodes.map((n) => {
        const cls = n.kind === "real" ? "gn-real" : n.kind === "breadcrumb" ? "gn-crumb" : "gn-decoy";
        return `<span class="grid-node ${cls}" title="${esc(n.label || "")}">${esc(n.id)}${n.tier ? `·T${n.tier}` : ""}</span>`;
      }).join("");
      gridRoot.innerHTML = `
        <div class="grid-legend"><span class="grid-node gn-real">gerçek çapa</span><span class="grid-node gn-crumb">kırıntı</span><span class="grid-node gn-decoy">sahte düğüm</span></div>
        <div class="grid-nodes">${chips}</div>
        <div class="grid-stats">
          <span>Kırıntı: <b>${grid.total_breadcrumbs ?? 0}</b></span>
          <span>Katman: <b>${Object.keys(byTier).length}</b></span>
          <span>Düğüm: <b>${grid.total_nodes ?? 0}</b></span>
        </div>
        <p class="note">${esc(grid.zero_false_positive_note || "Sahte düğüme dokunan her erişim neredeyse kesin saldırıdır — meşru kullanıcının orada işi yoktur.")}</p>`;
    }

    // 5) Kolektif bagisiklik
    const col = ad.collective || {};
    const colRoot = $("#ad-collective");
    if (colRoot) {
      const im = col.immunity || {}, pr = col.propagation || {};
      colRoot.innerHTML = `
        <div class="col-kpis">
          <div class="col-kpi"><span class="ck-v">${im.shared_indicators ?? 0}</span><span class="ck-l">paylaşılan gösterge</span></div>
          <div class="col-kpi"><span class="ck-v">${im.contributing_sensors ?? 0}/${im.total_sensors ?? 0}</span><span class="ck-l">katkı veren sensör</span></div>
          <div class="col-kpi"><span class="ck-v">%${im.coverage_pct ?? 0}</span><span class="ck-l">ağ kapsamı</span></div>
        </div>
        <p class="note">${esc(im.herd_immunity_note_tr || "")}</p>
        <p class="note" style="color:var(--ok);">${esc(pr.explanation_tr || pr.note_tr || "")}</p>`;
    }

    // 6) Dort sutunlu esleme tablosu
    const matrix = (cov.matrix || []);
    const mtable = $("#ad-matrix");
    if (mtable) {
      mtable.innerHTML = `<thead><tr><th>Faz</th><th>Ad</th><th>D3FEND</th><th>CSF 2.0</th><th>Karşıladığı ATT&CK</th></tr></thead>
        <tbody>${matrix.map((r) =>
          `<tr><td>${r.faz}</td><td>${esc(r.ad)}</td><td>${(r.d3fend || []).map((x) => esc(x)).join("<br>")}</td>
            <td>${(r.csf || []).map((x) => `<span class="csf-chip on">${esc(x)}</span>`).join(" ")}</td>
            <td class="muted">${esc(r.attack_counters || "-")}</td></tr>`).join("")}</tbody>`;
    }
  }

  /* ---------- Faz 39-40: Gerçek performans metrikleri ---------- */
  function metricTile(label, value, sub, tone) {
    return `<div class="metric-tile ${tone || ""}">
      <div class="mt-val">${value}</div>
      <div class="mt-label">${esc(label)}</div>
      ${sub ? `<div class="mt-sub">${esc(sub)}</div>` : ""}</div>`;
  }
  function pct(x) { return (x == null ? "—" : (x * 100).toFixed(1) + "%"); }

  function renderMetrics(m) {
    const root = $("#ov-metrics");
    if (!root) return;
    if (!m || !m.has_benchmark || !m.benchmark) {
      root.innerHTML = `<div class="metric-empty">
        <b>Henüz benchmark çalıştırılmadı.</b>
        <p>Gerçek Precision/Recall/F1/MTTD ölçümleri için binlerce etiketli senaryo çalıştır:</p>
        <code>python scripts/demo_benchmark.py</code>
        ${m && m.sensor_health ? `<p class="muted" style="margin-top:.6rem;">Filo sağlığı: %${m.sensor_health.fleet_health_pct} · canlı ${m.live_events_per_sec ?? 0} olay/sn</p>` : ""}
      </div>`;
      return;
    }
    const b = m.benchmark, full = b.full_system, sig = b.signature_only;
    const c = full.classification, t = full.timing, tp = full.throughput;
    const gradeTone = c.f1 >= 0.9 ? "ok" : c.f1 >= 0.75 ? "warn" : "bad";

    const tiles = [
      metricTile("Precision", pct(c.precision), `TP ${c.tp} / FP ${c.fp}`, "ok"),
      metricTile("Recall", pct(c.recall), `yakalanan / toplam kötü`, c.recall >= 0.9 ? "ok" : "warn"),
      metricTile("F1 Skoru", c.f1.toFixed(3), full.grade, gradeTone),
      metricTile("Yanlış Pozitif (FPR)", pct(c.false_positive_rate), `FP ${c.fp} / temiz ${c.fp + c.tn}`, c.false_positive_rate <= 0.02 ? "ok" : "warn"),
      metricTile("Yanlış Negatif (FNR)", pct(c.false_negative_rate), `kaçan ${c.fn}`, c.false_negative_rate <= 0.1 ? "ok" : "warn"),
      metricTile("Tespit Oranı", pct(c.detection_rate), `${c.tp}/${c.tp + c.fn}`, "ok"),
      metricTile("MTTD", t.mttd_ms.toFixed(2) + " ms", "ort. tespit süresi", "ok"),
      metricTile("P95 Gecikme", t.p95_detection_latency_ms.toFixed(2) + " ms", "95. yüzdelik", "ok"),
      metricTile("Throughput", Math.round(tp.events_per_sec).toLocaleString() + "/sn", "olay işleme hızı", "ok"),
    ].join("");

    // Katmanlı savunmanın getirisi: imza-only vs tam sistem F1
    const sf = sig.classification.f1, ff = full.classification.f1;
    const gain = (b.f1_gain != null ? b.f1_gain : (ff - sf));

    root.innerHTML = `
      <div class="metric-grid">${tiles}</div>
      <div class="metric-compare">
        <div class="mc-title">Katmanlı Savunmanın Ölçülmüş Getirisi <span class="muted">(${b.n_total.toLocaleString()} etiketli senaryo)</span></div>
        <div class="mc-bars">
          <div class="mc-row"><span class="mc-lbl">Sadece imza (WAF)</span>
            <div class="mc-track"><div class="mc-fill sig" style="width:${(sf * 100).toFixed(0)}%"></div></div>
            <span class="mc-num">F1 ${sf.toFixed(3)}</span></div>
          <div class="mc-row"><span class="mc-lbl">Tam katmanlı sistem</span>
            <div class="mc-track"><div class="mc-fill full" style="width:${(ff * 100).toFixed(0)}%"></div></div>
            <span class="mc-num">F1 ${ff.toFixed(3)}</span></div>
        </div>
        <div class="mc-gain">İmza-ötesi katmanların katkısı: <b>+${gain.toFixed(3)} F1</b> · yakalanamayan saldırı %${(sig.classification.false_negative_rate * 100).toFixed(1)} → %${(c.false_negative_rate * 100).toFixed(1)}</div>
      </div>
      <p class="note">${esc(full.summary_tr || "")}</p>`;
  }

  /* ============================================================
     POLL DONGULERI
     ============================================================ */
  let deepData = null;
  function ingestLive(live) {
    // Yeni kayitlari feed + radar + ses icin isle
    (live.alerts || []).forEach((a) => {
      if (!seen.alerts.has(a.id)) {
        if (!firstFeed) {
          Radar.pulse("waf");
          pushFeed(`<span class="t">${timePart(a.timestamp)}</span><span class="tag alert">ALARM</span>${esc(a.source_ip)} — ${esc(a.severity)} (skor ${esc(a.score)})`);
          if (a.severity === "critical" || a.severity === "high") { Sound.beep(); toast(`${a.severity === "critical" ? "KRİTİK" : "YÜKSEK"} ALARM`, `${esc(a.source_ip)} — skor ${esc(a.score)}`); }
        }
      }
    });
    (live.events || []).forEach((e) => { if (!seen.events.has(e.id)) { if (!firstFeed) { const nk = nodeForService(e.service); if (nk) Radar.pulse(nk); pushFeed(`<span class="t">${timePart(e.timestamp)}</span><span class="tag event">OLAY</span>${esc(e.source_ip)} → ${esc(e.service)} :: ${esc(e.event_type)}`); } } });
    (live.waf_events || []).forEach((w) => { if (!seen.waf.has(w.id)) { if (!firstFeed) { Radar.pulse("waf"); pushFeed(`<span class="t">${timePart(w.timestamp)}</span><span class="tag waf">WAF</span>${esc(w.source_ip)} ${esc(w.method)} ${esc(w.path)} — ${w.blocked ? "engellendi" : "geçti"}`); } } });
    (live.mtd_rotations || []).forEach((m) => { if (!seen.mtd.has(m.id)) { if (!firstFeed) { Radar.pulse("mtd"); pushFeed(`<span class="t">${timePart(m.timestamp)}</span><span class="tag mtd">MTD</span>${esc(m.component)}: ${esc(m.old_identity || "—")} → ${esc(m.new_identity)}`); } } });
    live.alerts && live.alerts.forEach((a) => seen.alerts.add(a.id));
    live.events && live.events.forEach((e) => seen.events.add(e.id));
    live.waf_events && live.waf_events.forEach((w) => seen.waf.add(w.id));
    live.mtd_rotations && live.mtd_rotations.forEach((m) => seen.mtd.add(m.id));
    firstFeed = false;
  }
  function ingestDefense(ad) {
    (ad.active_defense_log || []).forEach((d) => { if (!seen.def.has(d.id)) { if (!firstFeedDef) { Radar.pulse("defense"); pushFeed(`<span class="t">${timePart(d.timestamp)}</span><span class="tag defense">SAVUNMA</span>${esc(d.source_ip)} :: ${esc(d.technique)}`); } seen.def.add(d.id); } });
  }
  let firstFeedDef = true;

  async function fetchState() {
    let d; try { d = await (await fetch("/api/state", { cache: "no-store" })).json(); } catch (e) { return; }
    // Topbar
    const ov = d.overview || {};
    const pill = $("#posture-pill"); pill.className = "posture-pill " + (ov.posture_tone || "calm");
    $("#posture-text").textContent = ov.posture || "—";
    $("#clock").textContent = (d.now || "").replace(" UTC", "");
    // Badges
    updateBadge("badge-threats", (ov.kpis || {}).unique_attackers || 0);
    updateBadge("badge-soar", (ov.kpis || {}).awaiting_approval || 0);
    // Overview
    renderOverview(ov);
    // Command view (dome + map via command_center.js, layers here)
    if (window.ArachneCommandCenter) window.ArachneCommandCenter.update({ dome: d.dome, attack_map: d.attack_map });
    renderLayers(d.defense_layers);
    // SOAR view
    renderSoarView(d.active_defense || {}, d.live || {});
    // Mesh
    renderMesh(d.live || {});
    // Feed + radar
    ingestLive(d.live || {});
    ingestDefense(d.active_defense || {});
    firstFeedDef = false;
  }
  async function fetchDeep() {
    let d; try { d = await (await fetch("/api/deep", { cache: "no-store" })).json(); } catch (e) { return; }
    deepData = d;
    renderMetrics(d.metrics);   // Genel Bakış her zaman görünür - metrikleri hep güncelle
    if (currentView === "threats") renderThreats(d.threats);
    if (currentView === "rules") renderRules(d.rules_integrity);
    if (currentView === "adaptive") renderAdaptive(d.adaptive);
    if (d.adaptive && d.adaptive.posture) {
      const lvl = d.adaptive.posture.level;
      updateBadge("badge-adaptive", lvl && lvl !== "NORMAL" ? d.adaptive.posture.rank : 0);
    }
  }

  /* ---------- init ---------- */
  setupAnalyzer();
  fetchState();
  fetchDeep();
  setInterval(fetchState, STATE_POLL);
  setInterval(fetchDeep, DEEP_POLL);
})();
