/* Arachne Sentinel — canli panel istemci mantigi.
 * Hicbir sahte/uydurma veri uretmez: butun animasyonlar /api/live
 * uzerinden gelen GERCEK honeypot/WAF/tarama/MTD kayitlarina tepki verir.
 * Harici JS kutuphanesi kullanilmaz (sadece Canvas 2D + fetch). */
(function () {
  "use strict";

  const POLL_MS = 4000;
  const FEED_MAX_LINES = 70;

  /* ============================================================
   * 1) Ambient arka plan (tum sayfanin arkasinda, hafif, surekli)
   * ============================================================ */
  const AmbientField = (function () {
    const canvas = document.getElementById("bg-canvas");
    if (!canvas) return { flash() {} };
    const ctx = canvas.getContext("2d");
    let w, h, dpr;
    let dots = [];
    const flashes = [];

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.max(28, Math.floor((w * h) / 42000));
      dots = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.12,
        vy: (Math.random() - 0.5) * 0.12,
        r: Math.random() * 1.4 + 0.4,
      }));
    }
    window.addEventListener("resize", resize);
    resize();

    function flash(color) {
      flashes.push({
        x: Math.random() * w,
        y: Math.random() * h * 0.6,
        r: 0,
        maxR: 160 + Math.random() * 120,
        color: color || "34,211,238",
        alpha: 0.5,
      });
    }

    function tick() {
      ctx.clearRect(0, 0, w, h);

      // baglanti cizgileri (yakin noktalar arasinda, cok soluk)
      for (let i = 0; i < dots.length; i++) {
        const a = dots[i];
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > w) a.vx *= -1;
        if (a.y < 0 || a.y > h) a.vy *= -1;
        for (let j = i + 1; j < dots.length; j++) {
          const b = dots[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < 130 * 130) {
            const alpha = (1 - Math.sqrt(d2) / 130) * 0.06;
            ctx.strokeStyle = `rgba(120,150,180,${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      ctx.fillStyle = "rgba(140,170,200,0.28)";
      for (const d of dots) {
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // saldiri "flash" halkalari - gercek olay geldiginde tetiklenir
      for (let i = flashes.length - 1; i >= 0; i--) {
        const f = flashes[i];
        f.r += 3.2;
        f.alpha *= 0.965;
        ctx.strokeStyle = `rgba(${f.color},${Math.max(f.alpha, 0)})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(f.x, f.y, f.r, 0, Math.PI * 2);
        ctx.stroke();
        if (f.r > f.maxR || f.alpha < 0.02) flashes.splice(i, 1);
      }

      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
    return { flash };
  })();

  /* ============================================================
   * 2) Tehdit radari (Canli Tehdit Radari bolumu) - dugum grafi
   * ============================================================ */
  const ThreatRadar = (function () {
    const canvas = document.getElementById("radar-canvas");
    if (!canvas) return { pulse() {} };
    const ctx = canvas.getContext("2d");
    let w, h, dpr, cx, cy, radius;

    const NODES = [
      { key: "ssh", label: "SSH :2222", color: "34,211,238" },
      { key: "ftp", label: "FTP :2121", color: "34,211,238" },
      { key: "mysql", label: "MySQL :3307", color: "34,211,238" },
      { key: "http-admin", label: "HTTP-Admin :8081", color: "34,211,238" },
      { key: "waf", label: "WAF", color: "245,166,35" },
      { key: "scan", label: "Zafiyet Tarayici", color: "34,197,94" },
      { key: "mtd", label: "Hayalet Admin (MTD)", color: "45,212,191" },
    ];
    const pulses = []; // {nodeIdx, t}
    let rot = 0;

    function layout() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cx = w / 2; cy = h / 2;
      radius = Math.min(w, h) * 0.36;
    }
    window.addEventListener("resize", layout);

    function nodePos(i) {
      const angle = (i / NODES.length) * Math.PI * 2 + rot;
      return { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius, angle };
    }

    function pulse(key) {
      const idx = NODES.findIndex((n) => n.key === key);
      if (idx === -1) return;
      pulses.push({ idx, t: 0 });
    }

    function draw() {
      if (!w) layout();
      ctx.clearRect(0, 0, w, h);
      rot += 0.0009;

      // disk taramasi (radar supurme cizgisi)
      const sweepAngle = (Date.now() / 3200) % (Math.PI * 2);
      const grad = ctx.createConicGradient
        ? ctx.createConicGradient(sweepAngle, cx, cy)
        : null;
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.28, sweepAngle, sweepAngle + 0.9);
      ctx.lineTo(cx, cy);
      ctx.closePath();
      ctx.fillStyle = "rgba(34,211,238,0.045)";
      ctx.fill();
      ctx.restore();

      // dis cemberler
      ctx.strokeStyle = "rgba(120,150,180,0.12)";
      ctx.lineWidth = 1;
      [0.45, 0.75, 1.05].forEach((f) => {
        ctx.beginPath();
        ctx.arc(cx, cy, radius * f, 0, Math.PI * 2);
        ctx.stroke();
      });

      // baglanti cizgileri: dugum -> merkez
      NODES.forEach((n, i) => {
        const p = nodePos(i);
        ctx.strokeStyle = "rgba(120,150,180,0.16)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      });

      // merkez cekirdek
      ctx.beginPath();
      ctx.arc(cx, cy, 15, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(255,59,69,0.14)";
      ctx.fill();
      ctx.strokeStyle = "rgba(255,59,69,0.85)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.font = "700 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(233,237,245,0.85)";
      ctx.textAlign = "center";
      ctx.fillText("CORE", cx, cy + 3);

      // dugumler
      NODES.forEach((n, i) => {
        const p = nodePos(i);
        ctx.beginPath();
        ctx.arc(p.x, p.y, 6, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${n.color},0.9)`;
        ctx.shadowColor = `rgba(${n.color},0.9)`;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.font = "600 10px 'JetBrains Mono', monospace";
        ctx.fillStyle = "rgba(200,210,225,0.8)";
        const align = Math.cos(p.angle) > 0.15 ? "left" : Math.cos(p.angle) < -0.15 ? "right" : "center";
        ctx.textAlign = align;
        const off = align === "left" ? 10 : align === "right" ? -10 : 0;
        ctx.fillText(n.label, p.x + off, p.y + (Math.sin(p.angle) > 0 ? 16 : -10));
      });

      // aktif pulslar: dugumden merkeze dogru hareket eden parlak parcaciklar
      for (let i = pulses.length - 1; i >= 0; i--) {
        const pu = pulses[i];
        pu.t += 0.028;
        if (pu.t >= 1) { pulses.splice(i, 1); continue; }
        const node = NODES[pu.idx];
        const p = nodePos(pu.idx);
        const x = p.x + (cx - p.x) * pu.t;
        const y = p.y + (cy - p.y) * pu.t;

        // dugumde genisleyen halka
        ctx.beginPath();
        ctx.arc(p.x, p.y, 6 + pu.t * 22, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${node.color},${1 - pu.t})`;
        ctx.lineWidth = 2;
        ctx.stroke();

        // hareket eden parcacik
        ctx.beginPath();
        ctx.arc(x, y, 3.2, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${node.color},1)`;
        ctx.shadowColor = `rgba(${node.color},1)`;
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
    return { pulse };
  })();

  /* ============================================================
   * 2b) Alarm zaman cizelgesi (mini bar chart) - /api/live'daki
   *     GERCEK alerts_timeline dizisiyle her poll'da yeniden cizilir
   * ============================================================ */
  const Timeline = (function () {
    const canvas = document.getElementById("timeline-canvas");
    if (!canvas) return { update() {} };
    const ctx = canvas.getContext("2d");
    let current = [];

    function draw() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = canvas.clientWidth, h = canvas.clientHeight;
      if (!w || !h) return;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const n = current.length || 12;
      const max = Math.max(1, ...current);
      const padBottom = 16, padTop = 6;
      const barW = w / n;

      // yatay izgara
      ctx.strokeStyle = "rgba(120,150,180,0.1)";
      ctx.lineWidth = 1;
      [0.25, 0.5, 0.75].forEach((f) => {
        const y = padTop + (h - padTop - padBottom) * f;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      });

      current.forEach((count, i) => {
        const bh = count === 0 ? 0 : Math.max(3, ((h - padTop - padBottom) * count) / max);
        const x = i * barW + barW * 0.18;
        const bw = barW * 0.64;
        const y = h - padBottom - bh;
        const grad = ctx.createLinearGradient(0, y, 0, h - padBottom);
        grad.addColorStop(0, "rgba(255,59,69,0.9)");
        grad.addColorStop(1, "rgba(34,211,238,0.55)");
        ctx.fillStyle = count > 0 ? grad : "rgba(120,150,180,0.15)";
        const r = Math.min(4, bw / 2);
        ctx.beginPath();
        ctx.moveTo(x, y + r);
        ctx.arc(x + r, y + r, r, Math.PI, 1.5 * Math.PI);
        ctx.arc(x + bw - r, y + r, r, 1.5 * Math.PI, 0);
        ctx.lineTo(x + bw, h - padBottom);
        ctx.lineTo(x, h - padBottom);
        ctx.closePath();
        ctx.fill();
      });

      ctx.font = "500 9px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(139,147,167,0.8)";
      ctx.textAlign = "left";
      ctx.fillText("60 dk önce", 2, h - 3);
      ctx.textAlign = "right";
      ctx.fillText("şimdi", w - 2, h - 3);
    }

    window.addEventListener("resize", draw);
    function update(counts) { current = counts || []; draw(); }
    return { update };
  })();

  /* ============================================================
   * 2c) Ses uyarisi + toast bildirimi (kritik/yuksek alarmlar icin)
   * ============================================================ */
  const AlertSignal = (function () {
    const btn = document.getElementById("sound-toggle");
    const toastRoot = document.getElementById("toast-root");
    let audioCtx = null;
    let enabled = false;

    if (btn) {
      btn.addEventListener("click", () => {
        enabled = !enabled;
        btn.classList.toggle("on", enabled);
        btn.setAttribute("aria-pressed", String(enabled));
        btn.textContent = enabled ? "🔊 Ses" : "🔇 Ses";
        if (enabled && !audioCtx) {
          try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
          catch (e) { /* Web Audio desteklenmiyor - sessizce yoksay */ }
        }
        if (audioCtx && audioCtx.state === "suspended") audioCtx.resume();
      });
    }

    function beep() {
      if (!enabled || !audioCtx) return;
      const t0 = audioCtx.currentTime;
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = "square";
      osc.frequency.setValueAtTime(880, t0);
      osc.frequency.exponentialRampToValueAtTime(440, t0 + 0.18);
      gain.gain.setValueAtTime(0.0001, t0);
      gain.gain.exponentialRampToValueAtTime(0.06, t0 + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.22);
      osc.connect(gain).connect(audioCtx.destination);
      osc.start(t0); osc.stop(t0 + 0.24);
    }

    function toast(title, body) {
      if (!toastRoot) return;
      const el = document.createElement("div");
      el.className = "toast";
      el.innerHTML = `<div class="tt">${title}</div><div class="tb">${body}</div>`;
      toastRoot.appendChild(el);
      setTimeout(() => el.remove(), 5000);
    }

    function notify(title, body) { beep(); toast(title, body); }
    return { notify };
  })();

  /* ============================================================
   * 3) Sayac animasyonu (stat kartlari)
   * ============================================================ */
  function animateCount(el, to) {
    if (!el) return;
    const from = parseInt(el.textContent.replace(/[^\d-]/g, ""), 10) || 0;
    if (from === to) return;
    const dur = 650;
    const start = performance.now();
    el.classList.add("bump");
    function step(now) {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(step);
      else { el.textContent = to; setTimeout(() => el.classList.remove("bump"), 400); }
    }
    requestAnimationFrame(step);
  }

  /* ============================================================
   * 4) Canli akis (terminal paneli)
   * ============================================================ */
  const feedBody = document.getElementById("live-feed-body");
  function pushFeedLine(html) {
    if (!feedBody) return;
    const empty = feedBody.querySelector(".feed-empty");
    if (empty) empty.remove();
    const line = document.createElement("div");
    line.className = "feed-line";
    line.innerHTML = html;
    feedBody.prepend(line);
    while (feedBody.children.length > FEED_MAX_LINES) {
      feedBody.removeChild(feedBody.lastChild);
    }
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  }
  function timePart(ts) {
    if (!ts) return "";
    const parts = String(ts).split(" ");
    return esc(parts[1] || ts);
  }

  function renderTopIps(topIps) {
    const root = document.getElementById("top-ips-list");
    if (!root) return;
    if (!topIps.length) {
      root.innerHTML = `<p class="feed-empty">Henüz kaynak IP verisi yok.</p>`;
      return;
    }
    const max = topIps[0][1] || 1;
    root.innerHTML = topIps.map(([ip, count]) => `
      <div class="ip-row">
        <span class="mono ip-addr">${esc(ip)}</span>
        <div class="ip-bar-track"><div class="ip-bar-fill" style="width:${(count / max) * 100}%"></div></div>
        <span class="mono ip-count">${esc(count)}</span>
      </div>`).join("");
  }

  /* ============================================================
   * 5) Tablo yeniden cizimi (her poll'da tam yenileme, id ile "yeni" tespiti)
   * ============================================================ */
  function renderRows(tbodyId, items, colspan, rowFn, seenIds) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!items || !items.length) {
      tbody.innerHTML = tbody.dataset.emptyHtml || `<tr class="empty-row"><td colspan="${colspan}">Henuz veri yok</td></tr>`;
      return;
    }
    tbody.innerHTML = items.map((it) => {
      const isNew = seenIds && seenIds.has && !seenIds.has(it.id);
      return rowFn(it, isNew);
    }).join("");
  }

  /* ============================================================
   * 6) Canli veri dongusu
   * ============================================================ */
  const state = {
    firstLoad: true,
    seen: { alerts: new Set(), events: new Set(), waf: new Set(), mtd: new Set() },
  };

  function nodeKeyForService(service) {
    if (!service) return null;
    const s = String(service).toLowerCase();
    if (s.includes("ssh")) return "ssh";
    if (s.includes("ftp")) return "ftp";
    if (s.includes("mysql")) return "mysql";
    if (s.includes("admin")) return "http-admin";
    return null;
  }
  function nodeKeyForComponent(component) {
    if (!component) return null;
    const c = String(component).toLowerCase();
    if (c.startsWith("banner:")) return nodeKeyForService(c.split(":")[1]) || "http-admin";
    if (c.startsWith("port:")) return "mtd";
    if (c.startsWith("dns:")) return "mtd";
    return "mtd";
  }

  async function pollLive() {
    let data;
    try {
      const res = await fetch("/api/live", { cache: "no-store" });
      data = await res.json();
    } catch (e) {
      return; // sessizce atla - dashboard zaten SSR ile ilk yuklemede dolu geldi
    }

    // --- stat kartlari ---
    animateCount(document.getElementById("n-events"), data.honeypot_stats.total_events);
    animateCount(document.getElementById("n-alerts"), data.honeypot_stats.total_alerts);
    animateCount(document.getElementById("n-scan"), data.scan_findings.length);
    animateCount(document.getElementById("n-mtd-total"), data.mtd_stats.total_rotations);
    const wafEl = document.getElementById("n-waf");
    if (wafEl) wafEl.textContent = `${data.waf_stats.blocked_requests}/${data.waf_stats.total_requests}`;
    const wafPctBlocked = document.getElementById("waf-blocked-seg");
    const wafPctPassed = document.getElementById("waf-passed-seg");
    const wafPctLabel = document.getElementById("waf-pct-label");
    const totalWaf = data.waf_stats.total_requests || 0;
    const pct = totalWaf ? Math.round((data.waf_stats.blocked_requests / totalWaf) * 100) : 0;
    if (wafPctBlocked) wafPctBlocked.style.width = pct + "%";
    if (wafPctPassed) wafPctPassed.style.width = (100 - pct) + "%";
    if (wafPctLabel) wafPctLabel.textContent = `%${pct} istek engellendi`;
    const ghostEl = document.getElementById("n-ghost-port");
    if (ghostEl) ghostEl.textContent = data.ghost_admin_port ? (":" + data.ghost_admin_port) : "baslatilmadi";

    // --- saldirgan istihbarati: zaman cizelgesi + top IP listesi ---
    Timeline.update(data.alerts_timeline);
    renderTopIps(data.honeypot_stats.top_ips || []);

    // --- yeni kayitlari tespit et + radar/feed/flash tetikle ---
    if (!state.firstLoad) {
      for (const a of data.alerts) {
        if (!state.seen.alerts.has(a.id)) {
          AmbientField.flash("255,59,69");
          ThreatRadar.pulse("waf"); // genel bir tehdit isareti
          pushFeedLine(
            `<span class="t">${timePart(a.ts || a.timestamp)}</span>` +
            `<span class="tag alert">ALARM</span>${esc(a.source_ip)} — ${esc(a.severity)} (skor ${esc(a.score)})`
          );
          if (a.severity === "critical" || a.severity === "high") {
            AlertSignal.notify(
              `${a.severity === "critical" ? "KRİTİK" : "YÜKSEK"} ALARM`,
              `${esc(a.source_ip)} — skor ${esc(a.score)}`
            );
          }
        }
      }
      for (const e of data.events) {
        if (!state.seen.events.has(e.id)) {
          const nk = nodeKeyForService(e.service);
          if (nk) ThreatRadar.pulse(nk);
          AmbientField.flash("34,211,238");
          pushFeedLine(
            `<span class="t">${timePart(e.timestamp)}</span>` +
            `<span class="tag event">OLAY</span>${esc(e.source_ip)} → ${esc(e.service)} :: ${esc(e.event_type)}`
          );
        }
      }
      for (const w of data.waf_events) {
        if (!state.seen.waf.has(w.id)) {
          ThreatRadar.pulse("waf");
          AmbientField.flash("245,166,35");
          pushFeedLine(
            `<span class="t">${timePart(w.timestamp)}</span>` +
            `<span class="tag waf">WAF</span>${esc(w.source_ip)} ${esc(w.method)} ${esc(w.path)} — ` +
            (w.blocked ? "engellendi" : "gecti")
          );
        }
      }
      for (const m of data.mtd_rotations) {
        if (!state.seen.mtd.has(m.id)) {
          ThreatRadar.pulse(nodeKeyForComponent(m.component));
          AmbientField.flash("45,212,191");
          pushFeedLine(
            `<span class="t">${timePart(m.timestamp)}</span>` +
            `<span class="tag mtd">MTD</span>${esc(m.component)}: ${esc(m.old_identity || "—")} → ${esc(m.new_identity)}`
          );
        }
      }
    }
    data.alerts.forEach((a) => state.seen.alerts.add(a.id));
    data.events.forEach((e) => state.seen.events.add(e.id));
    data.waf_events.forEach((w) => state.seen.waf.add(w.id));
    data.mtd_rotations.forEach((m) => state.seen.mtd.add(m.id));

    // --- tablolari yenile ---
    renderRows("tbl-alerts", data.alerts, 5, (a) => {
      const cls = !state.firstLoad && !state._prevAlertIds ? "" : "";
      return `<tr class="${a._isNew ? "row-new" : ""}"><td class="mono muted">${esc(a.timestamp)}</td>` +
        `<td class="mono">${esc(a.source_ip)}</td><td><span class="badge badge-${esc(a.severity)}">${esc(a.severity)}</span></td>` +
        `<td class="mono">${esc(a.score)}</td><td class="reasons">${esc(a.reasons)}</td></tr>`;
    });
    renderRows("tbl-events", data.events.slice(0, 50), 5, (e) =>
      `<tr><td class="mono muted">${esc(e.timestamp)}</td><td class="mono">${esc(e.source_ip)}</td>` +
      `<td>${esc(e.service)}</td><td class="mono">${esc(e.event_type)}</td>` +
      `<td class="mono muted">${esc((e.payload || "").slice(0, 80))}</td></tr>`
    );
    renderRows("tbl-waf", data.waf_events, 7, (w) =>
      `<tr><td class="mono muted">${esc(w.timestamp)}</td><td class="mono">${esc(w.source_ip)}</td>` +
      `<td class="mono">${esc(w.method)}</td><td class="mono">${esc(w.path)}</td><td class="mono">${esc(w.score)}</td>` +
      `<td>${w.blocked ? '<span class="badge badge-blocked">Engellendi</span>' : '<span class="badge badge-passed">Gecti</span>'}</td>` +
      `<td class="reasons">${esc(w.reasons)}</td></tr>`
    );
    renderRows("tbl-scan", data.scan_findings, 6, (f) =>
      `<tr><td class="mono muted">${esc(f.timestamp)}</td><td class="mono">${esc(f.target)}</td>` +
      `<td class="mono">${esc(f.port)}</td><td>${esc(f.service_guess)}</td>` +
      `<td><span class="badge badge-${esc(f.severity)}">${esc(f.severity)}</span></td><td class="reasons">${esc(f.finding)}</td></tr>`
    );
    renderRows("tbl-mtd", data.mtd_rotations, 5, (r) =>
      `<tr><td class="mono muted">${esc(r.timestamp)}</td><td class="mono">${esc(r.component)}</td>` +
      `<td class="mono muted">${esc(r.old_identity || "—")}</td><td class="mono">${esc(r.new_identity)}</td>` +
      `<td class="reasons">${esc(r.reason)}</td></tr>`
    );

    state.firstLoad = false;
  }

  pollLive();
  setInterval(pollLive, POLL_MS);

  /* ============================================================
   * 7) Scroll-reveal
   * ============================================================ */
  const io = new IntersectionObserver(
    (entries) => entries.forEach((en) => { if (en.isIntersecting) en.target.classList.add("in-view"); }),
    { threshold: 0.12 }
  );
  document.querySelectorAll(".reveal").forEach((el) => io.observe(el));
})();
