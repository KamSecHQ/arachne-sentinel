/* Arachne Sentinel — Faz 5/6/8 arayuzu
 *
 *   - AI analist durum raporu (SITREP)
 *   - Saldirgan profilleri ve korele kampanyalar
 *   - Canli yuk analiz laboratuvari (tersine muhendislik)
 *
 * /api/intel daha pahali hesaplamalar icerdigi icin canli dongoden
 * (4sn) daha seyrek (20sn) cagrilir.
 */
(function () {
  "use strict";

  const INTEL_POLL_MS = 20000;

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
      }[c]));
  }

  /* ---------- AI durum raporu ---------- */
  function renderSituationReport(data) {
    const root = document.getElementById("sitrep");
    if (!root) return;
    const report = data && data.report;
    if (!report) {
      root.innerHTML = '<p class="feed-empty">Durum raporu henuz uretilemedi.</p>';
      return;
    }

    const postureClass = {
      "KRITIK": "p-critical", "YUKSEK": "p-high",
      "ORTA-YUKSEK": "p-high", "ORTA": "p-medium", "SAKIN": "p-calm",
    }[report.posture] || "p-medium";

    const findings = (report.findings || []).map((f) => `
      <div class="finding prio-${f.priority}">
        <div class="f-title"><span class="f-prio">P${f.priority}</span>${esc(f.title)}</div>
        <div class="f-detail">${esc(f.detail)}</div>
      </div>`).join("") || '<p class="feed-empty">Oncelikli bulgu yok.</p>';

    const recs = (report.recommendations || [])
      .map((r) => `<li>${esc(r)}</li>`).join("");

    const snap = report.stats_snapshot || {};
    const chips = [
      ["Olay", snap.total_events], ["Alarm", snap.total_alerts],
      ["Kritik", snap.critical_alerts], ["Saldirgan", snap.unique_attackers],
      ["Kampanya", snap.campaigns], ["MTD rotasyonu", snap.mtd_rotations],
      ["SOAR eylemi", snap.soar_actions],
    ].map(([label, value]) =>
      `<span class="chip"><b>${value ?? 0}</b> ${esc(label)}</span>`).join("");

    root.innerHTML = `
      <div class="sitrep-head">
        <div class="posture ${postureClass}">
          <div class="p-label">TEHDIT DUZEYI</div>
          <div class="p-value">${esc(report.posture)}</div>
        </div>
        <div class="sitrep-summary">
          <p class="s-reason">${esc(report.posture_reason)}</p>
          <div class="chips">${chips}</div>
          <p class="s-engine">Analiz motoru:
            <b>${esc((data.llm_status && data.llm_status.mode_tr) || "-")}</b></p>
        </div>
      </div>
      <div class="sitrep-body">
        <div class="sb-col">
          <h4 class="mini-h">Bulgular</h4>
          ${findings}
        </div>
        <div class="sb-col">
          <h4 class="mini-h">Oneriler</h4>
          <ul class="rec-list">${recs}</ul>
        </div>
      </div>`;
  }

  /* ---------- Saldirgan profilleri ---------- */
  function renderProfiles(profiles) {
    const tbody = document.getElementById("tbl-profiles");
    if (!tbody) return;
    if (!profiles || !profiles.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="8">Henuz saldirgan profili yok
        <span class="hint">python scripts/demo_attack.py</span></td></tr>`;
      return;
    }
    tbody.innerHTML = profiles.map((p) => {
      const kc = p.kill_chain || {};
      const timing = p.timing || {};
      return `<tr>
        <td class="mono">${esc(p.source_ip)}</td>
        <td><span class="badge badge-${threatBadge(p.threat_class)}">${esc(p.threat_class || "-")}</span></td>
        <td class="mono">${p.event_count || 0}</td>
        <td class="mono">${p.alert_count || 0}</td>
        <td class="mono">${esc(p.primary_tool || "-")}</td>
        <td class="mono">${timing.machine_like ? "makine" : "insan"}</td>
        <td>
          <div class="kc-bar" title="${esc(kc.phase_tr || "")}">
            <div class="kc-fill" style="width:${kc.progress_pct || 0}%"></div>
          </div>
          <span class="kc-label">${esc(kc.phase_tr || "-")}</span>
        </td>
        <td class="mono muted" title="Davranissal parmak izi">${esc((p.signature || "").slice(0, 8))}</td>
      </tr>`;
    }).join("");
  }

  function threatBadge(threatClass) {
    switch (threatClass) {
      case "hedefli-saldirgan": return "critical";
      case "aktif-tehdit": return "high";
      case "arac-kullanan": return "medium";
      case "otomatik-tarayici": return "medium";
      case "dusuk-etkilesim": return "low";
      default: return "info";
    }
  }

  /* ---------- Kampanya korelasyonu ---------- */
  function renderCampaigns(campaigns) {
    const root = document.getElementById("campaigns");
    if (!root) return;
    if (!campaigns || !campaigns.length) {
      root.innerHTML = `<p class="feed-empty">Korele kampanya tespit edilmedi &mdash;
        birden fazla IP ayni davranissal parmak izini paylastiginda burada gorunur.</p>`;
      return;
    }
    root.innerHTML = campaigns.map((c) => `
      <div class="campaign">
        <div class="c-head">
          <span class="c-id mono">${esc(c.campaign_id)}</span>
          <span class="c-count">${c.member_count} IP</span>
          <span class="c-tools">${esc((c.tools || []).join(", ") || "arac imzasi yok")}</span>
        </div>
        <div class="c-ips">${(c.member_ips || [])
          .map((ip) => `<span class="c-ip mono">${esc(ip)}</span>`).join("")}</div>
        <p class="c-assess">${esc(c.assessment_tr)}</p>
        <div class="c-links">${(c.evidence_links || []).slice(0, 4).map((l) =>
          `<span class="c-link mono">${esc(l.ip_a)} ↔ ${esc(l.ip_b)}
           <b>${(l.similarity * 100).toFixed(0)}%</b></span>`).join("")}</div>
      </div>`).join("");
  }

  /* ---------- Canli yuk analiz laboratuvari ---------- */
  function setupAnalyzer() {
    const form = document.getElementById("analyzer-form");
    const input = document.getElementById("analyzer-input");
    const output = document.getElementById("analyzer-output");
    if (!form || !input || !output) return;

    document.querySelectorAll("[data-sample]").forEach((btn) => {
      btn.addEventListener("click", () => {
        input.value = btn.getAttribute("data-sample");
        form.dispatchEvent(new Event("submit"));
      });
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = input.value.trim();
      if (!payload) return;

      output.innerHTML = '<p class="feed-empty">Analiz ediliyor...</p>';
      let data;
      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload }),
        });
        data = await response.json();
      } catch (e) {
        output.innerHTML = '<p class="feed-empty">Analiz basarisiz oldu.</p>';
        return;
      }
      if (data.error) {
        output.innerHTML = `<p class="feed-empty">${esc(data.error)}</p>`;
        return;
      }
      renderAnalysis(output, data);
    });
  }

  function renderAnalysis(root, data) {
    const tech = data.technical_analysis || {};
    const opinion = data.analyst_opinion || {};
    const deob = tech.deobfuscation || {};
    const san = data.sanitization || {};

    const steps = (deob.steps || []).map((s, i) => `
      <div class="deob-step">
        <span class="ds-n">${i + 1}</span>
        <span class="ds-method mono">${esc(s.method)}</span>
        <span class="ds-arrow">→</span>
        <code class="ds-after">${esc(s.after)}</code>
      </div>`).join("");

    const classes = (tech.attack_classes || []).map((c) => {
      const hidden = (tech.hidden_attack_classes || []).includes(c);
      return `<span class="badge ${hidden ? "badge-critical" : "badge-high"}">
        ${esc(c)}${hidden ? " (gizlenmisti)" : ""}</span>`;
    }).join(" ") || '<span class="badge badge-info">imza eslesmedi</span>';

    const techniques = (tech.attck_techniques || []).map((t) =>
      `<a class="attck-chip" href="${esc(t.url)}" target="_blank" rel="noopener">
        ${esc(t.id)} <span>${esc(t.name)}</span></a>`).join("");

    const tools = (tech.tools || []).map((t) => `
      <div class="tool-row">
        <b>${esc(t.tool)}</b> <span class="muted">${esc(t.category)}</span>
        <span class="conf">%${t.confidence}</span>
        <div class="tool-ev">${(t.evidence || []).map(esc).join(" · ")}</div>
      </div>`).join("");

    const iocGroups = Object.entries(tech.iocs || {})
      .filter(([, v]) => Array.isArray(v) && v.length)
      .map(([key, values]) => `
        <div class="ioc-group">
          <span class="ig-key mono">${esc(key)}</span>
          ${values.slice(0, 6).map((v) => `<code>${esc(v)}</code>`).join("")}
        </div>`).join("") || '<p class="feed-empty">IOC bulunamadi.</p>';

    const kc = tech.kill_chain || {};
    const injectionBanner = san.injection_attempt ? `
      <div class="injection-alert">
        <b>⚠ PROMPT ENJEKSIYONU DENEMESI TESPIT EDILDI</b>
        <p>${esc(san.injection_assessment_tr)}</p>
        <ul>${(san.injection_indicators || []).map((i) =>
          `<li>${esc(i.description)}: <code>${esc(i.matched_text)}</code></li>`).join("")}</ul>
        <p class="ia-note">Bu yuk AI analiz katmanini manipule etmeye calisiyordu.
        Datamarking (Spotlighting) savunmasi sayesinde talimat olarak degil,
        <b>kanit</b> olarak islendi.</p>
      </div>` : "";

    root.innerHTML = `
      ${injectionBanner}
      <div class="analysis-grid">
        <div class="an-block">
          <h5>Tehdit Degerlendirmesi</h5>
          <div class="verdict v-${esc(tech.verdict || "temiz")}">
            <span class="v-score">${tech.threat_score ?? 0}</span>
            <span class="v-label">${esc(tech.verdict || "temiz")}</span>
          </div>
          <div class="an-classes">${classes}</div>
          <div class="kc-bar big" title="${esc(kc.phase_tr || "")}">
            <div class="kc-fill" style="width:${kc.progress_pct || 0}%"></div>
          </div>
          <div class="kc-label">Kill chain: ${esc(kc.phase_tr || "-")}
            (${kc.stage_index || 0}/${kc.total_stages || 7})</div>
        </div>

        <div class="an-block">
          <h5>Kodlama Cozumu ${deob.was_obfuscated
            ? `<span class="badge badge-critical">${deob.layers} katman</span>` : ""}</h5>
          ${deob.was_obfuscated
            ? `<div class="deob-chain mono">${esc(deob.method_chain)}</div>${steps}
               <div class="deob-final"><span>Cozulmus:</span>
                 <code>${esc(deob.decoded)}</code></div>`
            : '<p class="feed-empty">Yuk kodlanmamis (duz metin).</p>'}
        </div>

        <div class="an-block">
          <h5>Analist Yorumu</h5>
          <p class="an-summary">${esc(opinion.summary)}</p>
          <div class="an-meta">
            <span><b>Amac:</b> ${esc(opinion.attacker_intent || "-")}</span>
            <span><b>Odak:</b> ${esc(opinion.recommended_focus || "-")}</span>
            <span><b>Guven:</b> ${esc(opinion.confidence || "-")}</span>
            <span><b>Kaynak:</b> ${esc(opinion._source || "-")}</span>
          </div>
        </div>

        <div class="an-block">
          <h5>MITRE ATT&CK Eslemesi</h5>
          <div class="attck-chips">${techniques || '<span class="muted">eslesme yok</span>'}</div>
          ${tools ? `<h5 style="margin-top:1rem">Arac Parmak Izi</h5>${tools}` : ""}
        </div>

        <div class="an-block wide">
          <h5>Cikarilan IOC'ler</h5>
          ${iocGroups}
        </div>
      </div>`;
  }

  /* ---------- Poll dongusu ---------- */
  async function pollIntel() {
    try {
      const response = await fetch("/api/intel", { cache: "no-store" });
      const data = await response.json();
      renderSituationReport(data);
      renderProfiles(data.profiles);
      renderCampaigns(data.campaigns);
    } catch (e) {
      /* sessizce atla - bir sonraki turda tekrar denenir */
    }
  }

  setupAnalyzer();
  pollIntel();
  setInterval(pollIntel, INTEL_POLL_MS);
})();
