/* ============================================================
   ARACHNE SENTINEL — Faz 63: Profesyonel Kritik Olay Rayı
   ------------------------------------------------------------
   Gerçek bir SOC duvarı gibi, sağ kenarda "KRİTİK ALARM" kartları.
   Kaynak: /api/state → live.alerts (alanlar: id, timestamp, source_ip,
   severity, score, reasons). SADECE gerçek alarmlar; critical/high
   olanlar süzülür. Hiç yoksa sakin durum gösterilir.
   Bağımsız çalışır (kendi 5sn fetch döngüsü). Hiçbir mevcut
   ID/sınıfı değiştirmez — yalnızca kendi #incident-rail'ini yönetir.
   ============================================================ */
(function () {
  "use strict";

  var POLL_MS = 5000;
  var MAX_CARDS = 6;
  var STORE_KEY = "arachne.incidentRail.collapsed";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  /* "YYYY-MM-DD HH:MM:SS" (UTC) → Date */
  function parseTs(ts) {
    if (!ts) return null;
    var s = String(ts).trim().replace(" UTC", "").replace(" ", "T");
    if (!/[zZ]|[+\-]\d\d:?\d\d$/.test(s)) s += "Z";
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  /* Canlı, göreli zaman damgası (Türkçe) */
  function relTime(ts) {
    var d = parseTs(ts);
    if (!d) return String(ts || "").split(" ")[1] || "—";
    var sec = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    if (sec < 10) return "az önce";
    if (sec < 60) return sec + " sn önce";
    var min = Math.floor(sec / 60);
    if (min < 60) return min + " dk önce";
    var hr = Math.floor(min / 60);
    if (hr < 24) return hr + " sa önce";
    return Math.floor(hr / 24) + " gün önce";
  }

  function clockPart(ts) {
    var p = String(ts || "").split(" ");
    return p[1] || "";
  }

  /* ---- rail iskeleti (markup app.html'de var; yoksa oluştur) ---- */
  var rail = document.getElementById("incident-rail");
  if (!rail) {
    rail = document.createElement("aside");
    rail.id = "incident-rail";
    document.body.appendChild(rail);
  }
  rail.innerHTML =
    '<div class="ir-head">' +
      '<span class="ir-title"><span class="ir-beacon"></span>KRİTİK ALARM</span>' +
      '<span class="ir-count" id="ir-count">0</span>' +
      '<button class="ir-toggle" id="ir-toggle" title="Rayı gizle/göster" aria-label="Kritik alarm rayını aç/kapat">›</button>' +
    '</div>' +
    '<div class="ir-list" id="ir-list"></div>' +
    '<div class="ir-foot" id="ir-foot">canlı · /api/state</div>';

  var listEl = rail.querySelector("#ir-list");
  var countEl = rail.querySelector("#ir-count");
  var toggleEl = rail.querySelector("#ir-toggle");

  /* Daralt/genişlet (localStorage'da hatırla) */
  function applyCollapsed(c) {
    rail.classList.toggle("collapsed", !!c);
    if (toggleEl) toggleEl.textContent = c ? "‹" : "›";
  }
  var collapsed = false;
  try { collapsed = localStorage.getItem(STORE_KEY) === "1"; } catch (e) {}
  applyCollapsed(collapsed);
  if (toggleEl) {
    toggleEl.addEventListener("click", function () {
      collapsed = !collapsed;
      applyCollapsed(collapsed);
      try { localStorage.setItem(STORE_KEY, collapsed ? "1" : "0"); } catch (e) {}
    });
  }

  var seen = {};        // hangi alarm id'leri daha önce çizildi (enter animasyonu)
  var lastKey = "";     // gereksiz yeniden çizimi engelle

  function sevRank(s) {
    s = String(s || "").toLowerCase();
    if (s === "critical" || s === "kritik") return 2;
    if (s === "high" || s === "yüksek" || s === "yuksek") return 1;
    return 0;
  }
  function isCriticalHigh(s) { return sevRank(s) >= 1; }
  function sevLabel(s) { return sevRank(s) === 2 ? "KRİTİK" : "YÜKSEK"; }
  function sevClass(s) { return sevRank(s) === 2 ? "critical" : "high"; }

  function render(alerts) {
    var crit = (alerts || [])
      .filter(function (a) { return a && isCriticalHigh(a.severity); })
      .sort(function (a, b) {
        var r = sevRank(b.severity) - sevRank(a.severity);
        if (r !== 0) return r;
        // en yeni üstte: id (varsa) yoksa timestamp
        if (a.id != null && b.id != null) return b.id - a.id;
        return String(b.timestamp || "").localeCompare(String(a.timestamp || ""));
      })
      .slice(0, MAX_CARDS);

    countEl.textContent = crit.length ? String(crit.length) : "0";
    countEl.classList.toggle("zero", crit.length === 0);

    if (!crit.length) {
      lastKey = "calm";
      listEl.innerHTML =
        '<div class="ir-calm">' +
          '<div class="ir-calm-ico">🛡️</div>' +
          '<div class="ir-calm-t">Sistem sakin</div>' +
          '<div class="ir-calm-s">kritik alarm yok</div>' +
        '</div>';
      return;
    }

    // içerik gerçekten değiştiyse yeniden çiz (zaman etiketi ayrıca güncellenir)
    var key = crit.map(function (a) { return (a.id != null ? a.id : a.timestamp) + ":" + a.severity; }).join("|");
    if (key === lastKey) { refreshTimes(); return; }
    lastKey = key;

    listEl.innerHTML = crit.map(function (a) {
      var id = a.id != null ? a.id : (a.source_ip + "|" + a.timestamp);
      var fresh = !seen[id];
      seen[id] = true;
      var sc = sevClass(a.severity);
      return (
        '<article class="ir-card sev-' + sc + (fresh ? " ir-enter" : "") + '" data-ts="' + esc(a.timestamp) + '">' +
          '<span class="ir-bar"></span>' +
          '<div class="ir-body">' +
            '<div class="ir-row1">' +
              '<span class="ir-sev">' + sevLabel(a.severity) + '</span>' +
              '<span class="ir-time">' + esc(relTime(a.timestamp)) + '</span>' +
            '</div>' +
            '<div class="ir-ip">' + esc(a.source_ip || "—") + '</div>' +
            '<div class="ir-row2">' +
              '<span class="ir-score">skor <b>' + esc(a.score != null ? a.score : "—") + '</b></span>' +
              '<span class="ir-clock">' + esc(clockPart(a.timestamp)) + '</span>' +
            '</div>' +
          '</div>' +
        '</article>'
      );
    }).join("");
  }

  /* Kartları yeniden çizmeden yalnızca göreli zamanları tazele */
  function refreshTimes() {
    var cards = listEl.querySelectorAll(".ir-card");
    for (var i = 0; i < cards.length; i++) {
      var ts = cards[i].getAttribute("data-ts");
      var t = cards[i].querySelector(".ir-time");
      if (t) t.textContent = relTime(ts);
    }
  }

  var latest = [];
  function poll() {
    fetch("/api/state", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.live) return;
        latest = data.live.alerts || [];
        render(latest);
      })
      .catch(function () { /* sessiz: bir sonraki turda tekrar dener */ });
  }

  poll();
  setInterval(poll, POLL_MS);
  // zaman etiketleri kart yeniden çizilmeden de aksın
  setInterval(refreshTimes, 15000);
})();
