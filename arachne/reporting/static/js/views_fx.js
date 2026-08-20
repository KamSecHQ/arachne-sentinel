/* ============================================================
   Arachne Sentinel — views_fx.js  (Faz 72)
   TÜM görünümlere sağlık kazandıran ADDITIVE geliştirme:
     1) Sayaç animasyonu (count-up) — stat/metrik sayıları 0→hedef
        yumuşak sayar; app.js/command_center yeniden render edince
        MutationObserver ile tekrar uygulanır. Var olan metni bozmaz,
        binlik ayraç formatı korunur. İçerik-tabanlı hafıza ile
        DEĞİŞMEYEN değerler tekrar animasyona sokulmaz (flicker yok).
     2) Veri çubukları — yüzde/oran içeren güvenli yerlere .fx-meter
        çubuğu enjekte eder (metrik tile + kolektif KPI).
   Defansif: her şey try/catch içinde, hata sessiz. __viewsFx guard'ı
   ile iki kez init olmaz. app.html'e script tag'i AYRICA eklenir.
   ============================================================ */
(function () {
  "use strict";
  if (window.__viewsFx) return;
  window.__viewsFx = true;

  try {
    var raf = window.requestAnimationFrame
      ? window.requestAnimationFrame.bind(window)
      : function (f) { return setTimeout(function () { f(now()); }, 16); };
    function now() { return (window.performance && performance.now) ? performance.now() : Date.now(); }

    /* Tamamen tamsayı mı? (opsiyonel binlik ayraç: 1,234 / 12 345) */
    var INT_RE = /^-?\d{1,3}(?:[, ]\d{3})+$|^-?\d+$/;
    var busy = new WeakSet();       // o an animasyonda olan düğümler
    var mem = Object.create(null);  // içerik-tabanlı son değer hafızası

    function toInt(s) {
      var n = parseInt(String(s).replace(/[^\d-]/g, ""), 10);
      return isNaN(n) ? null : n;
    }
    function txt(node) { return node ? String(node.textContent || "").trim() : ""; }
    function grouped(str, val) {
      try { if (/[, ]\d{3}/.test(str)) return val.toLocaleString("en-US"); } catch (e) {}
      return String(val);
    }
    function ease(p) { return 1 - Math.pow(1 - p, 3); }

    /* İçerik-tabanlı kararlı anahtar (DOM yeniden kurulsa da hatırlar). */
    function keyOf(el) {
      try {
        if (el.id) return "#" + el.id;
        if (el.matches("#map-stats b, .viz-stats b")) {
          var row = el.closest(".ms-row") || el.parentNode;
          var lbl = row ? row.querySelector("span") : null;
          return "vs:" + (lbl ? txt(lbl) : txt(el.previousSibling));
        }
        if (el.matches(".ck-v")) {
          var ckl = el.parentNode ? el.parentNode.querySelector(".ck-l") : null;
          return "ck:" + (ckl ? txt(ckl) : "");
        }
        if (el.matches(".mt-val")) {
          var mtl = el.parentNode ? el.parentNode.querySelector(".mt-label") : null;
          return "mt:" + (mtl ? txt(mtl) : "");
        }
        if (el.matches(".lc-metric")) {
          var card = el.closest(".layer-card");
          var nm = card ? card.querySelector(".lc-name") : null;
          return "lc:" + (nm ? txt(nm) : "");
        }
      } catch (e) {}
      return null;
    }

    /* 0→hedef animasyonu (write: her kareyi yazan fonksiyon). */
    function run(node, from, to, srcText, write) {
      var t0 = now(), dur = 600;
      function step(t) {
        var p = Math.min(1, (t - t0) / dur);
        var v = Math.round(from + (to - from) * ease(p));
        write(grouped(srcText, v));
        if (p < 1) raf(step); else { write(grouped(srcText, to)); busy.delete(node); }
      }
      raf(step);
    }

    /* Ortak sayaç mantığı: raw sayı metni + yazıcı. */
    function animateValue(node, raw, write) {
      var target = toInt(raw);
      if (target === null) return;
      var key = keyOf(node);
      var prev = (key != null && key in mem)
        ? mem[key]
        : (node.dataset && node.dataset.fxCur != null ? toInt(node.dataset.fxCur) : 0);
      if (prev === null) prev = 0;
      if (key != null) mem[key] = target;
      if (node.dataset) node.dataset.fxCur = String(target);
      if (prev === target) return;   // değişmedi → dokunma
      busy.add(node);
      run(node, prev, target, raw, write);
    }

    /* Tüm textContent'i sayı olan eleman. */
    function countFull(el) {
      if (!el || busy.has(el)) return;
      var raw = txt(el);
      if (!raw || !INT_RE.test(raw)) return;
      animateValue(el, raw, function (t) { el.textContent = t; });
    }

    /* Baştaki metin düğümü sayı olan eleman (ör. .lc-metric = "128<span>…"). */
    function countLead(el) {
      if (!el || busy.has(el)) return;
      var node = el.firstChild;
      if (!node || node.nodeType !== 3) return;
      var raw = String(node.nodeValue || "").trim();
      if (!raw || !INT_RE.test(raw)) return;
      animateValue(el, raw, function (t) {
        if (node && node.parentNode) node.nodeValue = t;
      });
    }

    var COUNT_FULL = ["#map-stats b", ".viz-stats b", ".mt-val", ".ck-v"];
    var COUNT_LEAD = [".lc-metric"];

    function scanCounts() {
      try { document.querySelectorAll(COUNT_FULL.join(",")).forEach(countFull); } catch (e) {}
      try { document.querySelectorAll(COUNT_LEAD.join(",")).forEach(countLead); } catch (e) {}
    }

    /* ---------- Veri çubukları (.fx-meter) ---------- */
    function clamp(x) { return Math.max(0, Math.min(100, x)); }
    /* "94.2%" / "%80" / "5/8" → 0-100 yüzde; değilse null. */
    function pctFrom(str) {
      if (!str) return null;
      var s = str.trim();
      var m = s.match(/(-?\d+(?:\.\d+)?)\s*%/) ||
              (s.charAt(0) === "%" ? s.slice(1).match(/^(-?\d+(?:\.\d+)?)/) : null);
      if (m) { var p = parseFloat(m[1]); return isFinite(p) ? clamp(p) : null; }
      var r = s.match(/^(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)$/);
      if (r) { var a = parseFloat(r[1]), b = parseFloat(r[2]); if (b > 0) return clamp((a / b) * 100); }
      return null;
    }

    function ensureMeter(host, pct) {
      if (!host) return;
      var meter = host.querySelector(":scope > .fx-meter");
      if (!meter) {
        meter = document.createElement("div");
        meter.className = "fx-meter";
        var bar = document.createElement("div");
        bar.className = "fx-bar";
        meter.appendChild(bar);
        host.appendChild(meter);
      }
      var fill = meter.firstChild;
      if (fill) {
        var w = pct.toFixed(1) + "%";
        if (fill.style.width !== w) {
          if (!fill.style.width) { fill.style.width = "0%"; void fill.offsetWidth; }
          fill.style.width = w;
        }
      }
    }

    function scanMeters() {
      try {
        document.querySelectorAll(".metric-tile").forEach(function (tile) {
          var v = tile.querySelector(".mt-val");
          var p = v ? pctFrom(v.textContent) : null;
          if (p !== null) ensureMeter(tile, p);
        });
      } catch (e) {}
      try {
        document.querySelectorAll(".col-kpi").forEach(function (col) {
          var v = col.querySelector(".ck-v");
          var p = v ? pctFrom(v.textContent) : null;
          if (p !== null) ensureMeter(col, p);
        });
      } catch (e) {}
    }

    /* ---------- Zamanlama: MutationObserver + rAF debounce ---------- */
    var pending = false;
    function schedule() {
      if (pending) return;
      pending = true;
      raf(function () {
        pending = false;
        scanCounts();
        scanMeters();
      });
    }

    function init() {
      scanCounts();
      scanMeters();
      try {
        if (window.MutationObserver && document.body) {
          var mo = new MutationObserver(schedule);
          mo.observe(document.body, { childList: true, characterData: true, subtree: true });
        } else {
          setInterval(schedule, 1500);
        }
      } catch (e) {
        try { setInterval(schedule, 1500); } catch (e2) {}
      }
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () { try { init(); } catch (e) {} });
    } else {
      init();
    }
  } catch (e) {
    /* sessiz — asla mevcut işlevi bozma */
  }
})();
