/* ============================================================
   ARACHNE SENTINEL — Sunum Modu (video kaydı için yönetmen)
   ------------------------------------------------------------
   Gerçek paneli, gerçek verisiyle, sinematik bir tur olarak oynatır:
   giriş kartı → sahneler (her biri alt yazılı) → kapanış kartı.
   Sahte veri ÜRETMEZ; yalnızca mevcut görünümler arasında gezer ve
   /api/state'teki gerçek alarmlara tepki verir (yeni kritik alarm
   gelirse "Canlı Akış"a keser ve alarmın kendi gerekçesini gösterir).

   Başlatma: üst bardaki "SUNUM" düğmesi, Shift+S ya da ?sunum=1.
   Durdurma: Esc.
   ============================================================ */
(function () {
  "use strict";

  var SCENES = [
    { view: "web", ms: 9000, k: "01", t: "Şebeke — tek ağda 18 savunma katmanı",
      s: "Her düğüm gerçek bir katman; parlaklığı, o katmanın işlediği gerçek olay sayısı." },
    { view: "overview", ms: 10000, k: "02", t: "Genel Bakış — ölçülmüş performans", scroll: 0.45,
      s: "Tüm sayılar etiketli benchmark senaryolarıyla ölçüldü. Tahmin değil, ölçüm." },
    { view: "feed", ms: 10000, k: "03", t: "Canlı Akış — saldırgan, hedef ve olay ilişkisi",
      s: "Honeypot servislerine düşen her etkileşim anında grafa ve olay terminaline akar." },
    { view: "command", ms: 11000, k: "04", t: "Çelik Kubbe — her saldırı bir mermi, her katman bir halka",
      s: "Çarpılan halka, o kaydı gerçekten işleyen savunma katmanıdır." },
    { view: "threats", ms: 9000, k: "05", t: "Tehdit İstihbaratı — kampanyalar ve MITRE ATT&CK", scroll: 0.35,
      s: "IP değiştiren saldırgan bile parmak iziyle aynı kampanyaya bağlanır." },
    { view: "replay", ms: 12000, k: "06", t: "Saldırı Tekrarı — kill chain adım adım", play: true,
      s: "Keşiften sızıntıya: her aşamada hangi savunmanın devreye girdiği görünür." },
    { view: "soar", ms: 9000, k: "07", t: "SOAR — otonom ama denetlenebilir müdahale", scroll: 0.4,
      s: "Geri alınabilir eylem otomatik uygulanır; yıkıcı eylem insan onayına yükselir." },
    { view: "bunker", ms: 11000, k: "08", t: "Son Hat — 50 katmanlı yer altı savunma",
      s: "Kubbe delinirse devreye girer; hedef kimliği ~100 ms'de bir döner (sentetik test adresleri)." },
    { view: "adaptive", ms: 9000, k: "09", t: "Adaptif Savunma — saldırganla birlikte evrilen savunma", scroll: 0.3,
      s: "D3FEND, NIST CSF 2.0 ve oyun-teorik hareketli hedef savunması." }
  ];
  var INTRO_MS = 4200, OUTRO_MS = 6500, POLL_MS = 2000, CUT_MS = 7000;

  var running = false, timers = [], idx = -1, baseAlertId = null, cutQueue = [], lastCutAt = 0;
  var root, capK, capT, capS, bar, live, liveN, newAlerts = 0;

  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
  function clearTimers() { timers.forEach(clearTimeout); timers = []; }

  function build() {
    root = document.createElement("div");
    root.id = "showcase";
    root.innerHTML =
      '<div class="sc-card sc-intro">' +
        '<div class="sc-mark">ARACHNE</div>' +
        '<div class="sc-mark-sub">S E N T I N E L</div>' +
        '<div class="sc-line"></div>' +
        '<div class="sc-tag">Self-hosted, açıklanabilir siber savunma platformu</div>' +
        '<div class="sc-meta">Gerçek komuta merkezi · gerçek veri · ' + new Date().toLocaleDateString("tr-TR") + '</div>' +
      '</div>' +
      '<div class="sc-card sc-outro">' +
        '<div class="sc-quote">“Ölçmediğimiz hiçbir şeyi<br>iddia etmiyoruz.”</div>' +
        '<div class="sc-line"></div>' +
        '<div class="sc-mark small">ARACHNE SENTINEL</div>' +
        '<div class="sc-contact">emirhanbaydere00@outlook.com<br>github.com/KamSecHQ/arachne-sentinel</div>' +
      '</div>' +
      '<div class="sc-hud">' +
        '<div class="sc-live" id="sc-live"><span class="sc-dot"></span>CANLI<span class="sc-live-n" id="sc-live-n"></span></div>' +
        '<div class="sc-cap">' +
          '<div class="sc-k" id="sc-k"></div>' +
          '<div class="sc-txt"><div class="sc-t" id="sc-t"></div><div class="sc-s" id="sc-s"></div></div>' +
        '</div>' +
        '<div class="sc-bar"><div class="sc-bar-fill" id="sc-bar"></div></div>' +
      '</div>';
    document.body.appendChild(root);
    capK = root.querySelector("#sc-k"); capT = root.querySelector("#sc-t"); capS = root.querySelector("#sc-s");
    bar = root.querySelector("#sc-bar"); live = root.querySelector("#sc-live"); liveN = root.querySelector("#sc-live-n");
  }

  function go(view) {
    var nav = document.querySelector('.nav [data-view="' + view + '"]');
    if (nav) nav.click();
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  function caption(k, t, s) {
    var cap = root.querySelector(".sc-cap");
    cap.classList.remove("in"); void cap.offsetWidth;
    capK.textContent = k; capT.textContent = t; capS.textContent = s;
    cap.classList.add("in");
  }

  function progress(ms) {
    bar.style.transition = "none"; bar.style.width = "0%"; void bar.offsetWidth;
    bar.style.transition = "width " + ms + "ms linear"; bar.style.width = "100%";
  }

  function scene(sc) {
    go(sc.view);
    caption(sc.k + " / " + String(SCENES.length).padStart(2, "0"), sc.t, sc.s);
    progress(sc.ms);
    if (sc.scroll) {
      later(function () {
        var max = document.documentElement.scrollHeight - window.innerHeight;
        if (max > 0) window.scrollTo({ top: max * sc.scroll, behavior: "smooth" });
      }, sc.ms * 0.4);
    }
    if (sc.play) {
      later(function () {
        var p = document.getElementById("rp-play");
        if (p && p.textContent.indexOf("▶") !== -1) p.click();
      }, 900);
    }
  }

  function next() {
    if (!running) return;
    // gerçek bir kritik alarm geldiyse araya canlı kesme gir
    if (cutQueue.length && Date.now() - lastCutAt > 15000) {
      var a = cutQueue.shift(); cutQueue = [];
      lastCutAt = Date.now();
      go("feed");
      caption("CANLI", "Yeni kritik alarm — " + (a.source_ip || "?") + " · skor " + (a.score != null ? a.score : "—"), reasonOf(a));
      progress(CUT_MS);
      later(next, CUT_MS);
      return;
    }
    idx++;
    if (idx >= SCENES.length) return outro();
    scene(SCENES[idx]);
    later(next, SCENES[idx].ms);
  }

  function reasonOf(a) {
    var r = a.reasons;
    if (typeof r === "string") { try { r = JSON.parse(r); } catch (e) { r = [r]; } }
    return String((r && r[0]) || "Kural motoru alarm üretti.").split(" — ")[0];
  }

  function poll() {
    if (!running) return;
    fetch("/api/state", { headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.live || !running) return;
        var alerts = d.live.alerts || [];
        var maxId = alerts.reduce(function (m, a) { return a.id > m ? a.id : m; }, 0);
        if (baseAlertId === null) { baseAlertId = maxId; return; }
        var fresh = alerts.filter(function (a) { return a.id > baseAlertId; });
        if (fresh.length) {
          newAlerts += fresh.length;
          baseAlertId = maxId;
          liveN.textContent = " · +" + newAlerts + " alarm";
          live.classList.remove("pulse"); void live.offsetWidth; live.classList.add("pulse");
          var crit = fresh.filter(function (a) { return a.severity === "critical"; });
          if (crit.length) cutQueue.push(crit[0]);
        }
      })
      .catch(function () {})
      .then(function () { if (running) later(poll, POLL_MS); });
  }

  function outro() {
    root.classList.add("show-outro");
    root.classList.remove("show-hud");
    later(stop, OUTRO_MS);
  }

  function start() {
    if (running) return;
    if (!root) build();
    running = true; idx = -1; baseAlertId = null; cutQueue = []; newAlerts = 0; liveN.textContent = "";
    var skip = document.getElementById("boot-skip");
    var boot = document.getElementById("boot");
    if (skip && boot && getComputedStyle(boot).display !== "none") skip.click();
    try { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); } catch (e) {}
    document.body.classList.add("showcase-on");
    root.className = "on show-intro";
    poll();
    later(function () {
      root.classList.remove("show-intro");
      root.classList.add("show-hud");
      next();
    }, INTRO_MS);
  }

  function stop() {
    running = false; clearTimers();
    document.body.classList.remove("showcase-on");
    if (root) root.className = "";
    try { if (document.fullscreenElement) document.exitFullscreen(); } catch (e) {}
  }

  // üst bar düğmesi
  var spacer = document.querySelector(".topbar .spacer");
  if (spacer) {
    var btn = document.createElement("button");
    btn.className = "pill-link sc-btn";
    btn.id = "showcase-btn";
    btn.title = "Sunum modu — video kaydı için otomatik tur (Shift+S, Esc ile çık)";
    btn.innerHTML = '<span class="sc-btn-dot"></span>SUNUM';
    btn.addEventListener("click", start);
    spacer.after(btn);
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && running) stop();
    if (e.key === "S" && e.shiftKey && !running && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) start();
  });
  if (/[?&]sunum=1/.test(location.search)) setTimeout(start, 600);

  window.ArachneShowcase = { start: start, stop: stop };
})();
