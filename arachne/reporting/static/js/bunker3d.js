/* ============================================================
   ARACHNE SENTINEL — Faz 82-100: YER ALTI ULTRA SAVUNMA (SON HAT)

   Gök kubbe (yüzey kalkanı) DELİNİRSE devreye giren GİZLİ son-hat savunması.
   Gök kubbeden çok daha ileri: 50 katmanlı, yer altına inen bir KASA + hedef
   kimliğini ~100 ms'de bir döndüren HAYALET (hiper hareketli hedef) motoru.

   Kavram (savunma teknikleri — tamamen savunma, hack-back yok):
     • Hiper Kimlik Rotasyonu: IP/port/parmak-izi 100 ms'de bir döner →
       saldırgan gerçek varlığı KİLİTLEYEMEZ.
     • 50 katmanlı yer altı kasası: kubbe delininde katmanlar tepeden dibe
       sırayla MÜHÜRLENİR; korunan varlık en dipte, dönen yem-çekirdek ordusu
       arasında gizlenir.
     • Kubbe delinse bile GERÇEK varlığa sızıntı olmaz — son hat tutar.

   DÜRÜSTLÜK: Gösterge artık GERÇEK bir motora bağlıdır (arachne/lastline).
   Kimlik (IP/port/parmak-izi/jeton) DETERMİNİSTİK üretilir: tarayıcı ile sunucu
   BİREBİR aynı FNV-1a'yı kullanır → aynı zaman diliminde AYNI kimliği üretirler
   (rastgele değil, doğrulanabilir). 50 katmanın adı/mührü/ölçüsü ve bütünlük
   kökü /api/fortress'ten (gerçek hesap) gelir. Adresler RFC 2544/5737 test
   aralığındandır. THREE/WebGL yoksa 2B'ye zarifçe düşer.
   ============================================================ */
(function () {
  "use strict";
  window.__BUNKER = false;

  /* ---------- FNV-1a 32-bit (arachne/lastline/base.py::fnv1a ile BİREBİR) ----------
     Python: h=0x811C9DC5; her bayt: h^=b; h=(h*0x01000193)&0xFFFFFFFF.
     JS'te 32-bit çarpım için Math.imul kullanılır (aksi halde hassasiyet kaybı). */
  const _enc = new TextEncoder();
  function fnv1a(str) {
    const bytes = _enc.encode(str);
    let h = 0x811C9DC5;
    for (let i = 0; i < bytes.length; i++) {
      h ^= bytes[i];
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }
  const hex8 = (n) => (n >>> 0).toString(16).padStart(8, "0");
  const hex4 = (n) => (n % 0x10000).toString(16).padStart(4, "0");

  /* ---------- Deterministik kimlik (identity.py::identity_at ile BİREBİR) ---------- */
  function identityAt(nowMs, seed, intervalMs) {
    const slot = Math.floor(nowMs / Math.max(1, intervalMs));
    const base = seed + ":" + slot;
    const ip1 = fnv1a(base + ":ip1") % 256;
    const ip2 = fnv1a(base + ":ip2") % 256;
    const ip = "198.18." + ip1 + "." + ip2;                 // RFC 2544 test aralığı
    const port = 1024 + (fnv1a(base + ":port") % 64512);
    const fp = hex8(fnv1a(base + ":fp1")) + hex4(fnv1a(base + ":fp2"));  // 12 hex
    const token = hex8(fnv1a(base + ":tok"));
    return { slot, ip, port, fingerprint: fp, token };
  }

  /* ---------- HAYALET hiper-kimlik motoru (GERÇEK: sunucuyla parite) ---------- */
  let active = false, rotTimer = null;
  // sunucudan gelen gerçek parametreler; sunucu erişilemezse güvenli varsayılan
  let mtdSeed = "arachne", mtdInterval = 100, mtdEngaged = false, mtdEpochSlot = 0;
  let layerNames = [];                 // sunucudan gelen gerçek katman adları
  const N = 50;

  function tickIdentity() {
    const el = document.getElementById("bunker-mtd");
    if (!el) return;
    const now = Date.now();
    const id = identityAt(now, mtdSeed, mtdInterval);        // sunucuyla AYNI değer
    const ip = document.getElementById("bk-ip"), pt = document.getElementById("bk-port"),
          fp = document.getElementById("bk-fp"), ct = document.getElementById("bk-count");
    if (ip) ip.textContent = id.ip;
    if (pt) pt.textContent = id.port;
    if (fp) fp.textContent = id.fingerprint;
    // rotasyon sayısı = devreye girişten bu yana geçen 100ms dilimi (gerçek)
    const rot = mtdEngaged ? Math.max(0, id.slot - mtdEpochSlot) : 0;
    if (ct) ct.textContent = rot.toLocaleString("tr-TR");
  }
  function startRotation(intervalMs) {
    if (rotTimer) clearInterval(rotTimer);
    rotTimer = setInterval(tickIdentity, intervalMs);
    tickIdentity();
  }

  /* ---------- /api/fortress: GERÇEK motor durumu ---------- */
  function applyStatus(st) {
    if (!st) return;
    const p = st.identity_params || {};
    if (p.seed) mtdSeed = p.seed;
    if (p.interval_ms) mtdInterval = p.interval_ms;
    mtdEngaged = !!p.engaged;
    if (p.epoch_ms) mtdEpochSlot = Math.floor(p.epoch_ms / Math.max(1, mtdInterval));
    // gerçek katman adları (parite: sunucu ne diyorsa o)
    if (Array.isArray(st.layers) && st.layers.length) {
      layerNames = st.layers.map((l) => l.name);
      renderLayerGrid(st.layers);
    }
    // bütünlük kökü + tepki + yem sayısı (gerçek ölçüler)
    const setTxt = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    if (st.integrity_root) setTxt("bk-integrity", "0x" + st.integrity_root);
    if (st.summary) {
      setTxt("bk-decoys", (st.summary.decoys || 0).toLocaleString("tr-TR"));
      setTxt("bk-sealed", (st.summary.sealed_layers || 0) + " / " + (st.summary.total_layers || 0));
    }
    if (typeof st.reaction_ms === "number")
      setTxt("bk-reaction", st.reaction_ms.toFixed(1) + " ms" + (st.reaction_ok ? " ✓" : ""));
  }
  async function fetchFortress(path, opts) {
    try {
      const r = await fetch(path, opts || {});
      if (!r.ok) return null;
      return await r.json();
    } catch (e) { return null; }
  }
  async function refreshFortress() {
    const st = await fetchFortress("/api/fortress");
    applyStatus(st);
    return st;
  }

  /* ---------- 50 katman durum ızgarası (DOM) — gerçek adlar ---------- */
  function renderLayerGrid(layers) {
    const root = document.getElementById("bunker-layers");
    if (!root) return;
    const names = (layers && layers.length) ? layers.map((l) => l.name)
                 : (layerNames.length ? layerNames : Array.from({ length: N }, (_, i) => "Katman " + (i + 1)));
    root.innerHTML = names.map((name, i) => {
      const sealed = layers && layers[i] && layers[i].engaged;
      const st = sealed ? "MÜHÜRLÜ" : "HAZIR";
      return `<div class="bk-layer${sealed ? " sealed" : ""}" data-i="${i}">` +
        `<span class="bk-idx">${String(i + 1).padStart(2, "0")}</span>` +
        `<span class="bk-name">${name}</span><span class="bk-state">${st}</span></div>`;
    }).join("");
  }
  function sealLayer(i) {
    const el = document.querySelector(`#bunker-layers .bk-layer[data-i="${i}"]`);
    if (!el) return;
    el.classList.add("sealed");
    const st = el.querySelector(".bk-state"); if (st) st.textContent = "MÜHÜRLÜ";
  }
  function resetLayers() {
    document.querySelectorAll("#bunker-layers .bk-layer").forEach((el) => {
      el.classList.remove("sealed"); const st = el.querySelector(".bk-state"); if (st) st.textContent = "HAZIR";
    });
  }
  function setStatus(txt, cls) {
    const s = document.getElementById("bunker-status");
    if (s) { s.textContent = txt; s.className = "bk-status " + (cls || ""); }
    const b = document.getElementById("badge-bunker");
    if (b) { b.textContent = cls === "on" ? "AKTİF" : "HAZIR"; b.classList.toggle("hot", cls === "on"); }
  }

  /* ============================================================
     3B YER ALTI KASASI (Three.js) — inen huni + 50 zırh halkası
     ============================================================ */
  let three = null;
  function initThree() {
    if (typeof THREE === "undefined") return null;
    const canvas = document.getElementById("bunker-canvas");
    if (!canvas) return null;
    let renderer;
    try { renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true }); }
    catch (e) { return null; }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05030a, 0.03);
    const camera = new THREE.PerspectiveCamera(52, 1, 0.1, 400);

    const C_VIOLET = new THREE.Color(0x9b6bff), C_GOLD = new THREE.Color(0xffcf6a),
          C_CYAN = new THREE.Color(0x35e0d0), C_RED = new THREE.Color(0xff3b45);
    let energy = 0, energyTarget = 0;   // 0 uyku, 1 tam aktif

    const DEPTH = 46, topR = 15, botR = 2.6;
    const rings = [];
    const vault = new THREE.Group(); scene.add(vault);
    for (let i = 0; i < N; i++) {
      const f = i / (N - 1);
      const y = -f * DEPTH;
      const rr = topR - (topR - botR) * f;            // huni gibi daralır
      // altıgen zırh halkası
      const geo = new THREE.TorusGeometry(rr, 0.10, 6, 6);   // 6 kenar = altıgen his
      const baseCol = C_VIOLET.clone().lerp(C_CYAN, f);
      const mat = new THREE.MeshBasicMaterial({ color: baseCol, transparent: true, opacity: 0.32,
        blending: THREE.AdditiveBlending, depthWrite: false });
      const m = new THREE.Mesh(geo, mat); m.rotation.x = Math.PI / 2; m.position.y = y;
      vault.add(m);
      rings.push({ m, base: baseCol.clone(), y, rr, sealT: 0, sealed: false });
    }
    // dikey enerji sütunları (kafes hissi)
    for (let k = 0; k < 8; k++) {
      const a = k / 8 * Math.PI * 2;
      const pts = [new THREE.Vector3(Math.cos(a) * topR, 0, Math.sin(a) * topR),
                   new THREE.Vector3(Math.cos(a) * botR, -DEPTH, Math.sin(a) * botR)];
      vault.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
        new THREE.LineBasicMaterial({ color: 0x6b4fb0, transparent: true, opacity: 0.18 })));
    }
    // dipteki KORUNAN VARLIK kasası (oktahedron) + hâle
    const core = new THREE.Mesh(new THREE.OctahedronGeometry(2.0, 0),
      new THREE.MeshBasicMaterial({ color: C_GOLD.clone(), wireframe: true, transparent: true, opacity: 0.9 }));
    core.position.y = -DEPTH; scene.add(core);
    const coreGlow = new THREE.Mesh(new THREE.SphereGeometry(1.3, 16, 16),
      new THREE.MeshBasicMaterial({ color: 0xfff0c0, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending }));
    coreGlow.position.y = -DEPTH; scene.add(coreGlow);
    // yem-çekirdek ordusu (dönen sahte çekirdekler)
    const decoys = [];
    for (let k = 0; k < 10; k++) {
      const d = new THREE.Mesh(new THREE.OctahedronGeometry(0.7, 0),
        new THREE.MeshBasicMaterial({ color: C_VIOLET.clone(), wireframe: true, transparent: true, opacity: 0.5 }));
      scene.add(d); decoys.push({ m: d, a: k / 10 * Math.PI * 2, rad: 5.2 });
    }
    // tepe: dönen kilit irisleri
    const iris = new THREE.Group(); iris.position.y = 0.4; scene.add(iris);
    for (let k = 0; k < 3; k++) {
      const ir = new THREE.Mesh(new THREE.TorusGeometry(topR * (1 + k * 0.06), 0.16, 8, 80),
        new THREE.MeshBasicMaterial({ color: C_VIOLET.clone(), transparent: true, opacity: 0.3, blending: THREE.AdditiveBlending }));
      ir.rotation.x = Math.PI / 2; iris.add(ir);
    }
    // hızlı dönen "hayalet kimlik" halkası
    const ghost = new THREE.Mesh(new THREE.TorusGeometry(topR * 0.7, 0.06, 6, 60),
      new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), transparent: true, opacity: 0.4, blending: THREE.AdditiveBlending }));
    ghost.rotation.x = Math.PI / 2; ghost.position.y = -1.5; scene.add(ghost);

    function resize() {
      const w = canvas.clientWidth || 900, h = canvas.clientHeight || 700;
      renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix();
    }
    window.addEventListener("resize", resize);

    let t = 0;
    function frame() {
      t += 0.016;
      energy += (energyTarget - energy) * 0.05;
      // kamera: şafta yukarıdan bakış + yavaş yörünge
      const orbit = t * 0.06, cr = 34, cy = 14;
      camera.position.set(Math.sin(orbit) * cr, cy, Math.cos(orbit) * cr);
      camera.lookAt(0, -DEPTH * 0.42, 0);

      vault.rotation.y += 0.0015 + energy * 0.004;
      iris.rotation.y -= 0.01 + energy * 0.05;
      ghost.rotation.y += 0.4 + energy * 1.6;   // AKTİFTE çılgınca döner (hayalet)

      rings.forEach((rg, i) => {
        // uykuda soluk; aktifte tepeden dibe dalga hâlinde parlar
        const wave = Math.max(0, 1 - Math.abs(((t * 0.6) % (N)) - i) / 3);
        let op = 0.22 + wave * 0.16 + energy * 0.28;
        let col = rg.base.clone();
        if (rg.sealed) { rg.sealT = Math.min(1, rg.sealT + 0.08); op = 0.35 + 0.5 * rg.sealT + 0.2 * Math.sin(t * 8 + i); col = col.lerp(C_GOLD, 0.6); }
        col.lerp(C_RED, energy * 0.15);
        rg.m.material.opacity = op;
        rg.m.material.color.copy(col);
        rg.m.scale.setScalar(rg.sealed ? 1.0 : 1.0 + Math.sin(t * 2 + i * 0.3) * 0.01);
      });

      core.rotation.y += 0.02 + energy * 0.06; core.rotation.x += 0.01;
      const cp = 1 + Math.sin(t * 3) * 0.12 + energy * 0.4; coreGlow.scale.setScalar(cp);
      coreGlow.material.opacity = 0.5 + energy * 0.4 + Math.sin(t * 5) * 0.15;
      core.material.color.copy(C_GOLD.clone().lerp(new THREE.Color(0xffffff), energy * 0.4));

      // yem çekirdekler çok hızlı döner (aktifte) → hangisi gerçek belli olmaz
      decoys.forEach((d, k) => {
        const spd = 0.6 + energy * 3.5;
        d.a += spd * 0.016;
        d.m.position.set(Math.cos(d.a) * d.rad, -DEPTH + Math.sin(t * 2 + k) * 1.2, Math.sin(d.a) * d.rad);
        d.m.rotation.y += 0.1; d.m.material.opacity = 0.3 + energy * 0.5;
        d.m.material.color.copy(C_VIOLET.clone().lerp(C_CYAN, (Math.sin(t + k) + 1) / 2));
      });

      renderer.render(scene, camera);
      requestAnimationFrame(frame);
    }
    resize(); requestAnimationFrame(frame);
    return {
      activate() { energyTarget = 1; },
      standby() { energyTarget = 0; },
      resize,
    };
  }

  /* ============================================================
     ETKİNLEŞTİRME AKIŞI
     ============================================================ */
  async function activateBunker() {
    if (active) return;
    active = true;
    setStatus("● AKTİF — SON HAT DEVREDE · hedef kilitlenemiyor", "on");
    if (three) three.activate();
    if (window.ArachneSFX) window.ArachneSFX.alarm();
    // GERÇEK motoru devreye al (kubbe delinmiş gibi) — tepki süresi ölçülür
    const st = await fetchFortress("/api/fortress/engage", { method: "POST" });
    if (st) {
      applyStatus(st);                  // gerçek katman durumu + tepki + bütünlük kökü
      startRotation(mtdInterval || 100); // 100 ms'de bir kimlik döner (sunucuyla parite)
      // gerçek "engaged" katmanları tepeden dibe sırayla mühürle (görsel dalga)
      resetLayers();
      const layers = st.layers || [];
      let step = 0;
      for (let i = 0; i < layers.length; i++) {
        if (layers[i].engaged) setTimeout(() => sealLayer(i), (step++) * 26);
      }
    } else {
      // sunucu erişilemedi — yine de deterministik kimlik dönsün (istemci-taraf)
      mtdEngaged = true; mtdEpochSlot = Math.floor(Date.now() / (mtdInterval || 100));
      startRotation(mtdInterval || 100);
    }
    // periyodik tazele (gerçek bütünlük/tepki/yem sayısı canlı kalsın)
    clearInterval(window.__bunkerPoll);
    window.__bunkerPoll = setInterval(refreshFortress, 2000);
    // 11 sn sonra bekleme moduna dön
    clearTimeout(window.__bunkerStand);
    window.__bunkerStand = setTimeout(standbyBunker, 11000);
  }
  async function standbyBunker() {
    active = false;
    setStatus("◎ HAZIR (STANDBY) — kubbe delinirse otomatik devreye girer", "");
    if (three) three.standby();
    clearInterval(window.__bunkerPoll);
    await fetchFortress("/api/fortress/standby", { method: "POST" });
    mtdEngaged = false;
    startRotation(1100);                // uykuda yavaş "nöbet" rotasyonu
  }

  /* ---------- başlat ---------- */
  async function boot() {
    if (!document.getElementById("bunker-canvas") && !document.getElementById("bunker-layers")) return;
    // gerçek motordan parametre + katman adlarını al (parite için)
    const st = await refreshFortress();
    renderLayerGrid(st && st.layers);
    three = initThree();
    window.__BUNKER = true;
    active = true; standbyBunker();     // uykuda başlar, nöbet rotasyonu döner
    // kubbe DELİNİRSE (arachne:breach) → SON HAT otomatik devreye girer
    window.addEventListener("arachne:breach", () => {
      activateBunker();
      // ~1.4 sn sonra kullanıcıyı Son Hat görünümüne al (dramatik geçiş)
      setTimeout(() => {
        const nav = document.querySelector('.nav-item[data-view="bunker"]');
        if (nav) nav.click();
      }, 1400);
    });
    window.ArachneBunker = { activate: activateBunker, standby: standbyBunker, refresh: refreshFortress };
  }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
