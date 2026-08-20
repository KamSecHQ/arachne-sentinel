/* ============================================================
   ARACHNE SENTINEL — Faz 51-53 (v2): 3D KÜRESEL KALKAN RADAR

   Belirgin, GERÇEK 3B küresel KALKAN kubbesi + 360° radar:
     • büyük, parlayan KÜRESEL KALKAN (jeodezik tel-kafes + hacimsel hâle
       + taban halkası). Saldırı yokken MAVİ, saldırı gelince KIRMIZI ve
       çok belirgin — nabız atar, çarpma noktasında dalgalanır.
     • 18 eşmerkezli katman halkası (dıştan içe), okunaklı etiketler
       (arka plakalı, lider çizgili, iç halkalar için açılmış)
     • dönen 360° tarama huzmesi + menzil ızgarası
     • kalkan yüzeyinden dalarak gelen 3B saldırı ışınları → doğru
       halkaya çarpıp patlar; kalkanda hex dalga bırakır
     • merkezde nabız atan reaktör çekirdek (KORUNAN VARLIK)

   HİÇBİR SAHTE VERI: her ışın gerçek bir olaydır; çarptığı halka o kaydı
   gerçekten işleyen katmandır. THREE/WebGL yoksa 2B kubbeye düşülür.
   ============================================================ */
(function () {
  "use strict";
  window.__DOME3D = false;
  if (typeof THREE === "undefined") return;
  const canvas = document.getElementById("dome-canvas");
  if (!canvas) return;
  let renderer;
  try { renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true }); }
  catch (e) { return; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const R = 22;
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 500);

  const rgb = (s) => { const p = String(s||"80,180,220").split(",").map(Number);
    return new THREE.Color(`rgb(${p[0]||80},${p[1]||180},${p[2]||220})`); };
  const C_GREEN = new THREE.Color(0x22c55e);
  const C_CYAN = new THREE.Color(0x35e0d0);
  const C_BLUE = new THREE.Color(0x2aa8e8);
  const C_RED = new THREE.Color(0xff2f3a);
  let alarm = 0, alarmTarget = 0;
  const mix = (a, b) => a.clone().lerp(b, alarm);

  /* ---------- zemin: menzil halkaları + radyal spokes ---------- */
  const gridG = new THREE.Group(); scene.add(gridG);
  for (let i = 1; i <= 6; i++) {
    const rr = (i / 6) * R;
    const m = new THREE.Mesh(new THREE.RingGeometry(rr - 0.03, rr + 0.03, 100),
      new THREE.MeshBasicMaterial({ color: 0x1f6f82, transparent: true, opacity: 0.22, side: THREE.DoubleSide }));
    m.rotation.x = -Math.PI/2; gridG.add(m);
  }
  for (let a = 0; a < 360; a += 15) {
    const rad = a*Math.PI/180;
    const g = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0.01,0),
      new THREE.Vector3(Math.cos(rad)*R,0.01,Math.sin(rad)*R)]);
    gridG.add(new THREE.Line(g, new THREE.LineBasicMaterial({ color: 0x1f6f82, transparent: true, opacity: a%45===0?0.22:0.10 })));
  }

  /* ---------- KÜRESEL KALKAN (belirgin, 3B) ---------- */
  const shield = new THREE.Group(); scene.add(shield);
  // 1) jeodezik tel-kafes (üst yarım küre)
  const shieldWire = new THREE.Mesh(
    new THREE.SphereGeometry(R, 48, 32, 0, Math.PI*2, 0, Math.PI/2),
    new THREE.MeshBasicMaterial({ color: C_BLUE.clone(), wireframe: true, transparent: true, opacity: 0.22 })
  );
  shield.add(shieldWire);
  // 2) hacimsel iç hâle (BackSide, additive) — kalkanın "cam" hissi
  const shieldGlow = new THREE.Mesh(
    new THREE.SphereGeometry(R*0.99, 48, 32, 0, Math.PI*2, 0, Math.PI/2),
    new THREE.MeshBasicMaterial({ color: C_BLUE.clone(), transparent: true, opacity: 0.06,
      side: THREE.BackSide, blending: THREE.AdditiveBlending, depthWrite: false })
  );
  shield.add(shieldGlow);
  // 3) ikinci ince kabuk (derinlik)
  const shieldWire2 = new THREE.Mesh(
    new THREE.SphereGeometry(R*0.93, 24, 16, 0, Math.PI*2, 0, Math.PI/2),
    new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), wireframe: true, transparent: true, opacity: 0.08 })
  );
  shield.add(shieldWire2);
  // 4) taban halkası (parlak)
  const baseRing = new THREE.Mesh(new THREE.TorusGeometry(R, 0.14, 10, 120),
    new THREE.MeshBasicMaterial({ color: C_BLUE.clone(), transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending }));
  baseRing.rotation.x = -Math.PI/2; shield.add(baseRing);

  // 5) enlem/boylam aksan çizgileri (kubbe "katı 3B enerji" hissi + shimmer)
  const shieldAccent = new THREE.Group(); shield.add(shieldAccent);
  for (let li = 1; li <= 3; li++) {           // enlem daireleri
    const el = (li/4)*(Math.PI/2), rr2 = Math.cos(el)*R*0.995, yy = Math.sin(el)*R*0.995;
    const pts = []; for (let k = 0; k <= 64; k++) { const a = k/64*Math.PI*2; pts.push(new THREE.Vector3(Math.cos(a)*rr2, yy, Math.sin(a)*rr2)); }
    shieldAccent.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
      new THREE.LineBasicMaterial({ color: C_CYAN.clone(), transparent: true, opacity: 0.10, blending: THREE.AdditiveBlending, depthWrite: false })));
  }
  for (let mi = 0; mi < 6; mi++) {             // boylam yarı-yayları
    const az = mi/6*Math.PI*2, pts = [];
    for (let k = 0; k <= 32; k++) { const el = k/32*(Math.PI/2); pts.push(new THREE.Vector3(Math.cos(az)*Math.cos(el)*R*0.995, Math.sin(el)*R*0.995, Math.sin(az)*Math.cos(el)*R*0.995)); }
    shieldAccent.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
      new THREE.LineBasicMaterial({ color: C_BLUE.clone(), transparent: true, opacity: 0.08, blending: THREE.AdditiveBlending, depthWrite: false })));
  }

  // yardımcılar
  const surfacePos = (angle, el, rad) => new THREE.Vector3(
    Math.cos(angle)*Math.cos(el)*rad, Math.sin(el)*rad, Math.sin(angle)*Math.cos(el)*rad);
  const norm = (a) => { a %= Math.PI*2; if (a < 0) a += Math.PI*2; return a; };
  const angDiff = (a, b) => { let d = (a-b) % (Math.PI*2); if (d > Math.PI) d -= Math.PI*2; if (d < -Math.PI) d += Math.PI*2; return Math.abs(d); };
  const disposeObj = (o) => o.traverse((c) => { if (c.geometry) c.geometry.dispose(); if (c.material) { if (c.material.map) c.material.map.dispose(); c.material.dispose(); } });

  // kalkan çarpma dalgaları (hex ripple yüzeyde)
  const shieldHits = [];
  function shieldHit(angle, color) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.4, 0.9, 24),
      new THREE.MeshBasicMaterial({ color: color.clone(), transparent: true, opacity: 0.9,
        side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
    // yüzeyde konumla (yarım küre üstünde, bearing yönünde)
    const el = Math.PI*0.28;
    m.position.copy(surfacePos(angle, el, R*0.98));
    m.lookAt(0,0,0);
    scene.add(m); shieldHits.push({ mesh: m, t: 0 });
  }

  // HEX KALKAN ÇATLAĞI + yerel parlama: ışın halkasına çarpınca kalkan yüzeyinde
  const shieldFractures = [];
  function shieldFracture(angle, color) {
    if (shieldFractures.length > 14) { const o = shieldFractures.shift(); scene.remove(o.grp); disposeObj(o.grp); }
    const el = Math.PI*0.28, P = surfacePos(angle, el, R*0.985);
    const grp = new THREE.Group(); grp.position.copy(P); grp.lookAt(0,0,0);
    const rr = 1.3, verts = [];
    for (let k = 0; k < 6; k++) { const a = k/6*Math.PI*2 + 0.25; verts.push(new THREE.Vector3(Math.cos(a)*rr, Math.sin(a)*rr, 0)); }
    const pts = [];
    for (let k = 0; k < 6; k++) { pts.push(verts[k].clone(), verts[(k+1)%6].clone()); }   // hex kenarları
    for (let k = 0; k < 6; k += 2) { pts.push(new THREE.Vector3(0,0,0), verts[k].clone().multiplyScalar(1.55)); } // radyal çatlaklar
    const seg = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(pts),
      new THREE.LineBasicMaterial({ color: color.clone(), transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false }));
    grp.add(seg);
    const disc = new THREE.Mesh(new THREE.CircleGeometry(1.7, 20),   // yerel parlama flaşı
      new THREE.MeshBasicMaterial({ color: color.clone(), transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide }));
    grp.add(disc);
    scene.add(grp); shieldFractures.push({ grp, seg, disc, t: 0 });
  }

  /* ---------- 360° tarama huzmesi ---------- */
  const sweep = new THREE.Group();
  const sect = new THREE.Mesh(new THREE.CircleGeometry(R, 60, 0, Math.PI*0.30),
    new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), transparent: true, opacity: 0.14,
      side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
  sect.rotation.x = -Math.PI/2; sweep.add(sect);
  const edge = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0.05,0), new THREE.Vector3(R,0.05,0)]),
    new THREE.LineBasicMaterial({ color: 0xaef, transparent: true, opacity: 0.7 }));
  sweep.add(edge); scene.add(sweep);

  // radar KONTAK blipleri: tarama huzmesi aktif halka / son çarpma yönünü geçince
  const blips = [], blipGeo = new THREE.CircleGeometry(0.55, 16);
  function blip(angle, radius, color, strength) {
    if (blips.length > 40) { const o = blips.shift(); scene.remove(o.m); o.m.material.dispose(); }
    const m = new THREE.Mesh(blipGeo, new THREE.MeshBasicMaterial({ color: color.clone(), transparent: true,
      opacity: strength, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide }));
    m.rotation.x = -Math.PI/2; m.position.set(Math.cos(angle)*radius, 0.09, Math.sin(angle)*radius);
    scene.add(m); blips.push({ m, t: 0, str: strength });
  }
  const impactBearings = [];       // {angle, radius, life, cool}
  let activeBlipT = 0, activeBlipIdx = 0;

  // HEDEF KİLİDİ retikülü: çarpma noktasında genişleyip solan dikey nişangâh
  const reticles = [];
  function reticle(pos, color) {
    if (reticles.length > 12) { const o = reticles.shift(); scene.remove(o.grp); disposeObj(o.grp); }
    const grp = new THREE.Group(); grp.position.copy(pos);
    const mat = new THREE.LineBasicMaterial({ color: color.clone(), transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false });
    const ring = []; for (let k = 0; k <= 32; k++) { const a = k/32*Math.PI*2; ring.push(new THREE.Vector3(Math.cos(a), 0.05, Math.sin(a))); }
    grp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(ring), mat));
    const ticks = []; [[1,0],[-1,0],[0,1],[0,-1]].forEach((d) => { ticks.push(new THREE.Vector3(d[0]*0.6,0.05,d[1]*0.6), new THREE.Vector3(d[0]*1.4,0.05,d[1]*1.4)); });
    grp.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(ticks), mat));
    grp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0), new THREE.Vector3(0,4.5,0)]), mat)); // dikey kilit
    scene.add(grp); reticles.push({ grp, mat, t: 0 });
  }

  /* ---------- reaktör çekirdek ---------- */
  const coreG = new THREE.Group(); scene.add(coreG);
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(1.5, 1),
    new THREE.MeshBasicMaterial({ color: C_GREEN.clone(), wireframe: true, transparent: true, opacity: 0.95 }));
  const coreGlow = new THREE.Mesh(new THREE.SphereGeometry(1.0, 16, 16),
    new THREE.MeshBasicMaterial({ color: 0xbdffce, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending }));
  coreG.add(core); coreG.add(coreGlow);

  /* ---------- katman halkaları + okunaklı etiketler ---------- */
  let layers = [];
  let ringMeshes = [], labels = [];

  function labelTexture(name, count, color) {
    const c = document.createElement("canvas"); c.width = 320; c.height = 68;
    const x = c.getContext("2d");
    // arka plaka
    x.fillStyle = "rgba(4,10,16,0.72)";
    if (x.roundRect) { x.beginPath(); x.roundRect(2, 8, 316, 52, 9); x.fill(); }
    else x.fillRect(2, 8, 316, 52);
    x.strokeStyle = `rgba(${color.r*255|0},${color.g*255|0},${color.b*255|0},0.85)`;
    x.lineWidth = 2; if (x.roundRect){ x.beginPath(); x.roundRect(2,8,316,52,9); x.stroke(); }
    // sayı
    x.font = "800 30px 'JetBrains Mono', monospace"; x.textBaseline = "middle";
    x.fillStyle = `rgb(${color.r*255|0},${color.g*255|0},${color.b*255|0})`;
    x.fillText(String(count), 16, 35);
    // isim
    x.font = "600 19px 'JetBrains Mono', monospace"; x.fillStyle = "rgba(226,240,250,0.96)";
    x.fillText(String(name).slice(0, 20), 16 + x.measureText(String(count)).width + 14, 35);
    const tex = new THREE.CanvasTexture(c); tex.needsUpdate = true; return tex;
  }

  function buildLayers() {
    ringMeshes.forEach(r => { scene.remove(r.mesh); if (r.mesh.geometry) r.mesh.geometry.dispose(); if (r.mesh.material) r.mesh.material.dispose();
      if (r.glow) { scene.remove(r.glow); r.glow.geometry.dispose(); r.glow.material.dispose(); } });
    labels.forEach(l => { scene.remove(l.sprite); scene.remove(l.leader);
      if (l.sprite.material.map) l.sprite.material.map.dispose(); l.sprite.material.dispose();
      l.leader.geometry.dispose(); l.leader.material.dispose(); });
    ringMeshes = []; labels = [];
    const n = layers.length || 1;
    layers.forEach((layer, i) => {
      const rr = Math.max(1.6, (layer.radius || (1 - i/n)) * R);
      const col = rgb(layer.color);
      // aktif halkalar belirgin kalın (tube), pasif halkalar zayıf
      const mesh = new THREE.Mesh(new THREE.TorusGeometry(rr, layer.active ? 0.17 : 0.05, 10, 120),
        new THREE.MeshBasicMaterial({ color: col.clone(), transparent: true,
          opacity: layer.active ? 0.66 : 0.12, blending: THREE.AdditiveBlending, depthWrite: false }));
      mesh.rotation.x = -Math.PI/2; scene.add(mesh);
      // aktif halkaya hâle tüpü (glow)
      let glow = null;
      if (layer.active) {
        glow = new THREE.Mesh(new THREE.TorusGeometry(rr, 0.36, 8, 120),
          new THREE.MeshBasicMaterial({ color: col.clone(), transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending, depthWrite: false }));
        glow.rotation.x = -Math.PI/2; scene.add(glow);
      }
      ringMeshes.push({ mesh, glow, layer, baseColor: col.clone() });

      // etiket: bearing eşit dağıt; iç halkalar için yarıçapı aç (okunaklılık)
      const ang = (i / n) * Math.PI*2;
      const lr = Math.max(rr, 8.5);
      const tex = labelTexture(layer.name || layer.id, layer.interceptions || 0, col);
      const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
      spr.scale.set(7.4, 1.57, 1);
      spr.position.set(Math.cos(ang)*lr, 1.4 + (i % 4)*0.7, Math.sin(ang)*lr);
      scene.add(spr);
      // lider çizgi: etiketten gerçek halkaya
      const leader = new THREE.Line(new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(Math.cos(ang)*lr, 0.3, Math.sin(ang)*lr),
        new THREE.Vector3(Math.cos(ang)*rr, 0.1, Math.sin(ang)*rr)]),
        new THREE.LineBasicMaterial({ color: col.clone(), transparent: true, opacity: layer.active?0.4:0.16 }));
      scene.add(leader);
      labels.push({ sprite: spr, leader, layer, lastCount: layer.interceptions || 0 });
    });
  }

  /* ---------- saldırı ışınları (kalkandan dalar) ---------- */
  const shots = [], bursts = [], TRAIL_N = 28;
  function fire(p) {
    if (shots.length > 28) { const o = shots.shift(); scene.remove(o.head); scene.remove(o.headGlow); scene.remove(o.trail);
      o.trail.geometry.dispose(); o.trail.material.dispose(); o.head.geometry.dispose(); o.head.material.dispose(); o.headGlow.material.dispose(); }
    const layer = layers.find(l => l.id === p.intercepted_by);
    const targetR = layer ? layer.radius * R : 1.4;
    const col = rgb((layer && layer.color) || "255,80,80");
    const hot = col.clone().lerp(C_RED, alarm*0.55);        // yüksek alarmda kırmızıya çal
    const ip = p.source_ip || ""; let h = 0;
    for (let i = 0; i < ip.length; i++) h = (h*31 + ip.charCodeAt(i))|0;
    const angle = (Math.abs(h)%3600)/3600 * Math.PI*2;
    // başlangıç: kalkan yüzeyinde yüksek bir nokta
    const el = Math.PI*0.34;
    const start = new THREE.Vector3(Math.cos(angle)*Math.cos(el)*R, Math.sin(el)*R, Math.sin(angle)*Math.cos(el)*R);
    // parlak additive baş + yumuşak hâle
    const head = new THREE.Mesh(new THREE.SphereGeometry(0.38, 10, 10),
      new THREE.MeshBasicMaterial({ color: new THREE.Color(0xffffff).lerp(C_RED, alarm*0.4), transparent: true, blending: THREE.AdditiveBlending }));
    const headGlow = new THREE.Mesh(new THREE.SphereGeometry(0.85, 12, 12),
      new THREE.MeshBasicMaterial({ color: hot.clone(), transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending, depthWrite: false }));
    scene.add(head); scene.add(headGlow);
    // uzun, incelen (tapered) parlayan iz — vertex renkleriyle
    const tPos = new Float32Array(TRAIL_N*3), tCol = new Float32Array(TRAIL_N*3);
    for (let k = 0; k < TRAIL_N; k++) { const f = 1 - k/(TRAIL_N-1), cc = hot.clone().multiplyScalar(f*f);
      tCol[k*3] = cc.r; tCol[k*3+1] = cc.g; tCol[k*3+2] = cc.b; }
    const tGeo = new THREE.BufferGeometry();
    tGeo.setAttribute("position", new THREE.BufferAttribute(tPos,3));
    tGeo.setAttribute("color", new THREE.BufferAttribute(tCol,3));
    const trail = new THREE.Line(tGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending }));
    scene.add(trail);
    shots.push({ head, headGlow, trail, tPos, tLen: 0, angle, start, u: 0, targetR, color: col, spd: 0.02 });
    shieldHit(angle, C_BLUE.clone().lerp(C_RED, 0.3));
    alarmTarget = 1; clearTimeout(window.__dome3dAlarmT);
    window.__dome3dAlarmT = setTimeout(() => { alarmTarget = 0; }, 2400);
  }
  function burst(pos, color) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.2, 0.55, 28),
      new THREE.MeshBasicMaterial({ color: color.clone(), transparent: true, opacity: 0.95,
        side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
    m.rotation.x = -Math.PI/2; m.position.copy(pos); scene.add(m); bursts.push({ m, t: 0 });
  }

  /* ---------- İHLAL TATBİKATI (kalkanı delen sızıntı senaryosu) ----------
     NOT: Bu bir SİMÜLASYON / TATBİKAT'tır. Savunmanın tespit/skorlama/SOAR
     motorlarına DOKUNMAZ; yalnızca komuta merkezinin ihlal TEPKİSİNİ görsel
     olarak test eder: koordineli bir saldırı kalkanı deler, çekirdeğe sızıntı
     olur (kırmızı kriz + kalkan çatlaması + sarsıntı), sonra çevrelenir. */
  let breachT = 0;                 // 0..1 kriz yoğunluğu (yavaşça söner)
  const breachRings = [];          // çekirdekten yayılan şok dalgaları
  function coreShock() {
    breachT = 1;
    for (let k = 0; k < 3; k++) {
      const m = new THREE.Mesh(new THREE.RingGeometry(0.3, 0.7, 40),
        new THREE.MeshBasicMaterial({ color: C_RED.clone(), transparent: true, opacity: 0.9,
          side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
      m.rotation.x = -Math.PI/2; m.position.set(0, 0.1, 0);
      scene.add(m); breachRings.push({ m, t: -k*0.2 });
    }
    // çekirdekten yükselen kırmızı enerji sütunu (sızıntı hüzmesi)
    const col = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 1.6, R*1.25, 18, 1, true),
      new THREE.MeshBasicMaterial({ color: 0xff5a4a, transparent: true, opacity: 0.5,
        side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
    col.position.set(0, R*0.55, 0); scene.add(col); breachRings.push({ m: col, t: 0, pillar: true });
  }
  function fireBreach(angle, delay) {
    setTimeout(() => {
      const start = surfacePos(angle, Math.PI*0.40, R*1.03);
      const head = new THREE.Mesh(new THREE.SphereGeometry(0.62, 12, 12),
        new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, blending: THREE.AdditiveBlending }));
      const headGlow = new THREE.Mesh(new THREE.SphereGeometry(1.5, 14, 14),
        new THREE.MeshBasicMaterial({ color: C_RED.clone(), transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false }));
      scene.add(head); scene.add(headGlow);
      const tPos = new Float32Array(TRAIL_N*3), tCol = new Float32Array(TRAIL_N*3);
      for (let k = 0; k < TRAIL_N; k++) { const f = 1 - k/(TRAIL_N-1); tCol[k*3]=1*f; tCol[k*3+1]=0.24*f; tCol[k*3+2]=0.18*f; }
      const tGeo = new THREE.BufferGeometry();
      tGeo.setAttribute("position", new THREE.BufferAttribute(tPos,3));
      tGeo.setAttribute("color", new THREE.BufferAttribute(tCol,3));
      const trail = new THREE.Line(tGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 1, blending: THREE.AdditiveBlending }));
      scene.add(trail);
      shots.push({ head, headGlow, trail, tPos, tLen: 0, angle, start, u: 0, targetR: 0.25, color: C_RED.clone(), spd: 0.03, breach: true });
      shieldHit(angle, C_RED.clone());
      shieldFracture(angle, C_RED.clone());
    }, delay);
  }
  function triggerBreach() {
    alarmTarget = 1;
    clearTimeout(window.__dome3dBreachT);
    window.__dome3dBreachT = setTimeout(() => { alarmTarget = 0; }, 9000);
    const N = 9;                             // 9 vektörlü eş zamanlı barajı
    for (let k = 0; k < N; k++) fireBreach((k / N) * Math.PI*2 + 0.2, k * 110);
  }
  window.addEventListener("arachne:breach", triggerBreach);

  /* ---------- veri ---------- */
  let seen = new Set(), first = true;
  function update(dome) {
    if (!dome) return;
    const nl = dome.layers || [];
    const sig = nl.map(l => l.id + ":" + (l.active?1:0)).join("|");
    if (sig !== update._sig) { layers = nl; update._sig = sig; buildLayers(); }
    else {
      layers = nl;
      labels.forEach(ls => {
        const cur = (layers.find(l => l.id === ls.layer.id) || {}).interceptions || 0;
        if (cur !== ls.lastCount) { ls.lastCount = cur;
          ls.sprite.material.map = labelTexture(ls.layer.name || ls.layer.id, cur, rgb(ls.layer.color));
          ls.sprite.material.needsUpdate = true; }
      });
    }
    const inc = dome.projectiles || [];
    if (first) { inc.slice(0,8).forEach((p,i)=>setTimeout(()=>fire(p), i*160)); inc.forEach(p=>seen.add(p.id)); first=false; return; }
    inc.filter(p=>!seen.has(p.id)).forEach((p,i)=>{ seen.add(p.id); setTimeout(()=>fire(p), i*110); });
    if (seen.size > 4000) seen = new Set(inc.map(p=>p.id));
  }

  function resize() {
    const w = canvas.clientWidth || 900, h = canvas.clientHeight || 700;
    renderer.setSize(w, h, false); camera.aspect = w/h; camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);
  window.addEventListener("arachne:attack", () => { alarmTarget = 1;
    clearTimeout(window.__dome3dAlarmT2); window.__dome3dAlarmT2 = setTimeout(()=>{alarmTarget=0;}, 2400); });

  let t = 0;
  function frame() {
    t += 0.016;
    alarm += (alarmTarget - alarm) * 0.06;

    // kamera: yavaş yörünge + eğim
    const orbit = t * 0.045, cr = 42, cy = 30;
    camera.position.set(Math.sin(orbit)*cr, cy, Math.cos(orbit)*cr);
    camera.lookAt(0, 3, 0);

    // KALKAN: mavi <-> kırmızı, nabız, alarmda çok belirgin (daha güçlü kayma + alarm nabzı)
    const scMix = Math.min(1, alarm*1.15);
    const sc = C_BLUE.clone().lerp(C_RED, scMix);
    const breathe = 0.5 + 0.5*Math.sin(t*1.5);
    const alarmPulse = alarm * (0.5 + 0.5*Math.sin(t*6));   // alarmda hızlı, belirgin nabız
    shieldWire.material.color.copy(sc);
    shieldWire.material.opacity = 0.18 + breathe*0.10 + alarm*0.35 + alarmPulse*0.16;
    shieldGlow.material.color.copy(sc);
    shieldGlow.material.opacity = 0.05 + alarm*0.24 + breathe*0.03 + alarmPulse*0.10;
    shieldWire2.material.color.copy(C_CYAN.clone().lerp(C_RED, scMix));
    shieldWire2.material.opacity = 0.07 + alarm*0.18 + (0.5+0.5*Math.sin(t*2.2 - 1.0))*0.05; // hafif shimmer
    baseRing.material.color.copy(sc);
    baseRing.material.opacity = 0.6 + alarm*0.4 + alarmPulse*0.2;
    // enlem/boylam aksanları: yavaş shimmer, renk kalkanı takip eder
    shieldAccent.children.forEach((c, idx) => {
      const sh = 0.5 + 0.5*Math.sin(t*1.2 + idx*0.9);
      c.material.opacity = 0.05 + sh*0.09 + alarm*0.12 + alarmPulse*0.06;
      c.material.color.copy(sc.clone().lerp(C_CYAN, 0.30*(1-alarm)));
    });
    shield.rotation.y += 0.0009 + alarm*0.002;

    // sweep
    sweep.rotation.y -= 0.013;
    const sweepBearing = norm(-sweep.rotation.y);

    // çekirdek
    const pulse = 1 + Math.sin(t*3)*0.14; coreG.scale.setScalar(pulse);
    core.rotation.y += 0.02; core.rotation.x += 0.009;
    coreGlow.material.opacity = 0.55 + Math.sin(t*3)*0.2;

    // halkalar: aktif = güçlü nabız + hâle tüpü; pasif = zayıf/kısık
    ringMeshes.forEach((r,i) => {
      if (r.layer.active) {
        const pw = 0.5 + 0.5*Math.sin(t*2 + i*0.4);
        r.mesh.material.opacity = 0.54 + pw*0.20 + alarm*0.22;
        r.mesh.material.color.copy(r.baseColor.clone().lerp(C_RED, alarm*0.6));
        if (r.glow) { r.glow.material.opacity = 0.10 + pw*0.12 + alarm*0.14;
          r.glow.material.color.copy(r.baseColor.clone().lerp(C_RED, alarm*0.6)); }
      } else {
        r.mesh.material.opacity = 0.11 + alarm*0.05;
        r.mesh.material.color.copy(r.baseColor.clone().lerp(C_RED, alarm*0.25));
      }
    });

    // radar KONTAK blipleri
    for (let i = impactBearings.length-1; i >= 0; i--) {
      const ib = impactBearings[i]; ib.life -= 0.004;
      if (ib.life <= 0) { impactBearings.splice(i,1); continue; }
      if (t > ib.cool && angDiff(ib.angle, sweepBearing) < 0.05) {
        blip(ib.angle, ib.radius, C_CYAN.clone().lerp(C_RED, alarm*0.7), 0.85*ib.life + 0.15);
        ib.cool = t + 0.45;
      }
    }
    // aktif halkalar tarama kenarında hafif kontak parıltısı (throttle + döngü)
    if (t > activeBlipT) {
      activeBlipT = t + 0.15;
      const act = ringMeshes.filter(r => r.layer.active);
      if (act.length) {
        const r = act[activeBlipIdx % act.length]; activeBlipIdx++;
        const rr = Math.max(1.6, (r.layer.radius || 0.5) * R);
        blip(sweepBearing, rr, r.baseColor.clone().lerp(C_RED, alarm*0.5), 0.32 + alarm*0.15);
      }
    }
    for (let i = blips.length-1; i >= 0; i--) {
      const bl = blips[i]; bl.t += 0.06; const s = 1 + bl.t*1.6; bl.m.scale.set(s,s,s);
      bl.m.material.opacity = (1-bl.t)*bl.str; if (bl.t >= 1) { scene.remove(bl.m); bl.m.material.dispose(); blips.splice(i,1); }
    }

    // saldırı ışınları: start(kalkan yüzeyi) -> hedef halka (yay çizerek)
    for (let i = shots.length-1; i >= 0; i--) {
      const s = shots[i]; s.u += s.spd;
      const end = new THREE.Vector3(Math.cos(s.angle)*s.targetR, 0.12, Math.sin(s.angle)*s.targetR);
      const pos = s.start.clone().lerp(end, s.u);
      pos.y += Math.sin(s.u*Math.PI)*3;   // hafif yay
      s.head.position.copy(pos); s.headGlow.position.copy(pos);
      const arr = s.tPos;
      for (let k = arr.length-1; k >= 3; k--) arr[k] = arr[k-3];
      arr[0]=pos.x; arr[1]=pos.y; arr[2]=pos.z;
      s.tLen = Math.min(TRAIL_N, s.tLen+1); s.trail.geometry.setDrawRange(0, s.tLen);
      s.trail.geometry.attributes.position.needsUpdate = true;
      if (s.u >= 1) {
        const impCol = s.breach ? C_RED.clone() : s.color.clone().lerp(C_RED, alarm*0.6);
        if (s.breach) { coreShock(); burst(new THREE.Vector3(0,0.1,0), C_RED.clone()); }  // çekirdeğe sızıntı!
        burst(end, impCol);                                  // mevcut patlama dalgası
        shieldFracture(s.angle, s.breach ? C_RED.clone() : C_BLUE.clone().lerp(C_RED, 0.35 + alarm*0.5)); // hex kalkan çatlağı + yerel flaş
        reticle(end, impCol);                                // hedef kilidi retikülü
        impactBearings.push({ angle: s.angle, radius: s.targetR, life: 1, cool: 0 }); // kontak izi
        if (impactBearings.length > 24) impactBearings.shift();
        scene.remove(s.head); scene.remove(s.headGlow); scene.remove(s.trail);
        s.head.geometry.dispose(); s.head.material.dispose(); s.headGlow.geometry.dispose(); s.headGlow.material.dispose();
        s.trail.geometry.dispose(); s.trail.material.dispose();
        shots.splice(i,1);
      }
    }
    for (let i = bursts.length-1; i >= 0; i--) {
      const b = bursts[i]; b.t += 0.04; const s = 1 + b.t*12; b.m.scale.set(s,s,s);
      b.m.material.opacity = (1-b.t)*0.95; if (b.t>=1) { scene.remove(b.m); b.m.geometry.dispose(); b.m.material.dispose(); bursts.splice(i,1); }
    }
    for (let i = shieldHits.length-1; i >= 0; i--) {
      const sh = shieldHits[i]; sh.t += 0.03; const s = 1 + sh.t*6; sh.mesh.scale.set(s,s,s);
      sh.mesh.material.opacity = (1-sh.t)*0.8; if (sh.t>=1) { scene.remove(sh.mesh); sh.mesh.geometry.dispose(); sh.mesh.material.dispose(); shieldHits.splice(i,1); }
    }
    // hex kalkan çatlakları: kısa süreli genişleyip solar; disk hızlı flaşlar
    for (let i = shieldFractures.length-1; i >= 0; i--) {
      const fr = shieldFractures[i]; fr.t += 0.05;
      const cs = 1 + fr.t*0.5; fr.seg.scale.set(cs,cs,cs);
      fr.seg.material.opacity = (1-fr.t)*0.95;
      fr.disc.material.opacity = Math.max(0, 0.55 - fr.t*1.4);  // ani parlama, hızlı sön
      const ds = 1 + fr.t*1.2; fr.disc.scale.set(ds,ds,ds);
      if (fr.t >= 1) { scene.remove(fr.grp); disposeObj(fr.grp); shieldFractures.splice(i,1); }
    }
    // hedef kilidi retikülleri: genişleyip solar
    for (let i = reticles.length-1; i >= 0; i--) {
      const rt = reticles[i]; rt.t += 0.045;
      const rs = 0.4 + rt.t*1.9; rt.grp.scale.set(rs, 1, rs);
      rt.mat.opacity = (1-rt.t)*0.9;
      if (rt.t >= 1) { scene.remove(rt.grp); disposeObj(rt.grp); reticles.splice(i,1); }
    }

    // ---- İHLAL kriz durumu: çekirdek kızarır, kamera sarsılır, kalkan delinir ----
    if (breachT > 0.001) {
      breachT = Math.max(0, breachT - 0.006);
      const shake = breachT * 0.9;
      camera.position.x += Math.sin(t*47) * shake;
      camera.position.y += Math.cos(t*41) * shake;
      coreGlow.material.color.copy(new THREE.Color(0xff3020));
      coreGlow.material.opacity = 0.6 + Math.abs(Math.sin(t*20))*0.4*breachT + breachT*0.3;
      core.material.color.copy(C_RED.clone());
      coreG.scale.setScalar((1 + Math.sin(t*3)*0.14) * (1 + breachT*0.8));
      shieldWire.material.color.copy(C_RED.clone());
      shieldWire.material.opacity = 0.10 + Math.abs(Math.sin(t*9))*0.28*breachT;  // "delik" titreşimi
    } else {
      core.material.color.copy(C_GREEN.clone());
      coreGlow.material.color.copy(new THREE.Color(0xbdffce));
    }
    for (let i = breachRings.length-1; i >= 0; i--) {
      const br = breachRings[i]; br.t += 0.02;
      if (br.t < 0) continue;
      if (br.pillar) { br.m.material.opacity = Math.max(0, 0.5 - br.t*0.9); br.m.scale.y = 1 + br.t*0.35; }
      else { const s = 1 + br.t*38; br.m.scale.set(s,1,s); br.m.material.opacity = Math.max(0, 1-br.t)*0.9; }
      if (br.t >= 1) { scene.remove(br.m); if (br.m.geometry) br.m.geometry.dispose(); br.m.material.dispose(); breachRings.splice(i,1); }
    }

    renderer.render(scene, camera);
    requestAnimationFrame(frame);
  }

  window.__DOME3D = true;
  window.ArachneDome3D = { update, fire, alarm(on){ alarmTarget = on ? 1 : 0; }, breach: triggerBreach };
  resize();
  requestAnimationFrame(frame);
})();
