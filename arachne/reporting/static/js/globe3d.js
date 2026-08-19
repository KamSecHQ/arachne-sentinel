/* ============================================================
   ARACHNE SENTINEL — Faz 64: MÜHENDİSLİK HARİKASI 3B DÜNYA

   Faz 55'in dönen dünya küresini derinleştirir:
     • gündüz/gece hissi: güneş yönlü ışığı + terminatör, gece
       tarafında prosedürel ŞEHİR IŞIKLARI parıltısı (additive, shader)
     • saldırı yayları artık PARLAYAN HÜZME: kalın additive tüp +
       parlak akan baş + kısa sönen kuyruk; önem rengine göre; alarmda güçlenir
     • saldırgan düğümlerinde nabız atan HÂLE halkası (kritik/çok olayda büyür)
     • önem→renk göstergesi (kritik/yüksek/orta/düşük/engelli) köşede sprite
     • parlatılmış enlem/boylam ızgarası + net atmosfer kenarı (fresnel rim)
     • yeni saldırgan gelince o bölge öne döner, düğüm anlık büyür (bloom),
       bölge etiketi parlar — yumuşak geçiş

   DÜRÜSTLÜK: konumlar çevrimdışı RIR (bölge) tahminidir; şehir hassasiyeti
   iddia edilmez (gece ışıkları yalnızca kozmetik, coğrafi iddia değildir).
   THREE/WebGL yoksa 2B haritaya düşülür (window.__GLOBE3D=false).
   Tüm dokular prosedürel/çevrimdışı; dış varlık yok. Geometri sayısı sınırlı.
   ============================================================ */
(function () {
  "use strict";
  window.__GLOBE3D = false;
  if (typeof THREE === "undefined") return;
  const canvas = document.getElementById("map-canvas");
  if (!canvas) return;
  let renderer;
  try { renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true }); }
  catch (e) { return; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200);
  camera.position.set(0, 3, 30);
  scene.add(camera); // kamera-bağlı gösterge sprite'ı için

  // GÜNEŞ: yönlü ışık — belirgin terminatör oluşturur
  const SUN_DIR = new THREE.Vector3(-1, 0.6, 1.2).normalize();
  const sun = new THREE.DirectionalLight(0xdff0ff, 1.42);
  sun.position.copy(SUN_DIR);
  scene.add(sun);
  scene.add(new THREE.AmbientLight(0x24384a, 0.5)); // gece tarafı tamamen kararmasın ama koyu kalsın

  const Rg = 9;
  let alarm = 0, alarmTarget = 0;

  const MAX_ARCS = 16;     // 60fps için tavan
  const TAIL_N = 4;        // hüzme kuyruğu segment sayısı

  /* ---------- kıta poligonları (kaba; offline, GeoJSON yok) ---------- */
  const LAND = [
    [[-168,66],[-158,71],[-130,70],[-95,70],[-80,73],[-60,60],[-55,50],[-65,45],[-70,42],[-75,35],[-81,25],[-97,26],[-107,23],[-115,30],[-124,40],[-125,48],[-135,57],[-150,60],[-168,66]],
    [[-81,10],[-72,12],[-60,5],[-50,0],[-35,-6],[-38,-16],[-48,-25],[-58,-35],[-63,-42],[-70,-52],[-75,-50],[-73,-40],[-71,-30],[-70,-18],[-77,-6],[-81,10]],
    [[-17,15],[0,15],[15,12],[32,15],[43,12],[51,12],[42,-2],[40,-15],[35,-24],[25,-34],[18,-34],[12,-18],[9,-1],[5,5],[-8,5],[-17,15]],
    [[-10,36],[-9,44],[-2,48],[2,51],[5,53],[8,55],[11,58],[18,60],[24,60],[30,60],[40,58],[40,48],[36,45],[28,41],[23,38],[15,38],[12,45],[3,43],[-10,36]],
    [[40,58],[60,62],[80,65],[100,68],[120,70],[140,68],[145,60],[142,50],[135,45],[128,38],[121,32],[110,20],[100,12],[95,17],[88,22],[80,10],[72,20],[62,25],[55,28],[48,30],[45,40],[40,48],[40,58]],
    [[113,-22],[122,-18],[131,-12],[142,-11],[147,-18],[153,-27],[150,-37],[141,-38],[131,-32],[123,-34],[115,-34],[113,-22]],
  ];

  const projTex = (lon, lat, W, H) => [ (lon+180)/360*W, (90-lat)/180*H ];
  function inPoly(lon, lat, poly) {
    let inside = false;
    for (let i = 0, j = poly.length-1; i < poly.length; j = i++) {
      const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
      const inter = ((yi > lat) !== (yj > lat)) && (lon < (xj-xi)*(lat-yi)/(yj-yi) + xi);
      if (inter) inside = !inside;
    }
    return inside;
  }

  function buildEarthTexture() {
    const W = 2048, H = 1024, c = document.createElement("canvas"); c.width = W; c.height = H;
    const x = c.getContext("2d");
    // okyanus
    const g = x.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, "#0a2036"); g.addColorStop(0.5, "#0c2a44"); g.addColorStop(1, "#081826");
    x.fillStyle = g; x.fillRect(0, 0, W, H);
    // enlem/boylam ızgarası (parlatıldı)
    x.strokeStyle = "rgba(96,158,198,0.24)"; x.lineWidth = 1.15;
    for (let lon = -180; lon <= 180; lon += 20) { const px = (lon+180)/360*W; x.beginPath(); x.moveTo(px,0); x.lineTo(px,H); x.stroke(); }
    for (let lat = -80; lat <= 80; lat += 20) { const py = (90-lat)/180*H; x.beginPath(); x.moveTo(0,py); x.lineTo(W,py); x.stroke(); }
    // ekvator biraz daha belirgin
    x.strokeStyle = "rgba(120,200,235,0.30)"; x.lineWidth = 1.6;
    x.beginPath(); x.moveTo(0,H/2); x.lineTo(W,H/2); x.stroke();
    // kıtalar
    LAND.forEach(poly => {
      x.beginPath();
      poly.forEach(([lon,lat], i) => { const [px,py] = projTex(lon,lat,W,H); if (i===0) x.moveTo(px,py); else x.lineTo(px,py); });
      x.closePath();
      const lg = x.createLinearGradient(0,0,0,H);
      lg.addColorStop(0, "rgba(34,120,110,0.92)"); lg.addColorStop(1, "rgba(26,90,84,0.92)");
      x.fillStyle = lg; x.fill();
      x.strokeStyle = "rgba(90,230,210,0.60)"; x.lineWidth = 2.2; x.stroke();
    });
    const tex = new THREE.CanvasTexture(c); tex.needsUpdate = true; tex.anisotropy = 4; return tex;
  }

  /* ---------- gece şehir ışıkları dokusu (prosedürel, offline) ---------- */
  function buildNightTexture() {
    const W = 2048, H = 1024, c = document.createElement("canvas"); c.width = W; c.height = H;
    const x = c.getContext("2d");
    x.clearRect(0, 0, W, H); // şeffaf zemin
    let count = 0; const MAX = 540;
    LAND.forEach(poly => {
      let minx = 180, maxx = -180, miny = 90, maxy = -90;
      poly.forEach(([lo,la]) => { minx=Math.min(minx,lo); maxx=Math.max(maxx,lo); miny=Math.min(miny,la); maxy=Math.max(maxy,la); });
      const want = Math.min(150, MAX - count);
      let placed = 0, tries = 0;
      while (placed < want && tries < want*10 && count < MAX) {
        tries++;
        const lo = minx + Math.random()*(maxx-minx), la = miny + Math.random()*(maxy-miny);
        if (!inPoly(lo, la, poly)) continue;
        const [px, py] = projTex(lo, la, W, H);
        const r = 0.6 + Math.random()*1.7;
        const gg = x.createRadialGradient(px, py, 0, px, py, r*3);
        gg.addColorStop(0, "rgba(255,226,150,0.95)");
        gg.addColorStop(0.5, "rgba(255,196,96,0.55)");
        gg.addColorStop(1, "rgba(255,170,70,0)");
        x.fillStyle = gg; x.beginPath(); x.arc(px, py, r*3, 0, 6.2832); x.fill();
        placed++; count++;
      }
    });
    const tex = new THREE.CanvasTexture(c); tex.needsUpdate = true; tex.anisotropy = 4; return tex;
  }

  /* ---------- küre ---------- */
  const globe = new THREE.Group(); scene.add(globe);
  const earth = new THREE.Mesh(new THREE.SphereGeometry(Rg, 64, 48),
    new THREE.MeshPhongMaterial({ map: buildEarthTexture(), shininess: 9, specular: 0x2a4e66 }));
  globe.add(earth);

  // GECE ŞEHİR IŞIKLARI: yalnızca güneşe bakmayan (karanlık) tarafta parlar
  const nightMat = new THREE.ShaderMaterial({
    uniforms: {
      lights: { value: buildNightTexture() },
      sunDir: { value: SUN_DIR.clone() },
      alarm:  { value: 0 },
    },
    vertexShader: [
      "varying vec2 vUv;",
      "varying vec3 vWorldNormal;",
      "void main(){",
      "  vUv = uv;",
      "  vWorldNormal = mat3(modelMatrix) * normal;",
      "  gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0);",
      "}"
    ].join("\n"),
    fragmentShader: [
      "uniform sampler2D lights;",
      "uniform vec3 sunDir;",
      "uniform float alarm;",
      "varying vec2 vUv;",
      "varying vec3 vWorldNormal;",
      "void main(){",
      "  vec4 tx = texture2D(lights, vUv);",
      "  float night = clamp(-dot(normalize(vWorldNormal), normalize(sunDir)), 0.0, 1.0);",
      "  night = smoothstep(0.02, 0.42, night);",
      "  vec3 col = mix(vec3(1.0,0.86,0.46), vec3(1.0,0.46,0.34), alarm);",
      "  float a = tx.a * night;",
      "  gl_FragColor = vec4(col, a);",
      "}"
    ].join("\n"),
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const night = new THREE.Mesh(new THREE.SphereGeometry(Rg*1.003, 64, 48), nightMat);
  globe.add(night);

  // enlem/boylam tel kafes (parlatıldı)
  const ggrid = new THREE.Mesh(new THREE.SphereGeometry(Rg*1.002, 36, 24),
    new THREE.MeshBasicMaterial({ color: 0x2aa8e8, wireframe: true, transparent: true, opacity: 0.10 }));
  globe.add(ggrid);

  // atmosfer hâlesi (geniş, yumuşak)
  const atmo = new THREE.Mesh(new THREE.SphereGeometry(Rg*1.14, 48, 32),
    new THREE.MeshBasicMaterial({ color: 0x2aa8e8, transparent: true, opacity: 0.14, side: THREE.BackSide, blending: THREE.AdditiveBlending }));
  scene.add(atmo);

  // NET KENAR (fresnel rim): kürenin siluetini keskin okutur
  const rimMat = new THREE.ShaderMaterial({
    uniforms: { glowColor: { value: new THREE.Color(0x5cc8ff) }, power: { value: 3.4 } },
    vertexShader: [
      "varying vec3 vNormal;",
      "void main(){",
      "  vNormal = normalize(normalMatrix * normal);",
      "  gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0);",
      "}"
    ].join("\n"),
    fragmentShader: [
      "varying vec3 vNormal;",
      "uniform vec3 glowColor;",
      "uniform float power;",
      "void main(){",
      "  float intensity = pow(0.72 - dot(vNormal, vec3(0.0,0.0,1.0)), power);",
      "  gl_FragColor = vec4(glowColor, 1.0) * clamp(intensity, 0.0, 1.0);",
      "}"
    ].join("\n"),
    transparent: true, depthWrite: false, side: THREE.BackSide, blending: THREE.AdditiveBlending,
  });
  const rim = new THREE.Mesh(new THREE.SphereGeometry(Rg*1.055, 48, 32), rimMat);
  scene.add(rim);

  function latLonToVec3(lat, lon, r) {
    const phi = (90 - lat) * Math.PI/180, theta = (lon + 180) * Math.PI/180;
    return new THREE.Vector3(-r*Math.sin(phi)*Math.cos(theta), r*Math.cos(phi), r*Math.sin(phi)*Math.sin(theta));
  }
  const sevColor = (n) => n.blocked ? new THREE.Color(0x94a3b8) : ({
    critical: new THREE.Color(0xff3b45), high: new THREE.Color(0xff7a45),
    medium: new THREE.Color(0xf5a623), low: new THREE.Color(0x4da3ff) }[n.severity] || new THREE.Color(0x22d3ee));

  /* ---------- önem göstergesi (legend) — kamera köşesinde sprite ---------- */
  const LEGEND = [
    ["kritik",  "#ff3b45"],
    ["yüksek",  "#ff7a45"],
    ["orta",    "#f5a623"],
    ["düşük",   "#4da3ff"],
    ["engelli", "#94a3b8"],
  ];
  function buildLegendSprite() {
    const W = 224, H = 168, c = document.createElement("canvas"); c.width = W; c.height = H;
    const x = c.getContext("2d");
    x.fillStyle = "rgba(4,10,16,0.72)";
    if (x.roundRect) { x.beginPath(); x.roundRect(1, 1, W-2, H-2, 10); x.fill(); } else x.fillRect(0,0,W,H);
    x.strokeStyle = "rgba(90,200,235,0.35)"; x.lineWidth = 1.5;
    if (x.roundRect) { x.beginPath(); x.roundRect(1, 1, W-2, H-2, 10); x.stroke(); }
    x.font = "700 15px 'JetBrains Mono',monospace"; x.textBaseline = "middle";
    x.fillStyle = "rgba(180,230,250,0.9)"; x.fillText("ÖNEM DERECESİ", 14, 20);
    LEGEND.forEach(([lbl, col], i) => {
      const y = 44 + i*24;
      x.fillStyle = col; x.beginPath(); x.arc(22, y, 7, 0, 6.2832); x.fill();
      x.fillStyle = "rgba(226,240,248,0.92)"; x.font = "600 14px 'JetBrains Mono',monospace";
      x.fillText(lbl, 40, y);
    });
    const tex = new THREE.CanvasTexture(c); tex.needsUpdate = true;
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false, depthWrite: false }));
    s.userData = { aspect: W/H };
    return s;
  }
  const legend = buildLegendSprite();
  const LEG_Z = -14, LEG_H = 2.05;   // kamera uzayında yükseklik
  legend.scale.set(LEG_H * legend.userData.aspect, LEG_H, 1);
  legend.renderOrder = 999;
  camera.add(legend);

  /* ---------- korunan varlık (İstanbul) ---------- */
  const asset = { lat: 41, lon: 29 };
  let assetPos = latLonToVec3(asset.lat, asset.lon, Rg*1.01);
  const assetMk = new THREE.Mesh(new THREE.SphereGeometry(0.16, 12, 12),
    new THREE.MeshBasicMaterial({ color: 0x22c55e }));
  assetMk.position.copy(assetPos); globe.add(assetMk);
  const assetRing = new THREE.Mesh(new THREE.RingGeometry(0.28, 0.36, 24),
    new THREE.MeshBasicMaterial({ color: 0x22c55e, transparent: true, opacity: 0.9, side: THREE.DoubleSide }));
  assetRing.position.copy(assetPos); assetRing.lookAt(0,0,0); globe.add(assetRing);

  /* ---------- düğümler + hâleler + yaylar + etiketler ---------- */
  let nodeObjs = [];   // {ip, mesh, halo, base, region, sev, ph, bloom, haloR}
  let arcs = [], labels = [];
  let seenIps = new Set(), first = true;
  let targetRotY = 0;

  function labelSprite(text, color) {
    const c = document.createElement("canvas"); c.width = 256; c.height = 48; const x = c.getContext("2d");
    x.fillStyle = "rgba(4,10,16,0.66)"; if (x.roundRect){x.beginPath();x.roundRect(0,6,256,36,8);x.fill();}
    x.font = "700 20px 'JetBrains Mono',monospace"; x.textBaseline = "middle";
    x.fillStyle = `rgb(${color.r*255|0},${color.g*255|0},${color.b*255|0})`;
    x.fillText(String(text).slice(0,18), 10, 26);
    const tex = new THREE.CanvasTexture(c); const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
    s.scale.set(4.2, 0.8, 1); s.userData = { baseScale: 4.2, baseY: 0.8, flash: 0 };
    return s;
  }

  function disposeObj(o) {
    if (!o) return;
    if (o.geometry) o.geometry.dispose();
    if (o.material) { if (o.material.map) o.material.map.dispose(); o.material.dispose(); }
  }

  /* ---------- PARLAYAN HÜZME YAYI ---------- */
  function makeArc(node) {
    if (arcs.length >= MAX_ARCS) {  // tavana varınca en eskisini düşür
      const old = arcs.shift();
      globe.remove(old.tube); disposeObj(old.tube);
      globe.remove(old.head); disposeObj(old.head);
      old.tail.forEach(tm => { globe.remove(tm); disposeObj(tm); });
    }
    const src = latLonToVec3(node.lat, node.lon, Rg*1.01);
    const mid = src.clone().add(assetPos).multiplyScalar(0.5).normalize().multiplyScalar(Rg*1.45);
    const curve = new THREE.QuadraticBezierCurve3(src, mid, assetPos.clone());
    const col = sevColor(node);

    // kalın additive tüp = parlayan hüzme gövdesi
    const tubeGeo = new THREE.TubeGeometry(curve, 48, 0.032, 6, false);
    const tube = new THREE.Mesh(tubeGeo,
      new THREE.MeshBasicMaterial({ color: col.clone(), transparent: true, opacity: 0.30, blending: THREE.AdditiveBlending, depthWrite: false }));
    globe.add(tube);

    // parlak akan baş
    const head = new THREE.Mesh(new THREE.SphereGeometry(0.11, 10, 10),
      new THREE.MeshBasicMaterial({ color: 0xdff6ff, blending: THREE.AdditiveBlending, transparent: true, depthWrite: false }));
    globe.add(head);

    // kısa sönen kuyruk (baş renginde, geriye doğru zayıflar)
    const tail = [];
    for (let k = 0; k < TAIL_N; k++) {
      const tm = new THREE.Mesh(new THREE.SphereGeometry(0.085 - k*0.014, 8, 8),
        new THREE.MeshBasicMaterial({ color: col.clone(), blending: THREE.AdditiveBlending, transparent: true, depthWrite: false, opacity: 0.5 }));
      globe.add(tm); tail.push(tm);
    }
    arcs.push({ tube, head, tail, curve, col: col.clone(), t: 0, spd: 0.012 + Math.random()*0.01, life: 0 });
  }

  function rebuild(nodes) {
    nodeObjs.forEach(o => { globe.remove(o.mesh); disposeObj(o.mesh); if (o.halo) { globe.remove(o.halo); disposeObj(o.halo); } });
    labels.forEach(l => { globe.remove(l); disposeObj(l); });
    nodeObjs = []; labels = [];
    const regionSeen = new Set();
    nodes.forEach(n => {
      if (n.lat == null || n.lon == null) return;
      const base = latLonToVec3(n.lat, n.lon, Rg*1.015);
      const col = sevColor(n);
      const r = 0.09 + Math.min(0.22, Math.log2((n.event_count||1)+1)*0.05);
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(r, 12, 12),
        new THREE.MeshBasicMaterial({ color: col.clone(), blending: THREE.AdditiveBlending, transparent: true }));
      mesh.position.copy(base); globe.add(mesh);

      // nabız atan HÂLE halkası — olay sayısı/kritiklik ile büyür
      const haloR = r * (1.7 + Math.min(1.4, Math.log2((n.event_count||1)+1)*0.18) + (n.severity==='critical'?0.5:0));
      const halo = new THREE.Mesh(new THREE.RingGeometry(haloR*0.86, haloR, 28),
        new THREE.MeshBasicMaterial({ color: col.clone(), transparent: true, opacity: 0.55, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
      halo.position.copy(base); halo.lookAt(0,0,0); globe.add(halo);

      nodeObjs.push({ ip: n.ip, mesh, halo, base, region: n.region_name || n.region, sev: n.severity, ph: Math.random()*6.28, bloom: 0, haloR });
      const rn = n.region_name || n.region;
      if (rn && !regionSeen.has(rn) && regionSeen.size < 5 && n.scope !== "loopback") {
        regionSeen.add(rn);
        const spr = labelSprite(rn, col); spr.position.copy(base.clone().multiplyScalar(1.12));
        spr.userData.region = rn; globe.add(spr); labels.push(spr);
      }
    });
  }

  function faceNode(o) {
    // düğümü kameraya (+Z) döndür: hedef rotY = π/2 - alpha
    const alpha = Math.atan2(o.base.z, o.base.x);
    targetRotY = Math.PI/2 - alpha;
  }

  function flashRegion(region) {
    labels.forEach(l => { if (l.userData.region === region) l.userData.flash = 1; });
  }

  function update(map) {
    if (!map) return;
    const nodes = map.nodes || [];
    if (map.defended_asset && (map.defended_asset.lat !== asset.lat || map.defended_asset.lon !== asset.lon)) {
      asset.lat = map.defended_asset.lat; asset.lon = map.defended_asset.lon;
      assetPos = latLonToVec3(asset.lat, asset.lon, Rg*1.01);
      assetMk.position.copy(assetPos); assetRing.position.copy(assetPos); assetRing.lookAt(0,0,0);
    }
    rebuild(nodes);
    const ids = new Set(nodes.map(n => n.ip));
    if (first) {
      nodes.slice(0,6).forEach(n => makeArc(n)); seenIps = ids; first = false;
      if (nodeObjs[0]) { faceNode(nodeObjs[0]); nodeObjs[0].bloom = 1; flashRegion(nodeObjs[0].region); }
      return;
    }
    // YENİ saldırgan -> o bölge öne dönsün + hüzme + bloom + etiket parlaması
    let newestObj = null;
    nodes.forEach(n => {
      if (!seenIps.has(n.ip)) {
        makeArc(n);
        const o = nodeObjs.find(x => x.ip === n.ip);
        if (o) { newestObj = o; o.bloom = 1; flashRegion(o.region); }
      }
    });
    if (newestObj) faceNode(newestObj);
    else if (nodes.length && Math.random() < 0.4) makeArc(nodes[(Math.random()*Math.min(nodes.length,6))|0]);
    seenIps = ids;
  }

  window.addEventListener("arachne:attack", () => { alarmTarget = 1;
    clearTimeout(window.__globeAlarmT); window.__globeAlarmT = setTimeout(()=>{alarmTarget=0;}, 2600); });

  function resize() {
    const w = canvas.clientWidth || 900, h = canvas.clientHeight || 560;
    renderer.setSize(w, h, false); camera.aspect = w/h; camera.updateProjectionMatrix();
    // göstergeyi sol-alt köşeye sabitle (kamera uzayında)
    const halfH = Math.abs(LEG_Z) * Math.tan((camera.fov * Math.PI/180) / 2);
    const halfW = halfH * camera.aspect;
    const sw = LEG_H * legend.userData.aspect, sh = LEG_H;
    legend.position.set(-halfW + sw/2 + 0.35, -halfH + sh/2 + 0.35, LEG_Z);
  }
  window.addEventListener("resize", resize);

  const RED = new THREE.Color(0xff3b45);
  const ATMO_BLUE = new THREE.Color(0x2aa8e8);
  const GRID_BLUE = new THREE.Color(0x2aa8e8);
  const RIM_BLUE = new THREE.Color(0x5cc8ff);
  let t = 0;
  function frame() {
    t += 0.016;
    alarm += (alarmTarget - alarm) * 0.05;

    // dönüş: hedefe yumuşak + sürekli hafif otomatik
    globe.rotation.y += (targetRotY - globe.rotation.y) * 0.03;
    targetRotY += 0.0015;

    // atmosfer / ızgara / kenar renkleri (alarmda kırmızıya)
    atmo.material.color.copy(ATMO_BLUE).lerp(RED, alarm);
    atmo.material.opacity = 0.14 + alarm*0.22;
    ggrid.material.color.copy(GRID_BLUE).lerp(RED, alarm);
    ggrid.material.opacity = 0.10 + alarm*0.10;
    rimMat.uniforms.glowColor.value.copy(RIM_BLUE).lerp(RED, alarm);
    nightMat.uniforms.alarm.value = alarm;

    // varlık nabzı
    const ap = 1 + Math.sin(t*3)*0.2; assetRing.scale.setScalar(ap);

    // düğüm nabzı + bloom; alarmda büyür; hâle halkaları nabız atar
    nodeObjs.forEach(o => {
      if (o.bloom > 0.001) o.bloom *= 0.93; else o.bloom = 0;
      const s = 1 + Math.sin(t*2.5 + o.ph)*0.3 + (o.sev==='critical'?alarm*0.8:alarm*0.3) + o.bloom*1.1;
      o.mesh.scale.setScalar(s);
      if (o.halo) {
        const hs = 1 + Math.sin(t*2.2 + o.ph)*0.22 + o.bloom*0.8 + alarm*0.25;
        o.halo.scale.setScalar(hs);
        o.halo.material.opacity = 0.35 + Math.sin(t*2.2 + o.ph)*0.18 + o.bloom*0.4;
      }
    });

    // etiket parlaması (yeni saldırı) — yumuşak sönüm
    labels.forEach(l => {
      if (l.userData.flash > 0.001) {
        l.userData.flash *= 0.94;
        const f = l.userData.flash;
        l.scale.set(l.userData.baseScale*(1+f*0.35), l.userData.baseY*(1+f*0.35), 1);
        l.material.opacity = 0.85 + f*0.15;
      } else if (l.userData.flash !== 0) {
        l.userData.flash = 0; l.scale.set(l.userData.baseScale, l.userData.baseY, 1); l.material.opacity = 1;
      }
    });

    // PARLAYAN HÜZME: akan baş + sönen kuyruk; alarmda güçlenir
    const boost = 1 + alarm*0.9;
    for (let i = arcs.length-1; i >= 0; i--) {
      const a = arcs[i]; a.t += a.spd;
      if (a.t <= 1) {
        a.head.visible = true; a.head.position.copy(a.curve.getPoint(a.t));
        a.head.scale.setScalar(boost);
        a.tail.forEach((tm, k) => {
          const tt = a.t - (k+1)*0.045;
          if (tt >= 0) { tm.visible = true; tm.position.copy(a.curve.getPoint(tt)); tm.material.opacity = (0.5 - k*0.11) * boost; }
          else tm.visible = false;
        });
        a.tube.material.opacity = (0.24 + 0.10*Math.sin(t*6 + i)) * boost;
      } else {
        a.head.visible = false; a.tail.forEach(tm => tm.visible = false);
        a.life += 0.02; a.tube.material.opacity = Math.max(0, (0.30 - a.life) * boost);
        if (a.life > 0.6) {
          globe.remove(a.tube); disposeObj(a.tube);
          globe.remove(a.head); disposeObj(a.head);
          a.tail.forEach(tm => { globe.remove(tm); disposeObj(tm); });
          arcs.splice(i,1);
        }
      }
    }

    renderer.render(scene, camera);
    requestAnimationFrame(frame);
  }

  window.__GLOBE3D = true;
  window.ArachneGlobe3D = { update };
  resize();
  requestAnimationFrame(frame);
})();
