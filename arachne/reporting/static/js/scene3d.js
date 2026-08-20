/* ============================================================
   ARACHNE SENTINEL — Faz 54-56 (v2): CANLI 3D KOMUTA ARKA PLANI

   Gerçek SCADA / mimic-wall hissi: tüm arayüzün ARKASINDA sürekli
   çalışan, PARLAK mavi, 3B canlı bir sahne:
     • dönen tel-kafes çekirdek küre (komuta reaktörü)
     • 3B AĞ GRAFİĞİ — düğümler + kenarlar; kenarlarda AKAN veri darbeleri
       (yaşayan bir şema/mimic panosu gibi)
     • perspektif enerji ızgarası (zemin) + ufuk parıltısı
     • yoğun parçacık alanı (cyan yıldız tozu)
     • dönen tarama halkaları
   Saldırı (arachne:attack) gelince tüm sahne KIRMIZI-ALARM'a döner.

   Paneller cam (saydam) olduğu için bu sahne HER sayfanın altından
   canlı canlı görünür. Salt kozmetik; THREE/WebGL yoksa devre dışı kalır.
   ============================================================ */
(function () {
  "use strict";
  if (typeof THREE === "undefined") return;
  const canvas = document.getElementById("scene3d");
  if (!canvas) return;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  } catch (e) { return; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  document.body.classList.add("gl3d");

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x030c16, 0.020);
  const camera = new THREE.PerspectiveCamera(62, 1, 0.1, 500);
  camera.position.set(0, 8, 46);

  const C_BLUE = new THREE.Color(0x2aa8e8);
  const C_CYAN = new THREE.Color(0x35e0d0);
  const C_RED = new THREE.Color(0xff3b45);
  const C_AMBER = new THREE.Color(0xff8a2f);
  let alarm = 0, alarmTarget = 0;
  const mix = (base, hot) => base.clone().lerp(hot, alarm);

  /* ---------- parçacık alanı (yoğun, parlak) ---------- */
  const P_COUNT = 2200;
  const pGeo = new THREE.BufferGeometry();
  const pPos = new Float32Array(P_COUNT * 3);
  const pSpd = new Float32Array(P_COUNT);
  for (let i = 0; i < P_COUNT; i++) {
    pPos[i*3] = (Math.random()-0.5)*180;
    pPos[i*3+1] = (Math.random()-0.5)*100;
    pPos[i*3+2] = (Math.random()-0.5)*140 - 20;
    pSpd[i] = Math.random()*0.06 + 0.02;
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
  const pMat = new THREE.PointsMaterial({ color: C_CYAN.clone(), size: 0.42,
    transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false });
  const points = new THREE.Points(pGeo, pMat);
  scene.add(points);

  /* ---------- merkez çekirdek küre ---------- */
  const core = new THREE.Mesh(
    new THREE.IcosahedronGeometry(11, 2),
    new THREE.MeshBasicMaterial({ color: C_BLUE.clone(), wireframe: true, transparent: true, opacity: 0.28 })
  );
  core.position.set(0, 3, -20);
  scene.add(core);
  const coreInner = new THREE.Mesh(
    new THREE.IcosahedronGeometry(6, 1),
    new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), wireframe: true, transparent: true, opacity: 0.22 })
  );
  coreInner.position.copy(core.position);
  scene.add(coreInner);

  /* ---------- 3B AĞ GRAFİĞİ (canlı şema) ---------- */
  const NODE_N = 42;
  const nodes = [];
  const nodeGeo = new THREE.SphereGeometry(0.5, 10, 10);
  const nodeMat = new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), transparent: true,
    opacity: 0.95, blending: THREE.AdditiveBlending });
  const nodeMesh = new THREE.InstancedMesh(nodeGeo, nodeMat, NODE_N);
  const dummy = new THREE.Object3D();
  for (let i = 0; i < NODE_N; i++) {
    const v = new THREE.Vector3(
      (Math.random()-0.5)*120, (Math.random()-0.5)*56, (Math.random()-0.5)*70 - 18);
    nodes.push({ p: v, ph: Math.random()*Math.PI*2 });
    dummy.position.copy(v); dummy.scale.setScalar(1); dummy.updateMatrix();
    nodeMesh.setMatrixAt(i, dummy.matrix);
  }
  scene.add(nodeMesh);

  // kenarlar: yakın düğümleri bağla
  const edges = [];        // {a,b}
  for (let i = 0; i < NODE_N; i++) {
    for (let j = i+1; j < NODE_N; j++) {
      if (nodes[i].p.distanceTo(nodes[j].p) < 34 && edges.length < 90) {
        if (Math.random() < 0.5) edges.push({ a: i, b: j });
      }
    }
  }
  const edgePos = new Float32Array(edges.length * 2 * 3);
  edges.forEach((e, k) => {
    const a = nodes[e.a].p, b = nodes[e.b].p;
    edgePos[k*6]=a.x; edgePos[k*6+1]=a.y; edgePos[k*6+2]=a.z;
    edgePos[k*6+3]=b.x; edgePos[k*6+4]=b.y; edgePos[k*6+5]=b.z;
  });
  const edgeGeo = new THREE.BufferGeometry();
  edgeGeo.setAttribute("position", new THREE.BufferAttribute(edgePos, 3));
  const edgeMat = new THREE.LineBasicMaterial({ color: C_BLUE.clone(), transparent: true,
    opacity: 0.30, blending: THREE.AdditiveBlending });
  const edgeLines = new THREE.LineSegments(edgeGeo, edgeMat);
  scene.add(edgeLines);

  // akan veri darbeleri (kenarlar boyunca hareket eden parlak noktalar)
  const PULSE_N = Math.min(48, edges.length);
  const pulseGeo = new THREE.BufferGeometry();
  const pulsePos = new Float32Array(PULSE_N * 3);
  pulseGeo.setAttribute("position", new THREE.BufferAttribute(pulsePos, 3));
  const pulseMat = new THREE.PointsMaterial({ color: 0x9df0ff, size: 1.1, transparent: true,
    opacity: 1, blending: THREE.AdditiveBlending, depthWrite: false });
  const pulses = new THREE.Points(pulseGeo, pulseMat);
  scene.add(pulses);
  const pulseState = [];
  for (let i = 0; i < PULSE_N; i++) {
    pulseState.push({ e: (i % edges.length), t: Math.random(), spd: 0.004 + Math.random()*0.01 });
  }

  /* ---------- perspektif enerji ızgarası ---------- */
  const grid = new THREE.GridHelper(320, 64, 0x2aa8e8, 0x113a55);
  grid.position.set(0, -26, -10);
  grid.material.transparent = true; grid.material.opacity = 0.30;
  scene.add(grid);

  /* ---------- dönen tarama halkaları ---------- */
  const rings = [];
  for (let i = 0; i < 3; i++) {
    const rm = new THREE.MeshBasicMaterial({ color: C_CYAN.clone(), transparent: true, opacity: 0,
      side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false });
    const ring = new THREE.Mesh(new THREE.RingGeometry(2, 2.4, 72), rm);
    ring.rotation.x = -Math.PI/2; ring.position.set(0, -25.5, -10);
    ring.userData.phase = i/3; scene.add(ring); rings.push(ring);
  }

  /* ---------- parallax + alarm ---------- */
  let mx = 0, my = 0;
  window.addEventListener("mousemove", (e) => {
    mx = e.clientX / window.innerWidth - 0.5;
    my = e.clientY / window.innerHeight - 0.5;
  });
  window.addEventListener("arachne:attack", () => {
    alarmTarget = 1;
    document.body.classList.add("attack-alarm");
    clearTimeout(window.__scene3dAlarmT);
    window.__scene3dAlarmT = setTimeout(() => {
      alarmTarget = 0; document.body.classList.remove("attack-alarm");
    }, 2600);
  });
  // İHLAL TATBİKATI: uzun süreli tam kırmızı kriz + ekran kırmızı vinyeti
  window.addEventListener("arachne:breach", () => {
    alarmTarget = 1;
    document.body.classList.add("attack-alarm", "breach-crisis");
    clearTimeout(window.__scene3dBreachT);
    window.__scene3dBreachT = setTimeout(() => {
      alarmTarget = 0;
      document.body.classList.remove("attack-alarm", "breach-crisis");
    }, 9000);
  });
  window.ArachneScene3D = { alarm(on){ alarmTarget = on ? 1 : 0; } };

  function resize() {
    const w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w/h; camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);
  resize();

  let t = 0;
  function frame() {
    t += 0.016;
    alarm += (alarmTarget - alarm) * 0.05;

    // renkler
    pMat.color.copy(mix(C_CYAN, C_AMBER)); pMat.opacity = 0.9;
    core.material.color.copy(mix(C_BLUE, C_RED)); core.material.opacity = 0.28 + alarm*0.2;
    coreInner.material.color.copy(mix(C_CYAN, C_RED)); coreInner.material.opacity = 0.22 + alarm*0.2;
    edgeMat.color.copy(mix(C_BLUE, C_RED)); edgeMat.opacity = 0.30 + alarm*0.25;
    nodeMat.color.copy(mix(C_CYAN, C_RED));
    grid.material.opacity = 0.30 + alarm*0.15;
    if (scene.fog) scene.fog.color.copy(mix(new THREE.Color(0x030c16), new THREE.Color(0x1a0407)));

    // parçacıklar akar
    const arr = pGeo.attributes.position.array;
    for (let i = 0; i < P_COUNT; i++) {
      arr[i*3+1] += pSpd[i] * (1 + alarm*1.6);
      if (arr[i*3+1] > 52) arr[i*3+1] = -52;
    }
    pGeo.attributes.position.needsUpdate = true;

    // çekirdek döner
    core.rotation.y += 0.0016; core.rotation.x += 0.0008;
    coreInner.rotation.y -= 0.003; coreInner.rotation.z += 0.0016;

    // düğümler hafif nabız (instanced scale)
    for (let i = 0; i < NODE_N; i++) {
      const s = 1 + Math.sin(t*2 + nodes[i].ph)*0.3 + alarm*0.4;
      dummy.position.copy(nodes[i].p); dummy.scale.setScalar(s); dummy.updateMatrix();
      nodeMesh.setMatrixAt(i, dummy.matrix);
    }
    nodeMesh.instanceMatrix.needsUpdate = true;

    // veri darbeleri kenarlar boyunca akar
    const parr = pulseGeo.attributes.position.array;
    for (let i = 0; i < PULSE_N; i++) {
      const st = pulseState[i]; st.t += st.spd * (1 + alarm*2);
      if (st.t > 1) { st.t = 0; st.e = (Math.random()*edges.length)|0; }
      const e = edges[st.e]; if (!e) continue;
      const a = nodes[e.a].p, b = nodes[e.b].p;
      parr[i*3]   = a.x + (b.x-a.x)*st.t;
      parr[i*3+1] = a.y + (b.y-a.y)*st.t;
      parr[i*3+2] = a.z + (b.z-a.z)*st.t;
    }
    pulseGeo.attributes.position.needsUpdate = true;
    pulseMat.color.copy(alarm > 0.4 ? C_RED.clone() : new THREE.Color(0x9df0ff));

    // tarama halkaları
    rings.forEach((ring) => {
      ring.userData.phase = (ring.userData.phase + 0.004) % 1;
      const s = 1 + ring.userData.phase * 34; ring.scale.set(s, s, s);
      ring.material.opacity = (1 - ring.userData.phase) * (0.55 + alarm*0.3);
      ring.material.color.copy(mix(C_CYAN, C_RED));
    });

    // kamera yumuşak parallax + nefes
    camera.position.x += (mx*12 - camera.position.x) * 0.03;
    camera.position.y += (8 - my*8 - camera.position.y) * 0.03;
    camera.position.z = 46 + Math.sin(t*0.18)*3;
    camera.lookAt(0, 1, -18);

    renderer.render(scene, camera);
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
