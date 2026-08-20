/* ============================================================
   ARACHNE SENTINEL — Faz 71: SİNEMATİK 3B AÇILIŞ / GÜÇ EKRANI

   #boot overlay'inin İÇİNE kendi saydam WebGL canvas'ını enjekte eder
   ve ışıklı, sinematik bir "reaktör çekirdeği" sahnesi kurar:
     • çok katmanlı dönen enerji çekirdeği (iç içe tel-kafes ikosahedron
       + dönen torus enerji halkaları), additive glow + nabız
     • yörüngede dönen enerji parçacıkları (cyan yıldız tozu)
     • hacimsel hâle (backside küre) + fresnel-vari kenar parıltısı
     • hafif kamera parallax + yavaş yörünge (derinlik hissi)

   API (window.ArachneBoot3D):
     • ignite()      → güç tuşuna basınca: çekirdek maviden parlak beyaza
                        "ısınır", halkalar hızlanır, enerji dalgası yayılır
     • setLevel(0..1)→ boot ilerlemesine göre yoğunluğu artırır
     • stop()        → rAF iptal + renderer temizle (boot kapanınca)

   HARD KURAL: salt kozmetik. THREE/WebGL yoksa sessizce devre dışı kalır;
   #boot yoksa erken çıkar; hiçbir global'i kirletmez (IIFE).
   ============================================================ */
(function () {
  "use strict";

  // ---- Sert güvenlik kapıları --------------------------------------------
  if (typeof THREE === "undefined") return;          // Three.js yoksa çık
  const boot = document.getElementById("boot");
  if (!boot) return;                                 // açılış overlay'i yoksa çık

  // ---- Kendi saydam canvas'ımızı #boot İÇİNE enjekte et ------------------
  // z-index: #boot-canvas (0) ile boot-ui (3) arasında → 1. pointer-events yok.
  const canvas = document.createElement("canvas");
  canvas.id = "boot3d-canvas";
  canvas.style.cssText =
    "position:absolute;inset:0;width:100%;height:100%;display:block;" +
    "z-index:1;pointer-events:none;";
  // #boot-canvas'tan hemen sonra yerleştir (varsa), yoksa başa ekle.
  const anchor = document.getElementById("boot-canvas");
  if (anchor && anchor.parentNode === boot) {
    boot.insertBefore(canvas, anchor.nextSibling);
  } else {
    boot.insertBefore(canvas, boot.firstChild);
  }

  // ---- Renderer (saydam) --------------------------------------------------
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  } catch (e) {
    canvas.remove();
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);   // tamamen saydam arka plan

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 200);
  camera.position.set(0, 0, 34);

  // Güç düğmesi ~%42 yükseklikte; çekirdeği onun ardına hizala (yukarı kaydır).
  const rig = new THREE.Group();
  rig.position.y = 3.0;
  scene.add(rig);

  // ---- Renk paleti --------------------------------------------------------
  const C_BLUE = new THREE.Color(0x1e78e6);   // derin enerji mavisi
  const C_CYAN = new THREE.Color(0x35e0ff);   // parlak cyan
  const C_WHITE = new THREE.Color(0xffffff);  // beyaz-sıcak (ignite)

  // ısı (ignite) ve seviye (boot ilerleme) durumları
  let heat = 0, heatTarget = 0;      // 0=mavi soğuk, 1=beyaz sıcak
  let level = 0.28, levelTarget = 0.28; // genel yoğunluk (0..1)
  let spin = 1, spinTarget = 1;      // halka/çekirdek dönüş çarpanı

  // heat'e göre çekirdek rengi: mavi → cyan → beyaz
  function hotColor(target, warm) {
    const c = C_BLUE.clone().lerp(C_CYAN, Math.min(1, warm * 1.4));
    return target.copy(c).lerp(C_WHITE, heat);
  }

  // ---- Fresnel / halo shader (kenar parıltısı + hacimsel hâle) -----------
  const FRESNEL_VERT = [
    "varying vec3 vNormal;",
    "varying vec3 vView;",
    "void main(){",
    "  vNormal = normalize(normalMatrix * normal);",
    "  vec4 mv = modelViewMatrix * vec4(position,1.0);",
    "  vView = normalize(-mv.xyz);",
    "  gl_Position = projectionMatrix * mv;",
    "}"
  ].join("\n");
  const FRESNEL_FRAG = [
    "uniform vec3 uColor;",
    "uniform float uIntensity;",
    "uniform float uPower;",
    "varying vec3 vNormal;",
    "varying vec3 vView;",
    "void main(){",
    "  float f = 1.0 - abs(dot(normalize(vNormal), normalize(vView)));",
    "  f = pow(clamp(f, 0.0, 1.0), uPower);",
    "  gl_FragColor = vec4(uColor * f * uIntensity, f * uIntensity);",
    "}"
  ].join("\n");

  function fresnelMat(color, power, side) {
    return new THREE.ShaderMaterial({
      uniforms: {
        uColor: { value: color.clone() },
        uIntensity: { value: 1.0 },
        uPower: { value: power }
      },
      vertexShader: FRESNEL_VERT,
      fragmentShader: FRESNEL_FRAG,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      side: side || THREE.FrontSide
    });
  }

  // ---- Hacimsel hâle: büyük backside küre (fresnel) -----------------------
  const haloMat = fresnelMat(C_CYAN, 2.6, THREE.BackSide);
  const halo = new THREE.Mesh(new THREE.SphereGeometry(12, 40, 40), haloMat);
  rig.add(halo);

  // ---- Çekirdek kenar parıltısı: frontside fresnel küre -------------------
  const rimMat = fresnelMat(C_CYAN, 3.2, THREE.FrontSide);
  const rim = new THREE.Mesh(new THREE.SphereGeometry(6.4, 40, 40), rimMat);
  rig.add(rim);

  // ---- Çok katmanlı dönen tel-kafes ikosahedronlar ------------------------
  const shells = [];
  function addShell(radius, detail, color, opacity, dx, dy, dz) {
    const mat = new THREE.MeshBasicMaterial({
      color: color.clone(), wireframe: true, transparent: true,
      opacity: opacity, blending: THREE.AdditiveBlending, depthWrite: false
    });
    const m = new THREE.Mesh(new THREE.IcosahedronGeometry(radius, detail), mat);
    m.userData = { dx: dx, dy: dy, dz: dz, baseOp: opacity };
    rig.add(m); shells.push(m); return m;
  }
  addShell(7.4, 1, C_BLUE, 0.35, 0.0011, 0.0016, 0.0);
  addShell(5.6, 2, C_CYAN, 0.32, -0.0018, 0.0026, 0.0009);
  addShell(3.9, 1, C_CYAN, 0.42, 0.0032, -0.0022, 0.0014);

  // ---- Parlak iç çekirdek (additive, nabız) -------------------------------
  const coreMat = new THREE.MeshBasicMaterial({
    color: C_CYAN.clone(), transparent: true, opacity: 0.9,
    blending: THREE.AdditiveBlending, depthWrite: false
  });
  const coreMesh = new THREE.Mesh(new THREE.IcosahedronGeometry(2.0, 1), coreMat);
  rig.add(coreMesh);

  // ---- Dönen torus enerji halkaları (farklı eksenlerde) -------------------
  const rings = [];
  function addRing(radius, tube, color, opacity, rx, ry, spd, axis) {
    const mat = new THREE.MeshBasicMaterial({
      color: color.clone(), transparent: true, opacity: opacity,
      blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide
    });
    const m = new THREE.Mesh(new THREE.TorusGeometry(radius, tube, 12, 90), mat);
    m.rotation.x = rx; m.rotation.y = ry;
    m.userData = { spd: spd, axis: axis || "z", baseOp: opacity };
    rig.add(m); rings.push(m); return m;
  }
  addRing(8.2, 0.10, C_CYAN, 0.55, Math.PI / 2, 0, 0.010, "z");
  addRing(9.4, 0.07, C_BLUE, 0.40, Math.PI / 2.4, 0.5, -0.007, "z");
  addRing(10.6, 0.05, C_CYAN, 0.32, Math.PI / 1.7, 1.1, 0.006, "y");

  // ---- Yörüngede dönen enerji parçacıkları --------------------------------
  const P_COUNT = 520;
  const pGeo = new THREE.BufferGeometry();
  const pPos = new Float32Array(P_COUNT * 3);
  const orbit = [];   // {r, a, tilt, spd, y0}
  for (let i = 0; i < P_COUNT; i++) {
    const r = 6 + Math.random() * 7.5;
    const a = Math.random() * Math.PI * 2;
    const tilt = (Math.random() - 0.5) * 0.9;
    const spd = (0.004 + Math.random() * 0.014) * (Math.random() < 0.5 ? 1 : -1);
    orbit.push({ r: r, a: a, tilt: tilt, spd: spd, y0: (Math.random() - 0.5) * 3 });
    pPos[i * 3] = Math.cos(a) * r;
    pPos[i * 3 + 1] = Math.sin(a) * r * tilt;
    pPos[i * 3 + 2] = Math.sin(a) * r;
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
  const pMat = new THREE.PointsMaterial({
    color: 0x9df0ff, size: 0.34, transparent: true, opacity: 0.95,
    blending: THREE.AdditiveBlending, depthWrite: false
  });
  const particles = new THREE.Points(pGeo, pMat);
  rig.add(particles);

  // ---- Enerji dalgası (ignite'te dışa yayılan halka) ----------------------
  const waveMat = new THREE.MeshBasicMaterial({
    color: C_WHITE.clone(), transparent: true, opacity: 0,
    blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide
  });
  const wave = new THREE.Mesh(new THREE.RingGeometry(1.0, 1.35, 96), waveMat);
  wave.rotation.x = 0;   // ekrana bakan halka
  rig.add(wave);
  let waveT = -1;   // <0 = pasif; 0..1 = yayılıyor

  // ---- Etkileşim: kamera parallax -----------------------------------------
  let mx = 0, my = 0;
  function onMove(e) {
    mx = e.clientX / window.innerWidth - 0.5;
    my = e.clientY / window.innerHeight - 0.5;
  }
  window.addEventListener("mousemove", onMove);

  // ---- Boyutlandırma ------------------------------------------------------
  function resize() {
    const w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);
  resize();

  // ---- Animasyon döngüsü --------------------------------------------------
  let raf = 0, running = true, t = 0;
  const cCore = new THREE.Color(), cCyanTmp = new THREE.Color();

  function frame() {
    if (!running) return;
    t += 0.016;

    // durumları yumuşat
    heat += (heatTarget - heat) * 0.04;
    level += (levelTarget - level) * 0.05;
    spin += (spinTarget - spin) * 0.05;

    const pulse = 0.5 + 0.5 * Math.sin(t * 2.4);
    const warm = level;                     // 0..1 yoğunluk
    const glow = 0.5 + warm * 0.9 + heat * 0.6;

    // çekirdek rengi (mavi→cyan→beyaz) ve nabız
    hotColor(cCore, warm);
    coreMat.color.copy(cCore);
    coreMat.opacity = (0.55 + pulse * 0.35) * (0.6 + warm * 0.6);
    const cs = 1 + pulse * 0.28 + heat * 0.5;
    coreMesh.scale.setScalar(cs);
    coreMesh.rotation.y += 0.02 * spin;
    coreMesh.rotation.x += 0.013 * spin;

    // hâle + rim renk/yoğunluk
    hotColor(cCyanTmp, warm);
    haloMat.uniforms.uColor.value.copy(cCyanTmp);
    haloMat.uniforms.uIntensity.value = (0.35 + warm * 0.55 + heat * 0.6);
    rimMat.uniforms.uColor.value.copy(cCyanTmp);
    rimMat.uniforms.uIntensity.value = (0.5 + warm * 0.7 + heat * 0.8) * (0.85 + pulse * 0.3);
    const hs = 1 + heat * 0.14 + pulse * 0.02;
    halo.scale.setScalar(hs); rim.scale.setScalar(1 + heat * 0.1);

    // tel-kafes kabuklar döner + ısıya göre parlar
    for (let i = 0; i < shells.length; i++) {
      const s = shells[i], u = s.userData;
      s.rotation.x += u.dx * spin;
      s.rotation.y += u.dy * spin;
      s.rotation.z += u.dz * spin;
      s.material.color.copy(hotColor(s.material.color, warm));
      s.material.opacity = u.baseOp * (0.6 + warm * 0.7 + heat * 0.4);
    }

    // torus enerji halkaları döner
    for (let i = 0; i < rings.length; i++) {
      const r = rings[i], u = r.userData;
      if (u.axis === "y") r.rotation.y += u.spd * spin;
      else r.rotation.z += u.spd * spin;
      r.material.color.copy(hotColor(r.material.color, warm));
      r.material.opacity = u.baseOp * (0.5 + warm * 0.8 + heat * 0.5);
    }

    // yörünge parçacıkları akar
    const arr = pGeo.attributes.position.array;
    for (let i = 0; i < P_COUNT; i++) {
      const o = orbit[i];
      o.a += o.spd * spin;
      arr[i * 3] = Math.cos(o.a) * o.r;
      arr[i * 3 + 1] = Math.sin(o.a) * o.r * o.tilt + o.y0;
      arr[i * 3 + 2] = Math.sin(o.a) * o.r;
    }
    pGeo.attributes.position.needsUpdate = true;
    pMat.opacity = 0.5 + warm * 0.45 + heat * 0.2;
    pMat.size = 0.28 + warm * 0.18 + heat * 0.14;
    pMat.color.copy(C_CYAN.clone().lerp(C_WHITE, heat));

    // enerji dalgası (ignite'te dışa yayılır)
    if (waveT >= 0) {
      waveT += 0.022;
      const s = 1 + waveT * 26;
      wave.scale.set(s, s, s);
      waveMat.opacity = Math.max(0, (1 - waveT)) * 0.9;
      if (waveT >= 1) { waveT = -1; waveMat.opacity = 0; }
    }

    // hâle katmanı global parlaklık (opsiyonel yumuşatma)
    void glow;

    // kamera yumuşak parallax + yavaş yörünge (derinlik)
    camera.position.x += (mx * 6 - camera.position.x) * 0.03;
    camera.position.y += ((-my * 4) - camera.position.y) * 0.03;
    camera.position.z = 34 + Math.sin(t * 0.15) * 2.2 - heat * 3.5;
    camera.lookAt(0, rig.position.y, 0);

    renderer.render(scene, camera);
    raf = requestAnimationFrame(frame);
  }
  raf = requestAnimationFrame(frame);

  // ---- Genel API ----------------------------------------------------------
  window.ArachneBoot3D = {
    // güç tuşuna basınca: ısın, hızlan, enerji dalgası yay
    ignite: function () {
      heatTarget = 1;
      spinTarget = 2.6;
      levelTarget = Math.max(levelTarget, 0.6);
      waveT = 0;                    // dalgayı başlat
      waveMat.opacity = 0.9;
    },
    // boot ilerlemesine göre yoğunluk (0..1)
    setLevel: function (x) {
      x = +x;
      if (isNaN(x)) return;
      levelTarget = Math.max(0, Math.min(1, x));
      // ilerledikçe dönüşü de hafif artır (ignite yoksa da canlı görünüm)
      if (spinTarget < 1.8) spinTarget = 1 + levelTarget * 0.8;
    },
    // boot kapanınca: döngüyü durdur + renderer temizle
    stop: function () {
      if (!running) return;
      running = false;
      cancelAnimationFrame(raf);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", resize);
      try { renderer.dispose(); } catch (e) {}
      try { if (canvas.parentNode) canvas.parentNode.removeChild(canvas); } catch (e) {}
    }
  };
})();
