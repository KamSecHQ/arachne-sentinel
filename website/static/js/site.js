  // Hero canvas: concentric interception rings, echoing the product's own
  // Çelik Kubbe visualization. An attack dot approaches and is caught at a
  // ring; a soft flash marks the interception. Loops slowly, ambient only.
  (function(){
    var canvas = document.getElementById('dome');
    if (!canvas) return;
    var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var ctx = canvas.getContext('2d');
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var size = 420;
    canvas.width = size * dpr; canvas.height = size * dpr;
    ctx.scale(dpr, dpr);
    var cx = size / 2, cy = size / 2;
    var ringCount = 11;
    var maxR = size * 0.47;
    var silk = '#52ddc7', ember = '#f0824a', thread = '#25324a';

    function ring(i){ return (i + 1) / ringCount * maxR; }

    // ambient dust — small static specks scattered between rings, purely
    // atmospheric, gives the dome a "live sensor field" feel at rest.
    var dust = [];
    (function seedDust(){
      var n = 46;
      for (var i = 0; i < n; i++){
        var a = Math.random() * Math.PI * 2;
        var r = maxR * (0.15 + Math.random() * 0.85);
        dust.push({ a: a, r: r, s: 0.5 + Math.random() * 1.1, ph: Math.random() * Math.PI * 2 });
      }
    })();

    // multiple projectiles fired on staggered schedules at different
    // rings/angles, so the dome reads as continuously active rather than
    // one lone dot looping — matches "many simultaneous events" reality.
    var projectiles = [
      { angle: -Math.PI / 2.4, hitRing: 3, period: 3400, offset: 0 },
      { angle: Math.PI / 6, hitRing: 6, period: 4600, offset: 1300 },
      { angle: Math.PI * 0.95, hitRing: 1, period: 5200, offset: 2600 },
      { angle: -Math.PI * 0.7, hitRing: 8, period: 6100, offset: 800 }
    ];
    var flashes = projectiles.map(function(){ return 0; });

    var t = 0;
    var rot = 0;

    function frame(){
      ctx.clearRect(0, 0, size, size);

      // slow outer-ring rotation dashes — a living sensor sweep, not a
      // static diagram
      rot += 0.0016;

      // rings
      for (var i = 0; i < ringCount; i++){
        var r = ring(i);
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = thread;
        ctx.lineWidth = 1;
        ctx.globalAlpha = i % 3 === 0 ? 0.95 : 0.55;
        if (i >= ringCount - 3){
          ctx.setLineDash([2, 5]);
          ctx.lineDashOffset = -rot * 60 * (i - ringCount + 4);
        } else {
          ctx.setLineDash([]);
        }
        ctx.stroke();
      }
      ctx.setLineDash([]);

      // ambient dust specks (gentle twinkle)
      for (var d = 0; d < dust.length; d++){
        var sp = dust[d];
        var tw = 0.35 + 0.35 * Math.sin(t * 0.0012 + sp.ph);
        var dx = cx + Math.cos(sp.a) * sp.r;
        var dy = cy + Math.sin(sp.a) * sp.r;
        ctx.beginPath();
        ctx.arc(dx, dy, sp.s, 0, Math.PI * 2);
        ctx.fillStyle = silk;
        ctx.globalAlpha = tw * 0.4;
        ctx.fill();
      }

      // core, with a soft breathing halo
      var breathe = 0.85 + 0.15 * Math.sin(t * 0.0022);
      ctx.beginPath();
      ctx.arc(cx, cy, 13 * breathe, 0, Math.PI * 2);
      ctx.fillStyle = silk;
      ctx.globalAlpha = 0.14;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      ctx.fillStyle = silk;
      ctx.globalAlpha = 0.95;
      ctx.fill();

      // projectiles
      for (var p = 0; p < projectiles.length; p++){
        var proj = projectiles[p];
        var cyc = (((t + proj.offset) % proj.period) / proj.period);
        var travel = Math.min(cyc / 0.72, 1);
        var startR = maxR + 20;
        var targetR = ring(proj.hitRing);
        var r2 = startR - (startR - targetR) * easeOutCubic(travel);
        var px = cx + Math.cos(proj.angle) * r2;
        var py = cy + Math.sin(proj.angle) * r2;

        if (travel >= 1 && flashes[p] < 1) flashes[p] += 0.06;
        if (cyc > 0.85) flashes[p] = Math.max(0, flashes[p] - 0.08);
        if (cyc < 0.02) flashes[p] = 0;

        if (travel < 1){
          ctx.beginPath();
          ctx.arc(px, py, 3.2, 0, Math.PI * 2);
          ctx.fillStyle = ember;
          ctx.globalAlpha = 1;
          ctx.fill();
          ctx.beginPath();
          ctx.moveTo(px, py);
          var tailR = r2 + 16;
          ctx.lineTo(cx + Math.cos(proj.angle) * tailR, cy + Math.sin(proj.angle) * tailR);
          ctx.strokeStyle = ember;
          ctx.globalAlpha = 0.32;
          ctx.lineWidth = 1.3;
          ctx.stroke();
        }

        if (flashes[p] > 0){
          ctx.beginPath();
          ctx.arc(cx, cy, targetR, 0, Math.PI * 2);
          ctx.strokeStyle = silk;
          ctx.globalAlpha = flashes[p] * 0.85;
          ctx.lineWidth = 2.2;
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(cx + Math.cos(proj.angle) * targetR, cy + Math.sin(proj.angle) * targetR, 5 + flashes[p] * 6, 0, Math.PI * 2);
          ctx.fillStyle = silk;
          ctx.globalAlpha = flashes[p] * 0.45;
          ctx.fill();
        }
      }

      ctx.globalAlpha = 1;
    }

    function easeOutCubic(x){ return 1 - Math.pow(1 - x, 3); }

    if (reduceMotion){
      t = 2600; frame();
      return;
    }
    var last = performance.now();
    function loop(now){
      t += Math.min(now - last, 48);
      last = now;
      frame();
      requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);
  })();

  // Command-center preview: cycles a soft highlight across the sample feed
  // lines, one at a time, so the illustrative panel reads as "live" rather
  // than a static screenshot. Purely decorative — no real event data.
  (function(){
    var lines = document.querySelectorAll('.console-feed .feed-line');
    if (!lines.length) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var i = 0;
    lines[0].classList.add('active');
    setInterval(function(){
      lines[i].classList.remove('active');
      i = (i + 1) % lines.length;
      lines[i].classList.add('active');
    }, 1800);
  })();
