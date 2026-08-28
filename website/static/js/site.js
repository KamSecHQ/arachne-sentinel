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
    var ringCount = 7;
    var maxR = size * 0.46;
    var silk = '#52ddc7', ember = '#f0824a', thread = '#25324a';

    var t = 0;
    var hitRing = 3, hitFlash = 0;
    var angle = -Math.PI / 2.4;

    function ring(i){ return (i + 1) / ringCount * maxR; }

    function frame(){
      ctx.clearRect(0, 0, size, size);

      // rings
      for (var i = 0; i < ringCount; i++){
        var r = ring(i);
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = thread;
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.9;
        ctx.stroke();
      }

      // core
      ctx.beginPath();
      ctx.arc(cx, cy, 6, 0, Math.PI * 2);
      ctx.fillStyle = silk;
      ctx.globalAlpha = 0.9;
      ctx.fill();

      // projectile path progress (0..1) loops every ~3.4s
      var cyc = (t % 3400) / 3400;
      var travel = Math.min(cyc / 0.72, 1); // reach ring then pause/reset
      var startR = maxR + 20;
      var targetR = ring(hitRing);
      var r = startR - (startR - targetR) * easeOutCubic(travel);
      var px = cx + Math.cos(angle) * r;
      var py = cy + Math.sin(angle) * r;

      if (travel >= 1 && hitFlash < 1) hitFlash += 0.06;
      if (cyc > 0.85) hitFlash = Math.max(0, hitFlash - 0.08);
      if (cyc < 0.02) hitFlash = 0;

      // projectile
      if (travel < 1){
        ctx.beginPath();
        ctx.arc(px, py, 3.4, 0, Math.PI * 2);
        ctx.fillStyle = ember;
        ctx.globalAlpha = 1;
        ctx.fill();
        // trail
        ctx.beginPath();
        ctx.moveTo(px, py);
        var tailR = r + 14;
        ctx.lineTo(cx + Math.cos(angle) * tailR, cy + Math.sin(angle) * tailR);
        ctx.strokeStyle = ember;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1.4;
        ctx.stroke();
      }

      // interception flash on the hit ring
      if (hitFlash > 0){
        ctx.beginPath();
        ctx.arc(cx, cy, targetR, 0, Math.PI * 2);
        ctx.strokeStyle = silk;
        ctx.globalAlpha = hitFlash * 0.9;
        ctx.lineWidth = 2.4;
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(cx + Math.cos(angle) * targetR, cy + Math.sin(angle) * targetR, 5 + hitFlash * 6, 0, Math.PI * 2);
        ctx.fillStyle = silk;
        ctx.globalAlpha = hitFlash * 0.5;
        ctx.fill();
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
