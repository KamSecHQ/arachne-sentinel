/* Kayitli demo (arachnesentinel.com/panel/) - sunucusuz komuta merkezi.
 *
 * GitHub Pages sunucu calistiramaz. Panelin /api/* istekleri burada,
 * gercek bir lab calismasindan alinmis anlik goruntu dosyalarina
 * (scripts/snapshot_panel.py) yonlendirilir. Veri uydurulmaz; sunucu
 * gerektiren eylemler demoda kapali oldugunu acikca soyler.
 */
(function () {
  "use strict";
  var realFetch = window.fetch.bind(window);
  var SNAPSHOT = {
    "/api/state": "api/state.json",
    "/api/live": "api/live.json",
    "/api/deep": "api/deep.json",
    "/api/intel": "api/intel.json",
    "/api/fortress": "api/fortress.json",
    "/api/fortress/engage": "api/fortress.json",
    "/api/fortress/standby": "api/fortress.json",
  };
  var OFF = "Bu kayıtlı demoda kapalı — sunucu gerektirir. Kendi kurulumunuzda " +
            "(python main.py dashboard) ya da GitHub Codespaces'te tam çalışır.";
  var answers = null;

  function json(obj) {
    return Promise.resolve(new Response(JSON.stringify(obj), {
      status: 200, headers: { "Content-Type": "application/json" },
    }));
  }

  function pathOf(input) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    try { return new URL(url, location.href).pathname; } catch (e) { return url; }
  }

  window.fetch = function (input, opts) {
    var raw = typeof input === "string" ? input : (input && input.url) || "";
    var path = raw.charAt(0) === "/" ? raw.split("?")[0] : pathOf(input);

    if (SNAPSHOT[path]) return realFetch(SNAPSHOT[path], { cache: "no-store" });

    if (path === "/api/analyze") return json({ error: OFF });

    if (path === "/api/assistant") {
      var q = "";
      try { q = JSON.parse((opts && opts.body) || "{}").question || ""; } catch (e) {}
      var load = answers ? Promise.resolve(answers)
        : realFetch("api/assistant.json").then(function (r) { return r.json(); })
            .then(function (a) { answers = a; return a; });
      return load.then(function (a) {
        if (a[q]) return json(a[q]);
        var msg = "Kayıtlı demoda asistan yalnızca alttaki hazır soruları yanıtlar " +
                  "(kayıtlı lab verisiyle). Serbest soru için kendi kurulumunuzu kullanın.";
        return json({ text_tr: msg, spoken_tr: msg });
      }).catch(function () { return json({ text_tr: OFF, spoken_tr: OFF }); });
    }

    return realFetch(input, opts);
  };
})();
