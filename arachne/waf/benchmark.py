"""
WAF ETKINLIK OLCUMU — dürüst, tekrarlanabilir bir benchmark.

Etiketli bir korpus (gercek saldiri yukleri + zararsiz istekler) HEM korumasiz
HEM korumali lab hedefinden gecirilir ve olculur:
  * yakalama orani (recall): saldirilarin yuzde kaci WAF tarafindan engellendi,
  * yanlis pozitif orani: zararsiz isteklerin yuzde kaci yanlislikla engellendi,
  * precision / F1: engelleme kararinin genel dogrulugu,
  * GERCEK deger: korumasizda GERCEKTEN calisan (exploited) saldirilardan kaci
    korumalida engellendi (uydurma yok — yukler once dogrulanir),
  * gecikme yuku: WAF acikken bir istegin ortalama ek maliyeti.

Ag gerekmez; Werkzeug test-client ile in-process olculur (deterministik).
"""
from __future__ import annotations

import time
from urllib.parse import urlencode

from . import labtarget as LT

# --- ETIKETLI KORPUS ---------------------------------------------------------
# Her saldiri gercek bir yuktur; kategori zemin-dogru etikettir. Kacinma
# (evasion) varyantlari da bilincli olarak eklenmistir.
_ATTACKS = [
    # SQL Injection
    ("SQL Injection", "/search", "name", "' OR '1'='1"),
    ("SQL Injection", "/search", "name", "' OR 1=1 --"),
    ("SQL Injection", "/search", "name", "x' UNION SELECT id, secret FROM users --"),
    ("SQL Injection", "/search", "name", "admin'; DROP TABLE users; --"),
    ("SQL Injection", "/search", "name", "' OR SLEEP(3)-- -"),
    # XSS
    ("XSS", "/comment", "text", "<script>alert(1)</script>"),
    ("XSS", "/comment", "text", "<img src=x onerror=alert(document.cookie)>"),
    ("XSS", "/comment", "text", "<svg/onload=alert(1)>"),
    ("XSS", "/comment", "text", "javascript:alert(1)"),
    # Path Traversal
    ("Path Traversal", "/file", "path", "app/public/../../etc/passwd"),
    ("Path Traversal", "/file", "path", "../../../../etc/passwd"),
    ("Path Traversal", "/file", "path", "..%2f..%2f..%2fetc%2fpasswd"),
    ("Path Traversal", "/file", "path", "app/public/../../etc/shadow"),
    # Command Injection
    ("Command Injection", "/ping", "host", "127.0.0.1; whoami"),
    ("Command Injection", "/ping", "host", "127.0.0.1 && id"),
    ("Command Injection", "/ping", "host", "127.0.0.1 | cat /etc/passwd"),
    ("Command Injection", "/ping", "host", "$(uname)"),
    ("Command Injection", "/ping", "host", "127.0.0.1`whoami`"),
    # SSTI
    ("SSTI", "/render", "name", "{{7*7}}"),
    ("SSTI", "/render", "name", "{{config}}"),
    ("SSTI", "/render", "name", "{{''.__class__.__mro__}}"),
    ("SSTI", "/render", "name", "${7*7}"),
]

# KACINMA (evasion) yukleri — gercek saldirganin denedigi atlatma teknikleri.
# Bazilari mevcut imzalarla YAKALANIR, bazilari YAKALANMAZ. Dürüstluk: bir
# WAF her seyi yakalayamaz; bu set gercek sinirlarimizi gosterir.
_EVASION = [
    # SQLi — tirnakli tautoloji (rakamsiz): mevcut regex rakam bekler -> KACAR
    ("SQL Injection", "/search", "name", "' OR 'a'='a"),
    # SQLi — inline yorumla parcalama: UNI/**/ON -> KACABILIR
    ("SQL Injection", "/search", "name", "x' UNI/**/ON SEL/**/ECT id,secret FROM users--"),
    # XSS — nadir olay isleyici (ontoggle): imza listesinde yok -> KACAR
    ("XSS", "/comment", "text", "<details open ontoggle=alert(1)>"),
    # XSS — ic ice etiket ile filtre kirma
    ("XSS", "/comment", "text", "<scr<script>ipt>alert(1)</scr</script>ipt>"),
    # Command Injection — yeni-satir ile enjeksiyon (metachar degil) -> KACABILIR
    ("Command Injection", "/ping", "host", "127.0.0.1\nwhoami"),
    # Path Traversal — CIFT kodlama (%252e): tek unquote coz(m)ez -> KACAR
    ("Path Traversal", "/file", "path", "app/public/%252e%252e/%252e%252e/etc/passwd"),
    # SSTI — bosluklu suslu parantez
    ("SSTI", "/render", "name", "{{ 7 * 7 }}"),
]

# Zararsiz istekler — WAF bunlari GECIRMELI (yanlis pozitif olcumu icin).
_BENIGN = [
    ("/search", "name", "emirhan"),
    ("/search", "name", "arkadasi"),
    ("/search", "name", "Ali Veli"),
    ("/comment", "text", "Merhaba, bu proje cok guzel olmus!"),
    ("/comment", "text", "1 < 2 ve 3 > 2 dogru mudur?"),        # < > var ama zararsiz
    ("/comment", "text", "Fiyat 100 TL, indirim %20"),
    ("/file", "path", "app/public/welcome.txt"),
    ("/file", "path", "app/public/logo.txt"),
    ("/ping", "host", "127.0.0.1"),
    ("/ping", "host", "example.com"),
    ("/render", "name", "dunya"),
    ("/render", "name", "Emirhan Baydere"),
    ("/", None, None),
]


def _url(path, param, value):
    if not param:
        return path
    return path + "?" + urlencode({param: value})


def _timed_get(client, url, src_ip, repeat=1):
    """Istegi (repeat kez) verilen kaynak IP'den atar; (status, body, ort_ms).

    NOT: her korpus ogesine AYRI kaynak IP verilir. Boylece imza tespiti,
    IP-basina rate-limit katmanindan yalitilarak olculur (tek IP'den arka arkaya
    onlarca istek rate-limit'i tetikler — bu ayri bir savunma katmanidir ve
    imza dogrulugunu golgelememeli). Rate-limit ayrica test edilir."""
    base = {"REMOTE_ADDR": src_ip}
    t0 = time.perf_counter()
    r = None
    for _ in range(repeat):
        r = client.get(url, environ_base=base)
    dt = (time.perf_counter() - t0) / repeat * 1000.0
    return r.status_code, r.get_data(as_text=True), dt


def run(db_path=None, block_threshold: int = 50, latency_repeat: int = 5) -> dict:
    """Benchmark'i calistirir ve GERCEK olculerle bir sozluk doner."""
    if db_path is not None:
        from .. import storage
        storage.init_db(db_path)          # WAF olaylari icin sema hazir olsun
    unprot = LT.build(protected=False).test_client()
    prot = LT.build(protected=True, db_path=db_path,
                    block_threshold=block_threshold).test_client()

    per_cat = {}   # kategori -> sayaclar
    items = []     # her istegin detayi
    lat_prot, lat_unprot = [], []

    # --- saldirilar --- (her saldiri ayri "saldirgan" IP'sinden)
    tier_stats = {"temel": {"total": 0, "blocked": 0}, "kacinma": {"total": 0, "blocked": 0}}
    all_attacks = [(c, p, pa, pl, "temel") for (c, p, pa, pl) in _ATTACKS] + \
                  [(c, p, pa, pl, "kacinma") for (c, p, pa, pl) in _EVASION]
    for i, (cat, path, param, payload, tier) in enumerate(all_attacks):
        url = _url(path, param, payload)
        ip = f"198.51.100.{i + 1}"      # TEST-NET-2 (RFC 5737)
        us, ub, ut = _timed_get(unprot, url, ip, latency_repeat)
        ps, pb, pt = _timed_get(prot, url, ip, latency_repeat)
        lat_unprot.append(ut); lat_prot.append(pt)
        exploited = LT.attack_succeeded(cat, us, ub, payload)   # korumasizda calisti mi
        blocked = (ps == 403)                                   # WAF engelledi mi
        c = per_cat.setdefault(cat, {"total": 0, "exploited": 0, "blocked": 0,
                                     "prevented": 0})
        c["total"] += 1
        c["exploited"] += int(exploited)
        c["blocked"] += int(blocked)
        c["prevented"] += int(exploited and blocked)   # GERCEK deger
        tier_stats[tier]["total"] += 1
        tier_stats[tier]["blocked"] += int(blocked)
        items.append({"kind": "attack", "category": cat, "payload": payload,
                      "tier": tier, "exploited_unprotected": exploited,
                      "blocked_by_waf": blocked})

    # --- zararsiz ---
    benign_total = 0
    benign_blocked = 0   # yanlis pozitif
    for j, (path, param, value) in enumerate(_BENIGN):
        url = _url(path, param, value)
        ip = f"203.0.113.{j + 1}"       # TEST-NET-3 (RFC 5737) — mesru kullanicilar
        _u, _ub, ut = _timed_get(unprot, url, ip, latency_repeat)
        ps, pb, pt = _timed_get(prot, url, ip, latency_repeat)
        lat_unprot.append(ut); lat_prot.append(pt)
        blocked = (ps == 403)
        benign_total += 1
        benign_blocked += int(blocked)
        items.append({"kind": "benign", "category": "benign",
                      "payload": value, "blocked_by_waf": blocked})

    # --- metrikler ---
    attacks_total = sum(c["total"] for c in per_cat.values())
    attacks_blocked = sum(c["blocked"] for c in per_cat.values())
    attacks_exploited = sum(c["exploited"] for c in per_cat.values())
    attacks_prevented = sum(c["prevented"] for c in per_cat.values())

    tp = attacks_blocked                      # dogru engellenen saldiri
    fp = benign_blocked                       # yanlislikla engellenen zararsiz
    fn = attacks_total - attacks_blocked      # kacan saldiri
    recall = tp / attacks_total if attacks_total else 0.0
    fp_rate = fp / benign_total if benign_total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    # korumasizda GERCEKTEN calisan saldirilardan kaci onlendi (en dürüst oran)
    prevention_rate = attacks_prevented / attacks_exploited if attacks_exploited else 0.0

    avg_prot = sum(lat_prot) / len(lat_prot) if lat_prot else 0.0
    avg_unprot = sum(lat_unprot) / len(lat_unprot) if lat_unprot else 0.0

    return {
        "totals": {
            "attacks": attacks_total, "attacks_blocked": attacks_blocked,
            "attacks_exploited_unprotected": attacks_exploited,
            "attacks_prevented": attacks_prevented,
            "benign": benign_total, "benign_blocked_false_positive": benign_blocked,
            "false_negatives": fn,
        },
        "metrics": {
            "recall_detection_rate": round(recall, 4),
            "false_positive_rate": round(fp_rate, 4),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
            "real_attack_prevention_rate": round(prevention_rate, 4),
        },
        "latency_ms": {
            "protected_avg": round(avg_prot, 4),
            "unprotected_avg": round(avg_unprot, 4),
            "overhead_avg": round(avg_prot - avg_unprot, 4),
        },
        "per_category": {k: dict(v) for k, v in per_cat.items()},
        "by_tier": {
            "temel": {**tier_stats["temel"],
                      "recall": round(tier_stats["temel"]["blocked"] / tier_stats["temel"]["total"], 4)
                      if tier_stats["temel"]["total"] else 0.0},
            "kacinma": {**tier_stats["kacinma"],
                        "recall": round(tier_stats["kacinma"]["blocked"] / tier_stats["kacinma"]["total"], 4)
                        if tier_stats["kacinma"]["total"] else 0.0},
        },
        "items": items,
        "config": {"block_threshold": block_threshold, "latency_repeat": latency_repeat},
    }


def summary_lines(result: dict) -> list[str]:
    m, t = result["metrics"], result["totals"]
    lat = result["latency_ms"]
    tier = result["by_tier"]
    out = [
        f"Saldiri yakalama (recall)      : {m['recall_detection_rate']*100:.1f}%  "
        f"({t['attacks_blocked']}/{t['attacks']})",
        f"  - temel yukler               : {tier['temel']['recall']*100:.1f}%  "
        f"({tier['temel']['blocked']}/{tier['temel']['total']})",
        f"  - kacinma (evasion) yukler   : {tier['kacinma']['recall']*100:.1f}%  "
        f"({tier['kacinma']['blocked']}/{tier['kacinma']['total']})  <- gercek sinir",
        f"Gercek-saldiri onleme          : {m['real_attack_prevention_rate']*100:.1f}%  "
        f"({t['attacks_prevented']}/{t['attacks_exploited_unprotected']} calisan saldiri onlendi)",
        f"Yanlis pozitif (zararsiz blok) : {m['false_positive_rate']*100:.1f}%  "
        f"({t['benign_blocked_false_positive']}/{t['benign']})",
        f"Precision / F1                 : {m['precision']:.3f} / {m['f1']:.3f}",
        f"Gecikme yuku (WAF)             : +{lat['overhead_avg']:.3f} ms/istek "
        f"({lat['unprotected_avg']:.3f} -> {lat['protected_avg']:.3f})",
    ]
    return out


if __name__ == "__main__":
    res = run()
    print("=== ARACHNE WAF ETKINLIK OLCUMU ===")
    for line in summary_lines(res):
        print(" ", line)
    print("\nKategori bazinda:")
    for cat, c in res["per_category"].items():
        print(f"  {cat:20} yakalama {c['blocked']}/{c['total']}  "
              f"(calisan {c['exploited']}, onlenen {c['prevented']})")
