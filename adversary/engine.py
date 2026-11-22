"""
Kampanya motoru — saldiri yuklerini (temel + mutasyonlu) YEREL lab hedefine
gonderir ve olçer. Her istek once guvenlik kapisindan geçer (safety.py):
loopback disi hicbir hedef kabul edilmez.

Olçtukleri:
  * blocked  — WAF (korumali hedef) istegi 403 ile engelledi mi,
  * exploited — korumasiz hedefte saldiri GERCEKTEN ise yaradi mi (zemin-dogru),
  * bypassed — hem sömürülebilir HEM de WAF'i geçti (asil onemli olan bu).

In-process çalisir (ag yok, en guvenli). Alternatif olarak yalnizca loopback
bir URL'ye de gonderilebilir (attack_http).
"""
from __future__ import annotations

from urllib.parse import urlencode

from . import payloads, mutators
from .safety import assert_local_target


def build_targets(block_threshold: int = 50):
    """Arachne lab hedefini korumali + korumasiz in-process kurar.
    Ikisi de yereldir (ag yok) — guvenlik kapisi bunu dogrular."""
    from arachne.waf import labtarget as LT
    from arachne import storage
    prot = LT.build(protected=True, block_threshold=block_threshold)
    unprot = LT.build(protected=False)
    assert_local_target(prot)          # in-process WSGI -> guvenli
    assert_local_target(unprot)
    try:
        storage.init_db(None)
    except Exception:
        pass
    return prot.test_client(), unprot.test_client(), LT


def _send(client, path, param, payload, ip):
    url = path + "?" + urlencode({param: payload}) if param else path
    r = client.get(url, environ_base={"REMOTE_ADDR": ip})
    return r.status_code, r.get_data(as_text=True)


def run_campaign(block_threshold: int = 50, use_mutations: bool = True,
                 extra_payloads=None, defense=None) -> dict:
    """Bir saldiri kampanyasi yurutur (yalnizca yerel). Sonuç sozlugu doner.

    `defense` verilirse (cat, path, param, payload)->bool, engelleme karari o
    ADAPTIF savunmadan alinir (ko-evrim icin). Yoksa sabit WAFMiddleware kullanilir.
    """
    prot, unprot, LT = build_targets(block_threshold)
    attempts = []
    i = 0
    catalog = list(payloads.base_attacks())
    if extra_payloads:
        catalog += list(extra_payloads)   # ko-evrimde uretilen yeni yukler

    for cat, path, param, payload in catalog:
        variants = mutators.mutate(cat, payload) if use_mutations else [("base", payload)]
        for mut_name, mpayload in variants:
            i += 1
            ip = f"127.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"  # loopback
            us, ub = _send(unprot, path, param, mpayload, ip)
            exploited = LT.attack_succeeded(cat, us, ub, mpayload)
            if defense is not None:
                blocked = bool(defense(cat, path, param, mpayload))
            else:
                ps, _pb = _send(prot, path, param, mpayload, ip)
                blocked = (ps == 403)
            attempts.append({
                "category": cat, "mutation": mut_name, "payload": mpayload,
                "exploited": exploited, "blocked": blocked,
                "bypassed": bool(exploited and not blocked),
            })

    # zararsiz trafik -> yanlis pozitif
    benign_total, benign_blocked = 0, 0
    for j, (path, param, value) in enumerate(payloads.BENIGN):
        ip = f"127.10.{(j >> 8) & 255}.{j & 255}"
        cat_b = {"/search": "SQL Injection", "/comment": "XSS", "/file": "Path Traversal",
                 "/ping": "Command Injection", "/render": "SSTI"}.get(path, "SQL Injection")
        if defense is not None:
            benign_blocked += int(bool(defense(cat_b, path, param, value)))
        else:
            ps, _pb = _send(prot, path, param, value, ip)
            benign_blocked += int(ps == 403)
        benign_total += 1

    total = len(attempts)
    exploited_n = sum(a["exploited"] for a in attempts)
    blocked_n = sum(a["blocked"] for a in attempts)
    bypassed = [a for a in attempts if a["bypassed"]]

    per_cat = {}
    for a in attempts:
        c = per_cat.setdefault(a["category"], {"total": 0, "bypassed": 0, "exploited": 0})
        c["total"] += 1
        c["bypassed"] += int(a["bypassed"])
        c["exploited"] += int(a["exploited"])

    per_mut = {}
    for a in attempts:
        m = per_mut.setdefault(a["mutation"], {"total": 0, "bypassed": 0})
        m["total"] += 1
        m["bypassed"] += int(a["bypassed"])

    return {
        "totals": {
            "attempts": total, "exploited": exploited_n, "blocked": blocked_n,
            "bypassed": len(bypassed),
            "benign": benign_total, "benign_blocked_fp": benign_blocked,
        },
        "metrics": {
            # savunmanin, GERCEKTEN calisan saldirilari durdurma orani
            "defense_stop_rate": round((exploited_n - len(bypassed)) / exploited_n, 4) if exploited_n else 1.0,
            # saldirganin, calisan saldirilarla WAF'i asma orani
            "attacker_bypass_rate": round(len(bypassed) / exploited_n, 4) if exploited_n else 0.0,
            "false_positive_rate": round(benign_blocked / benign_total, 4) if benign_total else 0.0,
        },
        "per_category": per_cat,
        "per_mutation": per_mut,
        "bypassed": [{"category": b["category"], "mutation": b["mutation"], "payload": b["payload"]} for b in bypassed],
        "attempts": attempts,
        "config": {"block_threshold": block_threshold, "use_mutations": use_mutations},
    }


def attack_http(url: str, path: str, param: str, payload: str):
    """Yalnizca LOOPBACK bir URL'ye tek istek (ag uzerinden). Guvenlik kapisi
    loopback disini reddeder. In-process mod tercih edilir; bu, canli sunucuya
    karsi manuel test icindir."""
    assert_local_target(url)           # loopback degilse RedTeamSafetyError
    import urllib.request
    full = url.rstrip("/") + path + "?" + urlencode({param: payload})
    try:
        with urllib.request.urlopen(full, timeout=5) as r:
            return r.status, r.read(2000).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode(errors="replace")


def summary_lines(res: dict):
    m, t = res["metrics"], res["totals"]
    return [
        f"Deneme (temel+mutasyon)   : {t['attempts']}  (calisan: {t['exploited']})",
        f"Savunma durdurma orani    : {m['defense_stop_rate']*100:.1f}%",
        f"Saldirgan atlatma orani   : {m['attacker_bypass_rate']*100:.1f}%  ({t['bypassed']} yuk WAF'i geçti)",
        f"Yanlis pozitif (zararsiz) : {m['false_positive_rate']*100:.1f}%  ({t['benign_blocked_fp']}/{t['benign']})",
    ]
