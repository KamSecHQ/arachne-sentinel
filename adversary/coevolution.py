"""
KO-EVRIM DÖNGUSU — kirmizi takim (saldiri) ↔ mavi takim (savunma) yarisi.

Her turda:
  1) Saldirgan, temel + mutasyonlu yukleri YEREL lab hedefine gonderir,
  2) Savunmanin (adaptif WAF) kaçirdigi (bypass) yukler tespit edilir,
  3) Mavi takim bu atlatmalara karsi gereken normallestiricileri OGRENIR,
  4) Sonraki turda savunma daha güçlü olur; atlatma orani düser.

Boylece "saldiri gelistikçe savunma yukari çekilir" ilkesi somut olarak, tur
tur olçulen sayilarla gosterilir. Tamamen yerel; disariya dokunulmaz.
"""
from __future__ import annotations

from . import engine
from .defense import AdaptiveWAF


def run(rounds: int = 4, block_threshold: int = 50) -> dict:
    waf = AdaptiveWAF(enabled=[], block_threshold=block_threshold)
    history = []

    for r in range(1, rounds + 1):
        res = engine.run_campaign(block_threshold=block_threshold, use_mutations=True,
                                  defense=waf.as_callable())
        t, m = res["totals"], res["metrics"]
        bypass_muts = sorted({b["mutation"] for b in res["bypassed"]})
        before = set(waf.enabled)
        learned = waf.learn_from(bypass_muts)
        # panel icin canli akis ornekleri (atlatanlar once, sonra engellenenler)
        atts = res["attempts"]
        by = [a for a in atts if a["bypassed"]][:6]
        bl = [a for a in atts if a["blocked"] and a["exploited"]][:6]
        feed = [{"category": a["category"], "mutation": a["mutation"],
                 "payload": a["payload"][:60],
                 "verdict": "bypass" if a["bypassed"] else "blocked"}
                for a in (by + bl)]
        history.append({
            "round": r,
            "attempts": t["attempts"],
            "exploited": t["exploited"],
            "bypassed": t["bypassed"],
            "attacker_bypass_rate": m["attacker_bypass_rate"],
            "defense_stop_rate": m["defense_stop_rate"],
            "false_positive_rate": m["false_positive_rate"],
            "defense_before": sorted(before),
            "bypass_mutations": bypass_muts,
            "defense_learned": sorted(learned),
            "defense_after": sorted(waf.enabled),
            "bypass_examples": [f"{b['category']} / {b['mutation']}: {b['payload'][:48]}"
                                for b in res["bypassed"][:6]],
            "feed": feed,
            "per_category": res["per_category"],
        })
        if t["bypassed"] == 0:
            break   # savunma tüm calisan saldirilari durdurdu

    first, last = history[0], history[-1]
    return {
        "rounds": history,
        "summary": {
            "start_bypass_rate": first["attacker_bypass_rate"],
            "end_bypass_rate": last["attacker_bypass_rate"],
            "start_bypassed": first["bypassed"],
            "end_bypassed": last["bypassed"],
            "final_defense": last["defense_after"],
            "converged": last["bypassed"] == 0,
            "final_false_positive_rate": last["false_positive_rate"],
        },
    }


def summary_lines(res: dict):
    out = []
    for h in res["rounds"]:
        out.append(
            f"Tur {h['round']}: atlatma {h['attacker_bypass_rate']*100:5.1f}% "
            f"({h['bypassed']:>2}/{h['exploited']} calisan saldiri geçti) · "
            f"savunma ogrendi: {', '.join(h['defense_learned']) or '—'}")
    s = res["summary"]
    out.append("")
    out.append(f"SONUÇ: atlatma %{s['start_bypass_rate']*100:.1f} → %{s['end_bypass_rate']*100:.1f}"
               f"  |  {'savunma yakaladi (yakinsadi)' if s['converged'] else 'yaris sürüyor'}"
               f"  |  yanlis pozitif %{s['final_false_positive_rate']*100:.1f}")
    return out
