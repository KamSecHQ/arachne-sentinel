"""
Playbook calistirma motoru.

Bir alarm geldiginde:
  1. Uyan playbook'lari bulur
  2. Zenginlestirme eylemlerini calistirir (salt-okunur, guvenli)
  3. Toplanan baglamla karar kurallarini degerlendirir - ILK eslesen kazanir
  4. Secilen eylemleri calistirir
  5. Her adimi denetim kaydina yazar

--- Neden "ilk eslesen kazanir"? ---
Karar kurallari en spesifikten en genele dogru siralanir. Bu, guvenlik
politikalarinda standart bir yaklasimdir (guvenlik duvari kurallari da
boyle calisir) ve davranisi ONGORULEBILIR kilar: bir kural yazarken
"benden once hangi kurallar var?" sorusuna bakmak yeterlidir.

--- Denetim kaydinin onemi ---
Otomatik bir sistem yanlis karar verdiginde, "neden boyle yapti?"
sorusuna cevap verebilmek zorunludur. Her eylem; hangi playbook, hangi
karar kurali ve hangi gerekce ile calistigi bilgisiyle kaydedilir.
"""
import logging

from .. import storage
from . import actions, playbooks

logger = logging.getLogger(__name__)


def _evaluate_condition(condition: dict, context: dict) -> bool:
    """Bir karar kuralinin kosullarini baglama karsi degerlendirir.

    Bos kosul ({}) her zaman dogrudur - "varsayilan/son care" kurali icin.
    Tum kosullar VE (AND) ile birlestirilir."""
    if not condition:
        return True

    for key, expected in condition.items():
        if key == "repeat_offender":
            if bool(context.get("repeat_offender")) != bool(expected):
                return False
        elif key == "automated":
            if bool(context.get("automated")) != bool(expected):
                return False
        elif key == "min_events":
            if context.get("total_events", 0) < expected:
                return False
        elif key == "min_score":
            if context.get("score", 0) < expected:
                return False
        elif key == "has_class":
            if expected not in (context.get("attack_classes") or []):
                return False
        elif key == "hidden_attack_found":
            if bool(context.get("hidden_attack_found")) != bool(expected):
                return False
        else:
            # Bilinmeyen kosul anahtari -> guvenli tarafta kal, eslesme yok
            logger.warning("Bilinmeyen playbook kosulu: %s", key)
            return False
    return True


def _run_enrichment(playbook: dict, source_ip: str, db_path=None,
                    base_context: dict = None) -> tuple:
    """Zenginlestirme eylemlerini calistirir ve karar baglamini olusturur.

    `base_context` verilirse, alarmin kendi bulgulari baslangic noktasi
    olur ve zenginlestirme sonuclari onlarin UZERINE EKLENIR (silmez)."""
    results = []
    context = {"attack_classes": list((base_context or {}).get("attack_classes") or [])}

    for action_name in playbook.get("enrichment", []):
        func = actions.get_action(action_name)
        if not func:
            logger.warning("Bilinmeyen zenginlestirme eylemi: %s", action_name)
            continue
        try:
            result = func(source_ip, context={"playbook": playbook["name"]}, db_path=db_path)
        except Exception as exc:
            logger.exception("Zenginlestirme hatasi: %s", action_name)
            result = actions.ActionResult(action_name, source_ip, False, "hata", str(exc))
        results.append(result)

        # Sonuclari karar baglamina aktar
        data = result.data or {}
        if "repeat_offender" in data:
            context["repeat_offender"] = data["repeat_offender"]
        if "total_events" in data:
            context["total_events"] = data["total_events"]
        if "automated" in data:
            context["automated"] = data["automated"]
        if "attack_classes" in data:
            # BIRLESTIR, uzerine yazma. Alarm baglamindaki siniflar kural
            # motorunun kesin bulgusudur; zenginlestirme yalnizca EKLEYEBILIR.
            # (Bu ayrim bir hata sonucu ogrenildi: veritabaninda kayit
            # olmadigi durumda zenginlestirme bos liste dondurup alarmin
            # kendi bulgularini siliyordu.)
            merged = list(context.get("attack_classes") or [])
            for cls in data["attack_classes"]:
                if cls not in merged:
                    merged.append(cls)
            context["attack_classes"] = merged
        if "kill_chain" in data:
            context["kill_chain"] = data["kill_chain"]
        if "threat_score" in data:
            context["threat_score"] = data["threat_score"]

    return results, context


def run_playbook(playbook: dict, source_ip: str, alert_context: dict,
                 db_path=None, dry_run: bool = False) -> dict:
    """Tek bir playbook'u calistirir ve tam bir yurutme kaydi dondurur."""
    # Alarm baglamiyla BASLA, sonra zenginlestir. Sira onemli: zenginlestirme
    # fonksiyonlari alarmin kendi bulgularinin uzerine yazamamali.
    context = dict(alert_context or {})
    context.setdefault("attack_classes", [])

    enrichment_results, derived = _run_enrichment(
        playbook, source_ip, db_path=db_path, base_context=context)
    context.update(derived)

    # Karar: ilk eslesen kural kazanir
    chosen = None
    for rule in playbook.get("decision", []):
        if _evaluate_condition(rule.get("if", {}), context):
            chosen = rule
            break

    action_results = []
    if chosen:
        for action_name, params in chosen.get("then", []):
            func = actions.get_action(action_name)
            if not func:
                logger.warning("Bilinmeyen eylem: %s", action_name)
                continue

            if dry_run:
                action_results.append(actions.ActionResult(
                    action_name, source_ip, True, "atlandi",
                    "Kuru calistirma (dry-run) - gercek eylem uygulanmadi",
                ))
                continue

            action_context = {
                "playbook": playbook["name"],
                "reason": chosen.get("because", ""),
                "severity": context.get("severity", "medium"),
                **params,
            }
            try:
                result = func(source_ip, context=action_context, db_path=db_path,
                              **{k: v for k, v in params.items() if k == "seconds"})
            except TypeError:
                # Eylem 'seconds' parametresini kabul etmiyorsa parametresiz cagir
                try:
                    result = func(source_ip, context=action_context, db_path=db_path)
                except Exception as exc:
                    logger.exception("Eylem hatasi: %s", action_name)
                    result = actions.ActionResult(action_name, source_ip, False,
                                                  "hata", str(exc))
            except Exception as exc:
                logger.exception("Eylem hatasi: %s", action_name)
                result = actions.ActionResult(action_name, source_ip, False, "hata", str(exc))
            action_results.append(result)

    return {
        "playbook": playbook["name"],
        "playbook_title": playbook["title_tr"],
        "source_ip": source_ip,
        "enrichment": [r.to_dict() for r in enrichment_results],
        "decision_matched": bool(chosen),
        "decision_reason": chosen.get("because", "") if chosen else "Hicbir kural eslesmedi",
        "actions": [r.to_dict() for r in action_results],
        "actions_applied": sum(1 for r in action_results if r.outcome == "uygulandi"),
        "awaiting_approval": sum(1 for r in action_results if r.requires_approval),
        "context": context,
        "dry_run": dry_run,
    }


def respond_to_alert(source_ip: str, score: int, severity: str,
                     attack_classes: list = None, db_path=None,
                     dry_run: bool = False) -> dict:
    """SOAR katmaninin ana giris noktasi.

    Bir alarm uretildiginde cagrilir; uyan tum playbook'lari calistirir.
    Hicbir playbook uymazsa bu da normal bir sonuctur (dusuk skorlu
    alarmlar icin otomatik mudahale gerekmeyebilir)."""
    attack_classes = attack_classes or []
    matched = playbooks.find_matching_playbooks(score, severity, attack_classes)

    if not matched:
        return {
            "source_ip": source_ip, "score": score, "severity": severity,
            "matched_playbooks": 0, "executions": [],
            "summary_tr": "Uyan playbook yok - otomatik mudahale gerekmedi",
        }

    alert_context = {
        "score": score,
        "severity": severity,
        "attack_classes": attack_classes,
    }

    executions = [
        run_playbook(pb, source_ip, alert_context, db_path=db_path, dry_run=dry_run)
        for pb in matched
    ]

    total_actions = sum(e["actions_applied"] for e in executions)
    awaiting = sum(e["awaiting_approval"] for e in executions)

    return {
        "source_ip": source_ip,
        "score": score,
        "severity": severity,
        "attack_classes": attack_classes,
        "matched_playbooks": len(matched),
        "playbook_names": [pb["name"] for pb in matched],
        "executions": executions,
        "total_actions_applied": total_actions,
        "awaiting_approval": awaiting,
        "summary_tr": (
            f"{len(matched)} playbook calisti, {total_actions} eylem uygulandi"
            + (f", {awaiting} eylem insan onayi bekliyor" if awaiting else "")
        ),
        "dry_run": dry_run,
    }
