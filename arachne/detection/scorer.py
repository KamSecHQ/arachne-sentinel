"""
Skorlama motoru: bir IP icin son olaylari toplar, tum kurallari calistirir,
toplam tehdit skorunu hesaplar ve esik asilirsa alarm kaydeder.
"""
from .. import config
from .. import storage
from . import rules


def _severity_for_score(score: int) -> str:
    thresholds = config.SEVERITY_THRESHOLDS
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def evaluate_ip(source_ip: str, lookback_seconds: int = None, db_path=None) -> dict:
    """Verilen IP icin son olaylari degerlendirir, gerekirse alarm olusturur.

    Donen sozluk: {"score": int, "severity": str, "reasons": list[str],
                    "triggered_alert": bool}
    """
    lookback_seconds = lookback_seconds or config.DEFAULT_LOOKBACK_SECONDS
    events = storage.get_recent_events(
        source_ip=source_ip, since_seconds=lookback_seconds, db_path=db_path
    )
    if not events:
        return {"score": 0, "severity": "low", "reasons": [], "triggered_alert": False}

    total_score = 0
    reasons = []

    for rule in rules.ALL_RULES:
        triggered, reason, weight = rule(events)
        if triggered:
            total_score += weight
            reasons.append(reason)

    prior = storage.has_prior_alert(source_ip, db_path=db_path)
    triggered, reason, weight = rules.rule_repeated_offender(events, prior)
    if triggered:
        total_score += weight
        reasons.append(reason)

    severity = _severity_for_score(total_score)
    triggered_alert = total_score >= config.ALERT_MIN_SCORE

    if triggered_alert:
        storage.log_alert(source_ip, total_score, severity, reasons, db_path=db_path)

    return {
        "score": total_score,
        "severity": severity,
        "reasons": reasons,
        "triggered_alert": triggered_alert,
    }
