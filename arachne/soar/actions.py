"""
SOAR mudahale eylemleri (response actions).

Her eylem, ticari SOAR urunlerindeki (Splunk SOAR, Cortex XSOAR, Microsoft
Sentinel) karsiliklarina bilincli olarak benzetildi. Eylemler iki sinifa
ayrilir - bu ayrim, sistemin guvenli otomasyon iddiasinin merkezindedir:

  ZENGINLESTIRME (enrichment)  : salt-okunur, yan etkisiz, her zaman
                                 tam otomatik calisir. Ornek: IP kapsamini
                                 belirle, gecmisi sorgula, IOC cikar.

  KISITLAMA (containment)      : durum degistirir. Geri alinabilir olanlar
                                 (sureli engelleme) otomatik; geri alinamaz
                                 ya da yuksek etkili olanlar INSAN ONAYI
                                 gerektirir.

Microsoft Sentinel'in kendisinde bile yerlesik bir "IP engelle" eylemi
yoktur - orkestrasyon ile YAPTIRIM birbirinden ayridir. Biz de ayni
ayrimi koruduk: playbook motoru karar verir, blocklist.py uygular.
"""
import time
from dataclasses import dataclass, field

from .. import storage
from ..intel.geo import classify_ip_scope, geo_for_ip
from . import blocklist


@dataclass
class ActionResult:
    action: str
    target: str
    success: bool
    outcome: str                    # "uygulandi" | "onay-bekliyor" | "atlandi" | "hata"
    detail: str = ""
    data: dict = field(default_factory=dict)
    requires_approval: bool = False

    def to_dict(self):
        return {
            "action": self.action, "target": self.target, "success": self.success,
            "outcome": self.outcome, "detail": self.detail, "data": self.data,
            "requires_approval": self.requires_approval,
        }


# --- ZENGINLESTIRME EYLEMLERI (her zaman otomatik, yan etkisiz) ------------

def enrich_ip_scope(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """IP'nin kapsamini ve tahmini bolgesini belirler."""
    geo = geo_for_ip(ip)
    return ActionResult(
        action="enrich_ip_scope", target=ip, success=True, outcome="uygulandi",
        detail=f"Kapsam: {geo['scope']}, bolge: {geo['region_name']} ({geo['precision_tr']})",
        data=geo,
    )


def enrich_history(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Bu IP'yi daha once gorduk mu? Kac alarm uretti?"""
    try:
        alerts = [a for a in storage.get_all_alerts(limit=500, db_path=db_path)
                  if a.get("source_ip") == ip]
        events = storage.get_recent_events(source_ip=ip, db_path=db_path)
    except Exception as exc:
        return ActionResult("enrich_history", ip, False, "hata", str(exc))

    data = {
        "prior_alerts": len(alerts),
        "total_events": len(events),
        "max_score": max((a.get("score") or 0 for a in alerts), default=0),
        "repeat_offender": len(alerts) > 1,
    }
    return ActionResult(
        action="enrich_history", target=ip, success=True, outcome="uygulandi",
        detail=(f"{data['prior_alerts']} onceki alarm, {data['total_events']} olay"
                + (" - TEKRARLAYAN SALDIRGAN" if data["repeat_offender"] else "")),
        data=data,
    )


def enrich_reverse_engineering(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Faz 5 tersine muhendislik analizini calistirir (salt-okunur)."""
    from ..reverse.attack_analyzer import analyze_ip
    try:
        events = storage.get_recent_events(source_ip=ip, db_path=db_path)
        analysis = analyze_ip(ip, events)
    except Exception as exc:
        return ActionResult("enrich_reverse_engineering", ip, False, "hata", str(exc))

    return ActionResult(
        action="enrich_reverse_engineering", target=ip, success=True, outcome="uygulandi",
        detail=(f"Saldiri siniflari: {', '.join(analysis['attack_classes']) or 'yok'}; "
                f"arac: {analysis['primary_tool'] or 'tespit edilemedi'}; "
                f"kill chain: {analysis['kill_chain']['phase_tr']}"),
        data={
            "attack_classes": analysis["attack_classes"],
            "primary_tool": analysis["primary_tool"],
            "automated": analysis["automated"],
            "kill_chain": analysis["kill_chain"],
            "threat_score": analysis["max_threat_score"],
            "ioc_count": analysis["ioc_count"],
        },
    )


# --- KISITLAMA EYLEMLERI (durum degistirir) --------------------------------

def rate_limit(ip: str, context: dict = None, db_path=None, seconds: int = 60) -> ActionResult:
    """Kisa sureli kisitlama - dusuk riskli, tamamen geri alinabilir.

    Bu, guven esigi tam olarak asilmadiginda uygulanan "yumusak" tedbirdir:
    saldirgani yavaslatir ama mesru bir kullaniciysa kisa surede serbest
    kalir."""
    result = blocklist.block(
        ip, seconds=seconds, reason=(context or {}).get("reason", "hiz sinirlama"),
        playbook=(context or {}).get("playbook", ""), severity="low", db_path=db_path,
    )
    if not result["blocked"]:
        return ActionResult("rate_limit", ip, False, "atlandi",
                            result.get("reason_not_blocked", ""))
    return ActionResult("rate_limit", ip, True, "uygulandi",
                        f"{seconds} saniye hiz sinirlamasi uygulandi", data=result)


def block_ip(ip: str, context: dict = None, db_path=None, seconds: int = 900) -> ActionResult:
    """Sureli tam engelleme - orta/yuksek riskli, TTL sayesinde geri alinabilir."""
    ctx = context or {}
    result = blocklist.block(
        ip, seconds=seconds, reason=ctx.get("reason", "otomatik engelleme"),
        playbook=ctx.get("playbook", ""), severity=ctx.get("severity", "high"),
        db_path=db_path,
    )
    if not result["blocked"]:
        return ActionResult("block_ip", ip, False, "atlandi",
                            result.get("reason_not_blocked", ""))
    return ActionResult("block_ip", ip, True, "uygulandi",
                        f"{seconds} saniye tam engelleme uygulandi", data=result)


def escalate_to_human(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Insan onayi gerektiren eylem - OTOMATIK UYGULANMAZ.

    Splunk SOAR'daki "Prompt" blogu, Cortex XSOAR'daki "Ask" gorevi ile
    ayni rolu oynar. Otomasyon olgunlugu 'her seyi otomatiklestirmek'
    degil, insan kapisinin NEREYE konulacagini bilmektir."""
    ctx = context or {}
    detail = ctx.get("reason", "Yuksek etkili mudahale icin analist onayi gerekiyor")
    try:
        storage.log_soar_action(
            action="escalate_to_human", target=ip, playbook=ctx.get("playbook", ""),
            reason=detail, outcome="onay-bekliyor",
            detail="Otomatik uygulanmadi - insan karari bekleniyor", db_path=db_path,
        )
    except Exception:
        pass
    return ActionResult("escalate_to_human", ip, True, "onay-bekliyor", detail,
                        requires_approval=True)


def trigger_mtd_rotation(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Faz 4 MTD katmanini erken rotasyona zorlar.

    Mantik: saldirgan bizi haritalamaya calisiyorsa, tam o anda kimligimizi
    degistirmek onun topladigi bilgiyi gecersiz kilar. Bu, MTD'yi pasif bir
    zamanlayicidan TEHDIDE TEPKI VEREN bir savunmaya donusturur - Faz 4 ile
    Faz 7'nin birbirini guclendirdigi nokta."""
    ctx = context or {}
    try:
        storage.log_mtd_rotation(
            component="soar:triggered-rotation",
            new_identity="rotasyon-istegi",
            old_identity=None,
            reason=f"SOAR tetikledi: {ip} kesif yapiyor ({ctx.get('reason', '')})",
            db_path=db_path,
        )
        storage.log_soar_action(
            action="trigger_mtd_rotation", target=ip, playbook=ctx.get("playbook", ""),
            reason=ctx.get("reason", ""), outcome="uygulandi",
            detail="MTD kimlik rotasyonu tetiklendi", db_path=db_path,
        )
    except Exception as exc:
        return ActionResult("trigger_mtd_rotation", ip, False, "hata", str(exc))
    return ActionResult("trigger_mtd_rotation", ip, True, "uygulandi",
                        "Hedef kimligi degistirildi - saldirganin haritasi gecersizlestirildi")


def create_incident(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Olay kaydi olusturur (ticket sistemlerinin karsiligi)."""
    ctx = context or {}
    incident_id = f"INC-{int(time.time())}-{ip.replace('.', '-')}"
    try:
        storage.log_soar_action(
            action="create_incident", target=ip, playbook=ctx.get("playbook", ""),
            reason=ctx.get("reason", ""), outcome="uygulandi",
            detail=f"Olay kaydi: {incident_id}", db_path=db_path,
        )
    except Exception as exc:
        return ActionResult("create_incident", ip, False, "hata", str(exc))
    return ActionResult("create_incident", ip, True, "uygulandi",
                        f"Olay kaydi olusturuldu: {incident_id}",
                        data={"incident_id": incident_id})


def tag_and_log(ip: str, context: dict = None, db_path=None) -> ActionResult:
    """Etiketleme + denetim kaydi (her zaman guvenli)."""
    ctx = context or {}
    tags = ctx.get("tags", [])
    try:
        storage.log_soar_action(
            action="tag_and_log", target=ip, playbook=ctx.get("playbook", ""),
            reason=ctx.get("reason", ""), outcome="uygulandi",
            detail=f"Etiketler: {', '.join(tags) if tags else 'yok'}", db_path=db_path,
        )
    except Exception as exc:
        return ActionResult("tag_and_log", ip, False, "hata", str(exc))
    return ActionResult("tag_and_log", ip, True, "uygulandi",
                        f"Etiketlendi: {', '.join(tags) if tags else '-'}",
                        data={"tags": tags})


# --- Eylem kaydi (registry) -------------------------------------------------
# Playbook'lar eylemleri ISIMLE cagirir; boylece playbook tanimlari saf veri
# olarak kalir ve ileride bir yapilandirma dosyasindan okunabilir.

ENRICHMENT_ACTIONS = {
    "enrich_ip_scope": enrich_ip_scope,
    "enrich_history": enrich_history,
    "enrich_reverse_engineering": enrich_reverse_engineering,
}

CONTAINMENT_ACTIONS = {
    "rate_limit": rate_limit,
    "block_ip": block_ip,
    "escalate_to_human": escalate_to_human,
    "trigger_mtd_rotation": trigger_mtd_rotation,
    "create_incident": create_incident,
    "tag_and_log": tag_and_log,
}

ALL_ACTIONS = {**ENRICHMENT_ACTIONS, **CONTAINMENT_ACTIONS}

# Hangi eylemler insan onayi gerektirir? (guvenlik politikasi)
HUMAN_GATED = {"escalate_to_human"}


def get_action(name: str):
    return ALL_ACTIONS.get(name)


def action_is_safe(name: str) -> bool:
    """Eylem yan etkisiz mi (tam otomatiklestirilebilir mi)?"""
    return name in ENRICHMENT_ACTIONS
