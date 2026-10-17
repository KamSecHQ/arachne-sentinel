"""
Son Hat yaptirimlari (Faz 116) — kale devreye girince sistemin geri kalaninda
GERCEKTEN degisen seyler.

Faz 115'e kadar Son Hat bir karar + kayit + gosterim motoruydu: panel disinda
`engaged` durumunu okuyan hicbir modul yoktu. Bu modul o koprudur. Son Hat
GERCEK sinyalle (tatbikatta DEGIL) acildiginda:

  1. SOAR engeli   : hedef IP TTL'li engelleme listesine yazilir ve SOAR denetim
                     kaydina "son-hat" playbook'uyla gecer. Faz 118'den beri
                     WAF da bu listeyi uygular (gercek varlik).
  2. Karantina     : honeypot o IP'yi reddetmek yerine tarpit + aldatma
                     kuyusunda tutar - saldirgan yakalandigini anlamaz. Pencere
                     kapaninca SOAR engeli kendi TTL'iyle baglantiyi reddeder.
  3. Hizli sicrama : hayalet admin paneli (Faz 4 port_hopper) port degistirme
                     araligini LASTLINE_HOP_INTERVAL_SECONDS'e indirir.

Durum veritabaninda tutulur (lastline_engagements): kale panel surecinde,
honeypot ve port_hopper ise full-demo surecinde calisir.

Guvenlik: hedef yalnizca GERCEK bir kaynaktan secilir (cekirdek yemini yutan
IP, yoksa fuzyonun en riskli IP'si). Loopback/ozel ag adresleri SOAR'daki
ayni kuralla korunur: engellenmez, karantinaya da alinmaz. Tum yaptirimlar
sureli ve geri alinabilirdir.
"""
from .. import config, storage
from .base import DefenseContext

PLAYBOOK = "son-hat"


def select_target(ctx: DefenseContext, trigger_ip=None):
    """(ip, kaynak). Gercek kaynak yoksa ip None, kaynak sebebi aciklar."""
    if trigger_ip:
        return trigger_ip, "cekirdek yemi"
    fusion_ip = (ctx.extra or {}).get("fusion_top_ip")
    if fusion_ip:
        return fusion_ip, "tehdit fuzyonu"
    return None, "kaynak IP belirlenemedi"


def engage_sanctions(ctx: DefenseContext, reason: str, trigger_ip=None, db_path=None) -> dict:
    """Son Hat gercek sinyalle acildi: yaptirim penceresini baslatir."""
    from ..soar import actions, blocklist

    ip, source = select_target(ctx, trigger_ip)
    target, note = None, ""
    if ip and blocklist.is_protected(ip):
        note = f"{ip} korunan adres (loopback/ozel ag) - engellenmedi, karantinaya alinmadi"
    elif ip:
        target = ip
        actions.block_ip(ip, context={"reason": f"Son Hat: {reason}", "playbook": PLAYBOOK,
                                      "severity": "critical"},
                         db_path=db_path, seconds=config.LASTLINE_SANCTION_SECONDS)
    else:
        note = source
    storage.start_lastline_engagement(target, reason, config.LASTLINE_SANCTION_SECONDS,
                                      db_path=db_path)
    st = status(db_path=db_path) or {}
    st.update({"target_source": source, "note": note})
    return st


def refresh_sanctions(db_path=None):
    """Sinyal suruyor: pencereyi uzatir; engel TTL'i dolduysa yeniler."""
    from ..soar import actions

    if not storage.extend_lastline_engagement(config.LASTLINE_SANCTION_SECONDS, db_path=db_path):
        return None
    st = status(db_path=db_path)
    if st and st["target_ip"] and not st["blocked"]:
        actions.block_ip(st["target_ip"],
                         context={"reason": "Son Hat: sinyal suruyor (engel yenilendi)",
                                  "playbook": PLAYBOOK, "severity": "critical"},
                         db_path=db_path, seconds=config.LASTLINE_SANCTION_SECONDS)
        st = status(db_path=db_path)
    return st


def release_sanctions(db_path=None) -> int:
    """Sinyal bitti: karantina ve hizli sicrama biter. SOAR engeli TTL'iyle surer."""
    return storage.release_lastline_engagements(db_path=db_path)


def status(db_path=None):
    """Gecerli yaptirimlar (panel + API icin) ya da None."""
    engagement = storage.active_lastline_engagement(db_path=db_path)
    if not engagement:
        return None
    ip = engagement["target_ip"]
    return {
        "target_ip": ip,
        "reason": engagement["reason"],
        "remaining_seconds": max(0, int(engagement["remaining_seconds"] or 0)),
        "blocked": bool(ip) and storage.is_ip_blocked(ip, db_path=db_path),
        "quarantined": bool(ip),
        "hop_interval_seconds": config.LASTLINE_HOP_INTERVAL_SECONDS,
    }


def hop_interval(normal_seconds: int, db_path=None) -> int:
    """port_hopper'in bir sonraki sicrama araligi: Son Hat devredeyse kisalir."""
    try:
        if storage.active_lastline_engagement(db_path=db_path):
            return min(normal_seconds, config.LASTLINE_HOP_INTERVAL_SECONDS)
    except Exception:
        pass   # durum okunamazsa normal aralik (MTD calismaya devam eder)
    return normal_seconds
