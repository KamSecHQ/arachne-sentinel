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
  4. Kampanya      : (Faz 119) ayni davranissal parmak izini paylasan kardes
                     IP'ler de engellenir ve karantinaya alinir. Sinyal surdukce
                     kampanya yeniden taranir: IP degistiren saldirganin YENI
                     IP'si de yakalanir.

Durum veritabaninda tutulur (lastline_engagements, lastline_campaign_targets):
kale panel surecinde, honeypot ve port_hopper ise full-demo surecinde calisir.

Guvenlik: hedef yalnizca GERCEK bir kaynaktan secilir (cekirdek yemini yutan
IP, yoksa fuzyonun en riskli IP'si). Loopback/ozel ag adresleri SOAR'daki
ayni kuralla korunur: engellenmez, karantinaya da alinmaz. Kampanya basina en
fazla MAX_CAMPAIGN_TARGETS kardes yaptirim alir - bir korelasyon hatasinin
etki alanini sinirlar. Tum yaptirimlar sureli ve geri alinabilirdir.
"""
import time
from collections import defaultdict

from .. import config, storage
from .base import DefenseContext

PLAYBOOK = "son-hat"
MAX_CAMPAIGN_TARGETS = 16
CAMPAIGN_LOOKBACK_SECONDS = 3600
CAMPAIGN_RESCAN_SECONDS = 30
MAX_PROFILED_IPS = 200

_last_campaign_scan = {}     # db_path -> monotonic (yeniden tarama kisitlamasi)


def select_target(ctx: DefenseContext, trigger_ip=None):
    """(ip, kaynak). Gercek kaynak yoksa ip None, kaynak sebebi aciklar."""
    if trigger_ip:
        return trigger_ip, "cekirdek yemi"
    fusion_ip = (ctx.extra or {}).get("fusion_top_ip")
    if fusion_ip:
        return fusion_ip, "tehdit fuzyonu"
    return None, "kaynak IP belirlenemedi"


def campaign_siblings(ip, db_path=None) -> list:
    """Hedefle ayni davranissal kampanyadaki diger IP'ler (Faz 6 korelasyonu).
    Son bir saatin en aktif IP'leri profillenir; korunan adresler elenir."""
    from ..intel import profiler
    from ..soar import blocklist

    by_ip = defaultdict(list)
    for event in storage.get_recent_events(since_seconds=CAMPAIGN_LOOKBACK_SECONDS,
                                           db_path=db_path):
        by_ip[event["source_ip"]].append(event)
    if ip not in by_ip:
        return []
    busiest = sorted(by_ip, key=lambda k: -len(by_ip[k]))[:MAX_PROFILED_IPS]
    if ip not in busiest:
        busiest.append(ip)
    profiles = [profiler.build_profile(src, by_ip[src]) for src in busiest]
    for campaign in profiler.correlate_campaigns(profiles):
        if ip in campaign["member_ips"]:
            return [m for m in campaign["member_ips"]
                    if m != ip and not blocklist.is_protected(m)]
    return []


def _block(ip, reason, db_path):
    from ..soar import actions
    actions.block_ip(ip, context={"reason": reason, "playbook": PLAYBOOK, "severity": "critical"},
                     db_path=db_path, seconds=config.LASTLINE_SANCTION_SECONDS)


def _sanction_campaign(engagement_id, target, reason, db_path):
    """Kampanya kardeslerini pencereye ekler ve engeller (ust sinir korunur)."""
    _last_campaign_scan[db_path] = time.monotonic()
    existing = set(storage.lastline_campaign_targets(engagement_id, db_path=db_path))
    room = max(0, MAX_CAMPAIGN_TARGETS - len(existing))
    fresh = [s for s in campaign_siblings(target, db_path=db_path) if s not in existing][:room]
    for ip in storage.add_lastline_campaign_targets(engagement_id, fresh, db_path=db_path):
        _block(ip, f"Son Hat: {reason} (kampanya kardesi: {target})", db_path)


def engage_sanctions(ctx: DefenseContext, reason: str, trigger_ip=None, db_path=None) -> dict:
    """Son Hat gercek sinyalle acildi: yaptirim penceresini baslatir."""
    from ..soar import blocklist

    ip, source = select_target(ctx, trigger_ip)
    target, note = None, ""
    if ip and blocklist.is_protected(ip):
        note = f"{ip} korunan adres (loopback/ozel ag) - engellenmedi, karantinaya alinmadi"
    elif ip:
        target = ip
        _block(ip, f"Son Hat: {reason}", db_path)
    else:
        note = source
    engagement_id = storage.start_lastline_engagement(
        target, reason, config.LASTLINE_SANCTION_SECONDS, db_path=db_path)
    if target:
        _sanction_campaign(engagement_id, target, reason, db_path)
    st = status(db_path=db_path) or {}
    st.update({"target_source": source, "note": note})
    return st


def refresh_sanctions(db_path=None):
    """Sinyal suruyor: pencereyi uzatir, suresi dolan engelleri yeniler ve
    kampanyayi (kisitli aralikla) yeniden tarar - IP degistiren saldirgan icin."""
    if not storage.extend_lastline_engagement(config.LASTLINE_SANCTION_SECONDS, db_path=db_path):
        return None
    st = status(db_path=db_path)
    if not st or not st["target_ip"]:
        return st
    for ip in [st["target_ip"]] + st["campaign_ips"]:
        if not storage.is_ip_blocked(ip, db_path=db_path):
            _block(ip, "Son Hat: sinyal suruyor (engel yenilendi)", db_path)
    last = _last_campaign_scan.get(db_path, float("-inf"))
    if time.monotonic() - last >= CAMPAIGN_RESCAN_SECONDS:
        _sanction_campaign(st["engagement_id"], st["target_ip"], st["reason"], db_path)
    return status(db_path=db_path)


def release_sanctions(db_path=None) -> int:
    """Sinyal bitti: karantina ve hizli sicrama biter. SOAR engeli TTL'iyle surer."""
    return storage.release_lastline_engagements(db_path=db_path)


def status(db_path=None):
    """Gecerli yaptirimlar (panel + API icin) ya da None."""
    engagement = storage.active_lastline_engagement(db_path=db_path)
    if not engagement:
        return None
    ip = engagement["target_ip"]
    campaign = storage.lastline_campaign_targets(engagement["id"], db_path=db_path)
    return {
        "engagement_id": engagement["id"],
        "target_ip": ip,
        "reason": engagement["reason"],
        "remaining_seconds": max(0, int(engagement["remaining_seconds"] or 0)),
        "blocked": bool(ip) and storage.is_ip_blocked(ip, db_path=db_path),
        "quarantined": bool(ip),
        "campaign_ips": campaign,
        "campaign_blocked": sum(1 for c in campaign if storage.is_ip_blocked(c, db_path=db_path)),
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
