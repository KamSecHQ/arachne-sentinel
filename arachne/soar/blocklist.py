"""
TTL'li engelleme listesi - SOAR katmaninin GERCEK yaptirim mekanizmasi.

Bu, projedeki "otomatik mudahale" iddiasinin somut karsiligidir: honeypot
dinleyicileri her yeni baglantida buraya sorar; IP engelliyse baglanti
aninda kapatilir.

--- Neden veritabani destekli? ---
Ilk tasarimda engellemeler yalnizca bellekte tutuluyordu. Uctan uca canli
testte su hata ortaya cikti: honeypot ve panel AYRI SURECLERDE calisir,
dolayisiyla bir surecte uygulanan engelleme digerinden gorunmuyordu.
Gercek bir yaptirim mekanizmasinin surecten bagimsiz olmasi gerekir -
bu yuzden engellemeler SQLite'a yazilir. Bellek katmani yalnizca sicak
yol (her baglantida cagrilan `is_blocked`) icin kisa omurlu bir onbellektir.

--- Neden TTL (sureli) engelleme? ---
Kalici engelleme tehlikelidir: yanlis pozitif bir IP'yi sonsuza kadar
engellersiniz ve bunu fark etmezsiniz. Gercek SOAR urunlerinde de standart
yaklasim sureli engellemedir - sure dolunca otomatik acilir, tehdit devam
ediyorsa yeniden engellenir. Bu, "geri alinabilirlik" ilkesidir ve
otomasyonun guvenli olmasinin temel sartidir.

--- Guvenlik onlemi: allowlist ---
Loopback ve ozel ag adresleri VARSAYILAN OLARAK engellenemez. Sebep: lab
ortaminda tum trafik 127.0.0.1'den gelir; koruma olmasaydi sistem ilk
demo saldirisinda kendi kendini kilitlerdi. Bu, gercek urunlerdeki
"kritik altyapiyi asla engelleme" kuralinin kucuk olcekli karsiligidir.
"""
import ipaddress
import threading
import time

from .. import storage

# Asla engellenmeyecek adresler/agler. Lab guvenligi icin kritik.
DEFAULT_ALLOWLIST = ["127.0.0.1", "::1"]
# Ozel aglari da varsayilan olarak koru (lab ici test trafigi)
PROTECT_PRIVATE_RANGES = True

# Sicak yol onbellegi: her TCP baglantisinda veritabanina gitmemek icin.
# Kisa omurlu tutuldu (1sn) - tazelik ile performans arasindaki denge.
CACHE_TTL_SECONDS = 1.0

_lock = threading.RLock()
_cache = {"blocked": set(), "fetched_at": 0.0}


def _is_protected(ip: str) -> bool:
    """Bu IP korunuyor mu (engellenemez mi)?

    RFC 5737 dokumantasyon adresleri (203.0.113.x vb.) KORUNMAZ: bu
    araliklarin arkasinda gercek bir cihaz olamaz, dolayisiyla onlari
    engellemek kimseye zarar veremez. Senaryo/demo trafigi bu araliklari
    kullanir, boylece SOAR yaptirimi gercekten test edilebilir."""
    from ..intel.geo import is_documentation_ip

    if ip in DEFAULT_ALLOWLIST:
        return True
    if is_documentation_ip(ip):
        return False
    if not PROTECT_PRIVATE_RANGES:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return True  # gecersiz IP'yi engellemeye calisma
    return addr.is_loopback or addr.is_private


def _invalidate_cache():
    with _lock:
        _cache["fetched_at"] = 0.0


def block(ip: str, seconds: int, reason: str = "", playbook: str = "",
          severity: str = "medium", db_path=None, force: bool = False) -> dict:
    """Bir IP'yi verilen sure boyunca engeller.

    force=True sadece testler ve bilincli lab senaryolari icindir; koruma
    listesini atlar. Uretim yolunda ASLA force kullanilmaz."""
    if not force and _is_protected(ip):
        return {
            "blocked": False,
            "ip": ip,
            "reason_not_blocked": (
                "Korunan adres (loopback/ozel ag) - lab guvenligi icin engellenmedi"
            ),
        }

    seconds = max(1, int(seconds))
    try:
        storage.add_block(ip, seconds, reason=reason, playbook=playbook,
                          severity=severity, db_path=db_path)
        storage.log_soar_action(
            action="block_ip", target=ip, playbook=playbook,
            reason=reason, outcome="uygulandi",
            detail=f"{seconds} saniye engellendi", db_path=db_path,
        )
    except Exception as exc:
        return {"blocked": False, "ip": ip,
                "reason_not_blocked": f"Depolama hatasi: {exc}"}

    _invalidate_cache()
    return {"blocked": True, "ip": ip, "seconds": seconds, "reason": reason}


def unblock(ip: str, db_path=None) -> bool:
    try:
        removed = storage.remove_block(ip, db_path=db_path)
    except Exception:
        return False
    if removed:
        _invalidate_cache()
        try:
            storage.log_soar_action(
                action="unblock_ip", target=ip, playbook="", reason="elle kaldirildi",
                outcome="uygulandi", detail="", db_path=db_path,
            )
        except Exception:
            pass
    return removed


def is_blocked(ip: str, db_path=None) -> bool:
    """Honeypot dinleyicilerinin her baglantida cagirdigi sicak yol (hot path).

    Kisa omurlu bir onbellek kullanir: her TCP baglantisinda veritabanina
    gitmek gereksiz yuk olurdu, ama onbellek 1 saniyeden uzun yasarsa yeni
    uygulanan bir engelleme gecikmeli devreye girerdi. 1sn bu dengeyi kurar."""
    now = time.monotonic()
    with _lock:
        if now - _cache["fetched_at"] > CACHE_TTL_SECONDS:
            try:
                blocks = storage.get_active_blocks(db_path=db_path)
                _cache["blocked"] = {b["ip"] for b in blocks}
                _cache["fetched_at"] = now
            except Exception:
                # Veritabani okunamiyorsa engelleme UYGULAMA (fail-open).
                # Bilincli tercih: bir depolama hatasi yuzunden mesru
                # trafigi kesmek, honeypot'un amaciyla celisirdi.
                return False
        return ip in _cache["blocked"]


def remaining_seconds(ip: str, db_path=None) -> int:
    try:
        for block_entry in storage.get_active_blocks(db_path=db_path):
            if block_entry["ip"] == ip:
                return max(0, int(block_entry.get("remaining_seconds") or 0))
    except Exception:
        pass
    return 0


def active_blocks(db_path=None) -> list:
    """Su an aktif olan tum engellemeler (panelde gosterilir)."""
    try:
        blocks = storage.get_active_blocks(db_path=db_path)
    except Exception:
        return []
    return [{
        "ip": b["ip"],
        "remaining_seconds": max(0, int(b.get("remaining_seconds") or 0)),
        "duration": b.get("duration_seconds"),
        "reason": b.get("reason") or "",
        "playbook": b.get("playbook") or "",
        "severity": b.get("severity") or "medium",
        "blocked_at": b.get("blocked_at"),
    } for b in blocks]


def clear_all(db_path=None):
    """Tum engellemeleri temizler (testler ve yeniden baslatma icin)."""
    try:
        storage.clear_blocks(db_path=db_path)
    except Exception:
        pass
    _invalidate_cache()


def stats(db_path=None) -> dict:
    blocks = active_blocks(db_path=db_path)
    return {
        "active_blocks": len(blocks),
        "protected_addresses": len(DEFAULT_ALLOWLIST),
        "longest_remaining": blocks[0]["remaining_seconds"] if blocks else 0,
    }
