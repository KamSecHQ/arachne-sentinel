"""
Faz 110 - Musteri Varlik Profili (Customer Asset Profile).

Bu, Arachne Sentinel'i kendi web sitesine/altyapisina entegre eden bir
musterinin KENDI kimlik/iletisim bilgilerini tanimladigi yerdir - "en altta
korunan cekirdege kendi bilgilerini koyabilmesi" ihtiyacinin karsiligi.

--- GUVENLIK ILKESI (kritik, sapilmaz) ---
Buraya GERCEK sifre/API anahtari/DB baglanti dizesi/kimlik bilgisi
KONULMAZ. Bu bir honeypot/aldatma sistemidir; amaci sahte veriyle
saldirgani oyalamaktir - gercek sirlari saklamak icin TASARLANMAMISTIR ve
boyle kullanilmasi (gercek bir uretim sisteminin kimlik bilgilerini bu
depoya koymak) ciddi bir guvenlik hatasi olurdu. Profildeki alanlar
BILINCLI olarak sadece KIMLIK ve ILETISIM metadatasidir:
  - hangi sirket/varlik "korunuyor" (goruntu/marka amacli)
  - kritik bir olayda kime/nereye (webhook/e-posta) haber verilsin
Gercek altyapi kimlik bilgilerinizi ASLA bu dosyaya ya da ortam
degiskenine yazmayin.

--- Varsayilan davranis ---
Profil yapilandirilmamissa (dosya yok) sistem TAMAMEN ONCEKI GIBI, jenerik
"Arachne Sentinel" kimligiyle calisir - hicbir davranis degismez. Bu,
projenin "acikca yapilandirilmadan hicbir sey degismez" ilkesiyle
(bkz. llm_backend.py, threat_intel.py) birebir aynidir.

--- Nasil ayarlanir ---
`python main.py onboard` interaktif sihirbazi ile YA DA elle
`data/customer_profile.json` dosyasi olusturarak (bkz. docs/INTEGRATION.md).
Dosya konumu `ARACHNE_CUSTOMER_PROFILE` ortam degiskeniyle ezilebilir
(ornegin container'da farkli bir volume yoluna isaret etmek icin).
"""
import json
import logging
import os
from pathlib import Path

from .. import config

logger = logging.getLogger(__name__)

ENV_PROFILE_PATH = "ARACHNE_CUSTOMER_PROFILE"
DEFAULT_PROFILE_PATH = config.DATA_DIR / "customer_profile.json"

# Sadece KIMLIK/ILETISIM metadatasi - gercek sir/kimlik bilgisi ASLA.
DEFAULT_PROFILE = {
    "company_name": "Arachne Sentinel",
    "asset_name": "Demo Varlık",
    "asset_description": "Yapılandırılmamış - varsayılan demo kimliği",
    "contact_name": None,
    "alert_email": None,
    "alert_webhook_url": None,
}

FIELDS = list(DEFAULT_PROFILE.keys())

# Bu alan adlari GERCEK SIR gibi gorunuyorsa (yanlislikla) reddedilir -
# musterinin kazara buraya bir uretim kimlik bilgisi yapistirmasina karsi
# basit bir korkuluk (tam bir tarama degil, iyi-niyetli bir uyari).
_SUSPICIOUS_VALUE_MARKERS = (
    "postgres://", "mysql://", "mongodb://", "redis://",
    "-----begin", "aws_secret", "api_key=", "password=",
)


def _looks_like_real_secret(value) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in _SUSPICIOUS_VALUE_MARKERS)


def profile_path() -> Path:
    custom = os.environ.get(ENV_PROFILE_PATH)
    return Path(custom) if custom else DEFAULT_PROFILE_PATH


def is_configured() -> bool:
    return profile_path().exists()


def load_profile() -> dict:
    """Musteri profilini okur. Dosya yoksa/bozuksa GUVENLE varsayilana
    duser - ASLA istisna firlatmaz (profil katmanindaki bir sorun ana
    sistemi etkileyemez, diger karantina katmanlariyla ayni ilke)."""
    path = profile_path()
    if not path.exists():
        return dict(DEFAULT_PROFILE)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("Musteri profili okunamadi (%s) - varsayilana dusuluyor", path)
        return dict(DEFAULT_PROFILE)

    profile = dict(DEFAULT_PROFILE)
    for key in FIELDS:
        if key in data and data[key]:
            profile[key] = data[key]
    return profile


def save_profile(profile: dict, path=None) -> Path:
    """Profili diske kaydeder. Supheli (gercek sir gibi gorunen) degerler
    REDDEDILIR - `python main.py onboard` ve elle duzenlemeler icin ayni
    korkuluk."""
    target = Path(path) if path else profile_path()
    merged = dict(DEFAULT_PROFILE)
    for key in FIELDS:
        value = profile.get(key)
        if not value:
            continue
        if _looks_like_real_secret(value):
            raise ValueError(
                f"'{key}' alani gercek bir sir/kimlik bilgisi gibi gorunuyor "
                "('postgres://', 'password=' vb. iceriyor). Bu profil SADECE "
                "kimlik/iletisim metadatasi icindir - gercek altyapi "
                "kimlik bilgilerini buraya YAZMAYIN (bkz. modul basligi)."
            )
        merged[key] = value

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def status() -> dict:
    """Panelde/CLI'da gosterilecek durum (iletisim degerlerinin KENDISINI
    degil, sadece var/yok bilgisini dondurur - ayni 'anahtari sizdirma'
    ilkesi)."""
    profile = load_profile()
    return {
        "configured": is_configured(),
        "company_name": profile["company_name"],
        "asset_name": profile["asset_name"],
        "asset_description": profile["asset_description"],
        "contact_name_configured": bool(profile.get("contact_name")),
        "alert_email_configured": bool(profile.get("alert_email")),
        "alert_webhook_configured": bool(profile.get("alert_webhook_url")),
    }
