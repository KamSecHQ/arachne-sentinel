"""
Sensor agi icin mesaj kimlik dogrulama - HMAC-SHA256.

--- Cozdugumuz problem ---
Dagitik bir sensor agi, merkezi toplayiciya raporlar gonderir. Eger bu
raporlar dogrulanmazsa, herkes sahte "saldiri" raporlari gondererek:
  * paneli sahte verilerle doldurabilir
  * SOAR katmanini masum IP'leri engellemeye kandirabilir (!)
  * tehdit istihbaratini zehirleyebilir

Ikinci madde ozellikle kritik: kimlik dogrulamasi olmayan bir SOAR
sistemi, saldirganin elinde bir SILAHA donusur.

--- Cozum: HMAC + nonce + zaman damgasi ---
  * HMAC-SHA256 : mesajin gercekten paylasilan sirri bilen bir sensorden
                  geldigini kanitlar
  * zaman damgasi: eski mesajlarin tekrar oynatilmasini (replay) engeller
  * nonce        : ayni pencerede ayni mesajin tekrarini engeller

--- Neden `hmac.compare_digest`? ---
Duz `==` karsilastirmasi, ilk farkli byte'ta durur. Saldirgan cevap
suresini olcerek imzayi byte byte tahmin edebilir (timing attack).
`compare_digest` sabit surede calisir. Bu, kriptografide klasik ve
gercek bir tuzaktir - stdlib'in bu fonksiyonu tam da bunun icin vardir.
"""
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from .. import config

logger = logging.getLogger(__name__)

# Tekrar oynatma penceresi: bu suredan eski mesajlar reddedilir (saniye).
# 300sn (5 dk), sensor ile toplayici arasindaki makul saat farkini tolere
# ederken saldirgana pratik bir tekrar penceresi birakmaz.
REPLAY_WINDOW_SECONDS = 300

# Gorulen nonce'lar (tekrar tespiti icin). Pencere disi kayitlar temizlenir.
_seen_nonces = {}

ENV_SHARED_SECRET = "ARACHNE_MESH_SECRET"
# Guvenlik denetimi (SECURITY_AUDIT_TOB.md, Bulgu 1): depoda YAZILI sabit bir
# varsayilan sir, onu okuyan herkesin gecerli imzali sahte sensor raporlari
# uretmesine - yani auth'suz SOAR silahlandirmasina - izin verirdi. Artik
# repoda hicbir sir yok:
#   1. ARACHNE_MESH_SECRET ortam degiskeni (dagitik/uretim: iki uca da ayni
#      deger girilir) - onceliklidir.
#   2. Yoksa, her kuruluma OZGU, otomatik uretilen data/mesh_secret dosyasi
#      (0600, git disi) - panel_token ile ayni fail-secure desen. Tek-makineli
#      lab/demoda hem imzalayan hem dogrulayan ayni dosyayi okur.
#   3. Hicbiri saglanamazsa (ornegin data/ yazilamaz) sir None'dir; bu durumda
#      verify_message HER mesaji reddeder ve /mesh/ingest fiilen kapanir.
SECRET_FILE = config.DATA_DIR / "mesh_secret"


def _load_or_create_local_secret() -> str:
    """Kuruluma ozgu paylasilan sirri okur; yoksa 0600 ile uretir.

    panel_auth.panel_token ile ayni desen: O_EXCL ile yaris kosulsuz olusturur,
    varsa dosyadan okur. Uretemezse (izin/FS hatasi) None doner - fail-secure."""
    path = Path(SECRET_FILE)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            return path.read_text().strip() or None
        except OSError:
            return None
    except OSError:
        return None
    secret = secrets.token_urlsafe(32)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    return secret


def get_shared_secret() -> str:
    """Paylasilan sirri dondurur: ortam degiskeni > data/mesh_secret > None.

    None donebilir (hicbir sir saglanamadiginda); cagiranlar bunu fail-secure
    ele almalidir (verify_message reddeder, sign_message hata firlatir)."""
    env = os.environ.get(ENV_SHARED_SECRET)
    if env:
        return env
    return _load_or_create_local_secret()


def using_default_secret() -> bool:
    """Ortam degiskeni ayarlanmamis, kuruluma ozgu yerel sir mi kullaniliyor?

    Tek-makineli lab icin sorun degil; dagitik/uretimde ARACHNE_MESH_SECRET
    ayarlanmalidir. Panelde/demoda uyari gostermek icin kullanilir."""
    return not os.environ.get(ENV_SHARED_SECRET)


def generate_nonce() -> str:
    """Kriptografik olarak guvenli tek kullanimlik deger.

    `secrets` modulu kullanilir, `random` DEGIL: `random` ongorulebilir bir
    Mersenne Twister'dir ve guvenlik baglaminda kullanilmasi bir hatadir."""
    return secrets.token_hex(16)


def canonical_json(payload: dict) -> str:
    """Imzalama icin belirlenimci (deterministic) JSON gosterimi.

    Anahtarlar siralanir ve bosluklar sabitlenir. Aksi halde ayni sozluk
    farkli sirayla serilestirilebilir ve imza dogrulamasi rastgele
    basarisiz olur - hata ayiklamasi cok zor bir sinif hata."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_message(payload: dict, secret: str = None) -> dict:
    """Bir mesaji imzalar; imzali zarfi (envelope) dondurur."""
    secret = secret or get_shared_secret()
    if not secret:
        raise RuntimeError(
            "Mesh paylasilan sirri yok (ARACHNE_MESH_SECRET ayarli degil ve "
            "data/mesh_secret uretilemedi) - imzalama yapilamaz.")
    envelope = {
        "payload": payload,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
    }
    envelope["signature"] = _compute_signature(envelope, secret)
    return envelope


def _compute_signature(envelope: dict, secret: str) -> str:
    """Zarf uzerinde HMAC-SHA256 hesaplar (signature alani haric)."""
    signable = {
        "payload": envelope["payload"],
        "timestamp": envelope["timestamp"],
        "nonce": envelope["nonce"],
    }
    message = canonical_json(signable).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _prune_nonces(now: float):
    cutoff = now - REPLAY_WINDOW_SECONDS
    for nonce, seen_at in list(_seen_nonces.items()):
        if seen_at < cutoff:
            _seen_nonces.pop(nonce, None)


def verify_message(envelope: dict, secret: str = None,
                   check_replay: bool = True) -> tuple:
    """Imzali zarfi dogrular.

    Donen: (gecerli_mi: bool, sebep: str)

    Dogrulama sirasi bilincli: once ucuz yapisal kontroller, sonra pahali
    kriptografik islem. Ayrica hata mesajlari saldirgana bilgi sizdirmayacak
    kadar genel ama hata ayiklamaya yetecek kadar spesifik tutuldu."""
    secret = secret or get_shared_secret()
    if not secret:
        # Fail-secure: sir yoksa hicbir mesaj dogrulanamaz, dolayisiyla
        # /mesh/ingest fiilen kapanir (bkz. SECURITY_AUDIT_TOB.md, Bulgu 1).
        return False, "Mesh sirri yok - ingest devre disi (ARACHNE_MESH_SECRET ayarlayin)"

    if not isinstance(envelope, dict):
        return False, "Zarf bir JSON nesnesi degil"
    for field in ("payload", "timestamp", "nonce", "signature"):
        if field not in envelope:
            return False, f"Eksik alan: {field}"
    if not isinstance(envelope["payload"], dict):
        return False, "payload bir nesne olmali"

    now = time.time()
    try:
        ts = int(envelope["timestamp"])
    except (TypeError, ValueError):
        return False, "Gecersiz zaman damgasi"

    age = now - ts
    if age > REPLAY_WINDOW_SECONDS:
        return False, f"Mesaj cok eski ({int(age)}sn) - tekrar oynatma korumasi"
    if age < -REPLAY_WINDOW_SECONDS:
        return False, "Mesaj gelecekten geliyor - saat farki cok buyuk"

    expected = _compute_signature(envelope, secret)
    # Sabit surede karsilastirma - timing saldirisina karsi
    if not hmac.compare_digest(expected, str(envelope["signature"])):
        return False, "Imza dogrulanamadi - paylasilan sir uyusmuyor"

    if check_replay:
        nonce = str(envelope["nonce"])
        _prune_nonces(now)
        if nonce in _seen_nonces:
            return False, "Nonce daha once kullanildi - tekrar oynatma denemesi"
        _seen_nonces[nonce] = now

    return True, "Dogrulandi"


def clear_nonce_cache():
    """Nonce onbellegini temizler (testler icin)."""
    _seen_nonces.clear()


def nonce_cache_size() -> int:
    return len(_seen_nonces)
