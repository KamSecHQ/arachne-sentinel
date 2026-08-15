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
import os
import secrets
import time

# Tekrar oynatma penceresi: bu suredan eski mesajlar reddedilir (saniye).
# 300sn (5 dk), sensor ile toplayici arasindaki makul saat farkini tolere
# ederken saldirgana pratik bir tekrar penceresi birakmaz.
REPLAY_WINDOW_SECONDS = 300

# Gorulen nonce'lar (tekrar tespiti icin). Pencere disi kayitlar temizlenir.
_seen_nonces = {}

ENV_SHARED_SECRET = "ARACHNE_MESH_SECRET"
# Lab varsayilani. URETIMDE ORTAM DEGISKENI ILE DEGISTIRILMELIDIR - bu
# deger acik kaynak depoda oldugu icin gizli sayilmaz.
DEFAULT_LAB_SECRET = "arachne-lab-shared-secret-degistirin"


def get_shared_secret() -> str:
    """Paylasilan sirri dondurur (ortam degiskeni onceliklidir)."""
    return os.environ.get(ENV_SHARED_SECRET) or DEFAULT_LAB_SECRET


def using_default_secret() -> bool:
    """Varsayilan lab sirri mi kullaniliyor? Panelde uyari gostermek icin."""
    return get_shared_secret() == DEFAULT_LAB_SECRET


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
