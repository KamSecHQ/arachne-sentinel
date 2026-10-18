"""
Model dosyasi butunluk dogrulamasi (SECURITY_AUDIT_TOB.md, Bulgu 3).

--- Cozdugumuz problem ---
ML/anomali modelleri `joblib.load` ile yuklenir; joblib ozunde `pickle`
kullanir ve pickle cozumleme GUVENILMEYEN veride rastgele kod calistirir.
`data/` dizinine yazabilen bir aktor (paylasilan Docker volume, dusuk yetkili
yerel kullanici, `data/`'ya ulasan bir yol-ge6isi) zararli bir `.joblib`
birakirsa, bir sonraki yukleme RCE'ye yukselir.

--- Cozum: guvenilir referans olmadan pickle YUKLEME ---
Onemli gozlem: model dosyasi yalnizca bir ONBELLEKTIR. Her iki siniflandirici
da `_fit_pipeline()/_fit_model()` ile modeli bundled egitim verisinden saf
kodla yeniden uretebilir (surumden bagimsiz). Dolayisiyla en guvenli varsayilan,
dogrulanamayan bir pickle'i yuklemek yerine yeniden egitmektir - islevsellik
kaybi yok, saldiri yuzeyi kapali.

Dogrulama referansi onceligi:
  1. Ortam degiskeni ile SABITLENEN SHA-256 ( or. ARACHNE_ML_MODEL_SHA256) -
     `data/` disinda tutuldugu icin data/ yazabilen bir saldirgandan etkilenmez;
     uretimde onerilen sertlestirme budur.
  2. Model yaninda, kaydetme aninda yazilan sidecar manifest (`<model>.sha256`).
     Bu, bozulmayi ve kismi kurcalamayi yakalar; ancak `data/`'ya tam yazma
     erisimi olan bir saldirgan hem modeli hem manifesti degistirebilir -
     bu yuzden tek basina yeterli DEGILDIR (bkz. 1 ve salt-okunur mount).
  3. Hicbir referans yoksa: dogrulama BASARISIZ sayilir; cagiran pickle'i
     yuklemez, modeli yeniden egitir.
"""
import hashlib
import hmac
import logging
import os
from pathlib import Path

logger = logging.getLogger("arachne.model_integrity")

_CHUNK = 1 << 16


def file_sha256(path) -> str:
    """Dosyanin SHA-256'sini parca parca hesaplar (bellege tumuyle almadan)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sidecar_path(model_path) -> Path:
    p = Path(model_path)
    return p.with_name(p.name + ".sha256")


def write_manifest(model_path) -> None:
    """Modelin yaninda SHA-256 manifestini yazar (0600). Kaydetmeden SONRA cagrilir.

    Hata durumunda sessizce gecer: manifest yazilamazsa bir sonraki yukleme
    'referans yok' sayar ve yeniden egitir - yine fail-secure."""
    try:
        digest = file_sha256(model_path)
        sc = sidecar_path(model_path)
        fd = os.open(sc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(digest + "\n")
    except OSError:
        logger.warning("Model manifesti yazilamadi: %s", model_path, exc_info=True)


def verify(model_path, env_var: str = None) -> tuple:
    """Modeli yuklemeden ONCE butunlugunu dogrular.

    Donen: (guvenilir_mi: bool, sebep: str). False ise cagiran pickle'i
    YUKLEMEMELI, bunun yerine modeli yeniden egitmelidir."""
    model_path = Path(model_path)
    if not model_path.exists():
        return False, "model dosyasi yok"
    try:
        actual = file_sha256(model_path)
    except OSError:
        return False, "model dosyasi okunamadi"

    pinned = os.environ.get(env_var) if env_var else None
    if pinned:
        if hmac.compare_digest(actual, pinned.strip().lower()):
            return True, "ortam degiskeni ile sabitlenen hash dogrulandi"
        return False, f"hash ortam degiskeniyle uyusmuyor ({env_var})"

    sc = sidecar_path(model_path)
    if sc.exists():
        try:
            expected = sc.read_text().strip().split()[0].lower()
        except (OSError, IndexError):
            return False, "sidecar manifest okunamadi"
        if hmac.compare_digest(actual, expected):
            return True, "sidecar manifest dogrulandi"
        return False, "model hash'i sidecar manifest ile uyusmuyor - kurcalanmis olabilir"

    return False, "guvenilir referans yok (ne ortam degiskeni ne sidecar) - pickle yuklenmeyecek"
