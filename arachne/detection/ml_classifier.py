"""
Kural motoruna EK bir sinyal olarak calisan, denetimli ogrenme tabanli
saldiri payload siniflandiricisi.

Neden kural motorunun yerine degil de yanina eklendi? Kural motoru
aciklanabilir ama sadece "bildigi" imzalari yakalar. ML modeli, karakter
n-gram'lari sayesinde hafif obfuske edilmis ya da kural setinde tam olarak
yer almayan varyasyonlari da yakalayabilir. Ikisi birlikte, tek basina
hicbirinin yakalayamayacagi bir kapsama alani saglar.
"""
import logging

from .. import config

logger = logging.getLogger("arachne.ml")

_model = None


def _build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=1)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def _fit_pipeline():
    """Bundled egitim verisiyle taze bir pipeline egitir (diske YAZMAZ).
    Surumden bagimsizdir — her sklearn surumunde ayni kodla yeniden uretilir."""
    from .training_data import BENIGN_SAMPLES, MALICIOUS_SAMPLES

    X = MALICIOUS_SAMPLES + BENIGN_SAMPLES
    y = [1] * len(MALICIOUS_SAMPLES) + [0] * len(BENIGN_SAMPLES)

    pipeline = _build_pipeline()
    pipeline.fit(X, y)
    return pipeline


def train_and_save(model_path=None):
    """Egitim verisiyle modeli egitir ve diske kaydeder. Donen: egitilmis pipeline."""
    import joblib

    pipeline = _fit_pipeline()
    path = model_path or config.ML_MODEL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)
    logger.info("ML modeli egitildi ve kaydedildi: %s", path)
    return pipeline


def _model_is_usable(model) -> bool:
    """Yuklenen modelin gercekten calistigini dogrular. Surumler-arasi pickle
    (or. baska bir sklearn surumuyle egitilmis model) TfidfVectorizer'i 'not
    fitted' birakabilir; boyle bir modeli tespit edip reddederiz."""
    try:
        model.predict_proba(["test"])
        return True
    except Exception:
        return False


def _get_model():
    global _model
    if _model is not None:
        return _model

    # 1) Kayitli modeli yuklemeyi dene; ama SADECE gercekten calisiyorsa kullan.
    #    (Surumler-arasi joblib pickle 'idf vector is not fitted' verebilir.)
    if config.ML_MODEL_PATH.exists():
        try:
            import joblib
            candidate = joblib.load(config.ML_MODEL_PATH)
            if _model_is_usable(candidate):
                _model = candidate
                return _model
            logger.warning("Kayitli ML modeli bu ortamda calismiyor (muhtemelen "
                           "surumler-arasi pickle); bundled veriyle yeniden egitiliyor.")
        except Exception:
            logger.warning("Kayitli ML modeli yuklenemedi; yeniden egitiliyor.",
                           exc_info=True)

    # 2) Yok ya da bozuk: taze egit. Diske kaydetmeyi dene (best-effort);
    #    yazamasak bile bellekteki model calisir.
    _model = _fit_pipeline()
    try:
        import joblib
        config.ML_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_model, config.ML_MODEL_PATH)
        logger.info("ML modeli yeniden egitildi ve kaydedildi: %s", config.ML_MODEL_PATH)
    except Exception:
        logger.warning("Yeniden egitilen model kaydedilemedi (salt-okunur olabilir); "
                       "bellekten kullaniliyor.", exc_info=True)
    return _model


def classify(payload: str):
    """Verilen metni siniflandirir.

    Donen: (is_malicious: bool, confidence: float) - confidence, modelin
    "zararli" sinifina verdigi olasiliktir (0.0 - 1.0).
    """
    if not payload or not payload.strip():
        return False, 0.0

    model = _get_model()
    proba = model.predict_proba([payload])[0]
    # class 1 = zararli (bkz. train_and_save icindeki etiketleme)
    classes = list(model.named_steps["clf"].classes_)
    malicious_idx = classes.index(1)
    confidence = float(proba[malicious_idx])
    return confidence >= 0.5, confidence
