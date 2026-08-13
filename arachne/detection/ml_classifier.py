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


def train_and_save(model_path=None):
    """Egitim verisiyle modeli egitir ve diske kaydeder. Donen: egitilmis pipeline."""
    import joblib

    from .training_data import BENIGN_SAMPLES, MALICIOUS_SAMPLES

    X = MALICIOUS_SAMPLES + BENIGN_SAMPLES
    y = [1] * len(MALICIOUS_SAMPLES) + [0] * len(BENIGN_SAMPLES)

    pipeline = _build_pipeline()
    pipeline.fit(X, y)

    path = model_path or config.ML_MODEL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)
    logger.info("ML modeli egitildi ve kaydedildi: %s", path)
    return pipeline


def _get_model():
    global _model
    if _model is not None:
        return _model

    import joblib

    if config.ML_MODEL_PATH.exists():
        _model = joblib.load(config.ML_MODEL_PATH)
    else:
        _model = train_and_save()
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
