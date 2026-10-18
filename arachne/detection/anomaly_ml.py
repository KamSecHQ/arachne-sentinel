"""
Faz 106 - Davranissal anomali tespiti (Isolation Forest tabanli ikinci ML sinyali).

--- Neden ikinci bir ML modeli? ---
`ml_classifier.py` (Faz 2) TEK bir payload METNINE bakar (TF-IDF karakter
n-gram + Lojistik Regresyon) - "bu metin zararli mi gorunuyor?" sorusunu
cevaplar. Bu modul TAMAMEN FARKLI bir soruya bakar: "bu IP'nin ZAMAN
ICINDEKI DAVRANISI normalden sapiyor mu?" - tek bir payload'a degil, bir
IP'nin olay hizina, farkli servis/port sayisina, yuk uzunluk/entropi
istatistiklerine bakar (davranissal ozellik vektoru). Ikisi birbirini
TAMAMLAR: metin-tabanli siniflandirici hafif obfuske edilmis TEK bir
saldiriyi yakalayabilir ama yavas/dagitik bir tarama kampanyasini
gormeyebilir - davranissal anomali onu yakalar.

--- Kendini onarma kalibi (ml_classifier.py'den BIREBIR alindi) ---
Ayni "surumler-arasi pickle uyumsuzlugu" sorunu (bkz. ml_classifier.py'nin
`_model_is_usable`/`_get_model` fonksiyonlari ve proje git tarihindeki
"ML modeli surumler-arasi pickle uyumsuzlugunda kendini yeniden egitir"
duzeltmesi) bu model icin de gecerlidir - o yuzden AYNI savunma kalibi
(gercek bir `decision_function` cagrisiyla dogrulama, basarisizsa bellekte
yeniden egitim, best-effort diske kaydetme) burada da uygulanir.

--- Entegrasyon ---
Temel kural motoruna (rules.ALL_RULES) DOGRUDAN eklenmez - bunun yerine
`adaptive/threat_fusion.py`'nin (Faz 43) Bayes log-odds fuzyonuna
"behavioral_anomaly" adiyla BAGIMSIZ bir kanit olarak beslenir (bkz.
aggregator.coevolution_advanced). Gerekce: proje zaten "tek dedektoru
atlatmak sistemi atlatmaz" ilkesini ensemble/fuzyon katmanlarinda
uyguluyor (Faz 24, Faz 43); davranissal anomaliyi oraya eklemek temel
kural motorunu basit/denetlenebilir tutarken bilesik tespiti guclendirir.

--- DURUSTLUK NOTU ---
"Normal" taban cizgisi (bkz. behavioral_training_data.py) gercek uretim
trafiginden OGRENILMEMISTIR - kucuk, elle yazilmis, illustratif bir
sentetik veri kumesidir (Faz 2'nin egitim verisiyle ayni olcekte ve ayni
felsefede). anomaly_score kesin kalibre bir olasilik degil, Isolation
Forest'in decision_function ciktisinin 0-100'e sikistirilmis, aciklayici
bir donusumudur.
"""
import logging

from .. import config
from . import model_integrity

logger = logging.getLogger("arachne.anomaly_ml")

FEATURE_NAMES = ["event_count", "distinct_services", "distinct_ports",
                 "avg_payload_length", "avg_entropy"]

MODEL_PATH = config.DATA_DIR / "anomaly_ml_model.joblib"
# Butunluk sabitlemesi icin ortam degiskeni (bkz. model_integrity, Bulgu 3).
ANOMALY_MODEL_SHA256_ENV = "ARACHNE_ANOMALY_MODEL_SHA256"

_model = None


def _build_model():
    from sklearn.ensemble import IsolationForest
    return IsolationForest(n_estimators=100, contamination=0.2, random_state=42)


def _fit_model():
    """Bundled sentetik veriyle taze bir model egitir (diske YAZMAZ)."""
    from .behavioral_training_data import NORMAL_FEATURE_SAMPLES

    model = _build_model()
    model.fit(NORMAL_FEATURE_SAMPLES)
    return model


def train_and_save(model_path=None):
    """Bundled veriyle modeli egitir ve diske kaydeder. Donen: egitilmis model."""
    import joblib

    model = _fit_model()
    path = model_path or MODEL_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    model_integrity.write_manifest(path)
    logger.info("Davranissal anomali modeli egitildi ve kaydedildi: %s", path)
    return model


def _model_is_usable(model) -> bool:
    """Yuklenen modelin gercekten calistigini dogrular (bkz. modul basligi -
    ml_classifier.py'nin `_model_is_usable` fonksiyonuyla ayni gerekce)."""
    try:
        model.decision_function([[1.0, 1.0, 1.0, 10.0, 2.0]])
        return True
    except Exception:
        return False


def _get_model():
    global _model
    if _model is not None:
        return _model

    # Butunluk: guvenilir referans yoksa pickle'i YUKLEMEYIZ (bkz. Bulgu 3).
    trusted, reason = model_integrity.verify(MODEL_PATH, ANOMALY_MODEL_SHA256_ENV)
    if trusted:
        try:
            import joblib
            candidate = joblib.load(MODEL_PATH)
            if _model_is_usable(candidate):
                _model = candidate
                return _model
            logger.warning("Kayitli anomali modeli bu ortamda calismiyor (muhtemelen "
                           "surumler-arasi pickle); bundled veriyle yeniden egitiliyor.")
        except Exception:
            logger.warning("Kayitli anomali modeli yuklenemedi; yeniden egitiliyor.",
                           exc_info=True)
    else:
        logger.warning("Kayitli anomali modeli butunluk dogrulamasindan gecemedi (%s); "
                       "pickle yuklenmeden bundled veriyle yeniden egitiliyor.", reason)

    _model = _fit_model()
    try:
        import joblib
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(_model, MODEL_PATH)
        model_integrity.write_manifest(MODEL_PATH)
        logger.info("Anomali modeli yeniden egitildi ve kaydedildi: %s", MODEL_PATH)
    except Exception:
        logger.warning("Yeniden egitilen anomali modeli kaydedilemedi (salt-okunur "
                       "olabilir); bellekten kullaniliyor.", exc_info=True)
    return _model


def clear_cache():
    """Bellekteki model onbellegini temizler (testler icin)."""
    global _model
    _model = None


def extract_features(events: list) -> list:
    """Bir IP'nin olay listesinden davranissal ozellik vektoru cikarir.

    Olay yoksa tum ozellikler 0.0 - "sessiz/hic gorulmemis" bir IP anormal
    sayilmaz, sadece notrdur."""
    from ..reverse.advanced_decoder import shannon_entropy

    if not events:
        return [0.0, 0.0, 0.0, 0.0, 0.0]

    services = set()
    ports = set()
    lengths = []
    entropies = []
    for e in events:
        if e.get("service"):
            services.add(e["service"])
        if e.get("dest_port") is not None:
            ports.add(e["dest_port"])
        payload = e.get("payload")
        if payload:
            text = str(payload)
            lengths.append(len(text))
            entropies.append(shannon_entropy(text))

    avg_length = sum(lengths) / len(lengths) if lengths else 0.0
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

    return [float(len(events)), float(len(services)), float(len(ports)),
            avg_length, avg_entropy]


def _feature_baseline():
    """Bundled 'normal' verinin ortalama/std'si - aciklanabilirlik icin."""
    from .behavioral_training_data import NORMAL_FEATURE_SAMPLES

    columns = list(zip(*NORMAL_FEATURE_SAMPLES))
    means = [sum(col) / len(col) for col in columns]
    stds = []
    for i, col in enumerate(columns):
        variance = sum((v - means[i]) ** 2 for v in col) / len(col)
        stds.append(variance ** 0.5 or 1.0)  # 0 std'yi 1'e sikistir (bolme guvenligi)
    return means, stds


def score_features(features: list) -> dict:
    """Ham ozellik vektorunu puanlar - ag/DB erisimi yok, saf fonksiyon."""
    model = _get_model()
    raw_score = float(model.decision_function([features])[0])
    # decision_function: pozitif = normale yakin, negatif = anormal. Kaba ama
    # aciklanabilir bir 0-100 donusumu (kesin kalibrasyon iddia edilmez).
    anomaly_score = max(0, min(100, round((0.5 - raw_score) * 100)))
    is_anomalous = bool(model.predict([features])[0] == -1)

    means, stds = _feature_baseline()
    deviations = [abs(features[i] - means[i]) / stds[i] for i in range(len(features))]
    top_idx = max(range(len(deviations)), key=lambda i: deviations[i])

    return {
        "anomaly_score": anomaly_score,
        "is_anomalous": is_anomalous,
        "raw_decision_score": round(raw_score, 4),
        "contributing_feature": FEATURE_NAMES[top_idx],
        "features": dict(zip(FEATURE_NAMES, features)),
    }


def score_ip(source_ip: str, db_path=None, since_seconds: int = 7200) -> dict:
    """Bir IP'nin son `since_seconds` icindeki davranisini puanlar."""
    from .. import storage

    events = storage.get_recent_events(source_ip=source_ip, since_seconds=since_seconds,
                                        db_path=db_path)
    result = score_features(extract_features(events))
    result["source_ip"] = source_ip
    result["event_count"] = len(events)
    return result
