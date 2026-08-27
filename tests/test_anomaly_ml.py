"""Faz 106 - Davranissal anomali (Isolation Forest) testleri."""
from arachne import storage
from arachne.detection import anomaly_ml


def setup_function(_):
    # Her testten once bellek onbellegini temizle - testler birbirinden
    # izole olsun (model dosyasi/global cache sizmasin).
    anomaly_ml.clear_cache()


# --- Ozellik cikarimi ---------------------------------------------------

def test_extract_features_empty_events():
    features = anomaly_ml.extract_features([])
    assert features == [0.0, 0.0, 0.0, 0.0, 0.0]


def test_extract_features_counts_distinct_services_and_ports():
    events = [
        {"service": "ssh", "dest_port": 2222, "payload": "hello"},
        {"service": "ftp", "dest_port": 2121, "payload": "world"},
        {"service": "ssh", "dest_port": 2222, "payload": None},
    ]
    features = anomaly_ml.extract_features(events)
    event_count, distinct_services, distinct_ports, avg_len, avg_entropy = features
    assert event_count == 3
    assert distinct_services == 2
    assert distinct_ports == 2
    assert avg_len > 0
    assert avg_entropy > 0


# --- Puanlama: acikca normal vs acikca anormal profiller ayirt edilmeli ----

def test_normal_profile_scores_low():
    normal = [2, 1, 1, 15, 2.8]  # bundled 'normal' verideki tipik bir ornek
    result = anomaly_ml.score_features(normal)
    assert result["is_anomalous"] is False


def test_extreme_profile_scores_higher_than_normal():
    normal = [2, 1, 1, 15, 2.8]
    extreme = [500, 20, 40, 4000, 7.9]  # yogun tarama + yuksek entropi yuk
    normal_res = anomaly_ml.score_features(normal)
    extreme_res = anomaly_ml.score_features(extreme)
    assert extreme_res["anomaly_score"] > normal_res["anomaly_score"]
    assert extreme_res["is_anomalous"] is True


def test_score_features_reports_contributing_feature():
    extreme = [500, 20, 40, 4000, 7.9]
    result = anomaly_ml.score_features(extreme)
    assert result["contributing_feature"] in anomaly_ml.FEATURE_NAMES


def test_score_features_never_crashes_on_zero_vector():
    result = anomaly_ml.score_features([0.0, 0.0, 0.0, 0.0, 0.0])
    assert "anomaly_score" in result


# --- score_ip: gercek DB entegrasyonu ----------------------------------

def test_score_ip_on_empty_db(tmp_path):
    db = str(tmp_path / "empty.db")
    storage.init_db(db_path=db)
    result = anomaly_ml.score_ip("203.0.113.5", db_path=db)
    assert result["event_count"] == 0
    assert result["source_ip"] == "203.0.113.5"


def test_score_ip_with_heavy_scanning_activity(tmp_path):
    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    services = ["ssh", "ftp", "mysql", "http-admin", "redis", "telnet",
               "docker-api", "elasticsearch"]
    for i in range(60):
        storage.log_event("203.0.113.9", services[i % len(services)], "connect",
                          dest_port=1000 + (i % len(services)),
                          payload="A" * 50 + str(i), db_path=db)
    result = anomaly_ml.score_ip("203.0.113.9", db_path=db)
    assert result["event_count"] == 60
    assert result["features"]["distinct_services"] == len(services)


# --- Kendini onarma: bozuk/uyumsuz model dosyasi -----------------------

def test_self_heals_from_missing_model_file(tmp_path, monkeypatch):
    fake_path = tmp_path / "does_not_exist.joblib"
    monkeypatch.setattr(anomaly_ml, "MODEL_PATH", fake_path)
    anomaly_ml.clear_cache()

    model = anomaly_ml._get_model()
    assert anomaly_ml._model_is_usable(model)
    assert fake_path.exists()  # best-effort kaydetme basarili olmali


def test_self_heals_from_corrupted_model_file(tmp_path, monkeypatch):
    bad_path = tmp_path / "corrupt.joblib"
    bad_path.write_bytes(b"bu gecerli bir joblib/pickle dosyasi degil")
    monkeypatch.setattr(anomaly_ml, "MODEL_PATH", bad_path)
    anomaly_ml.clear_cache()

    # Cokmemeli - bozuk dosyayi tespit edip sessizce yeniden egitmeli.
    model = anomaly_ml._get_model()
    assert anomaly_ml._model_is_usable(model)


def test_train_and_save_creates_model_file(tmp_path):
    path = tmp_path / "anomaly_model.joblib"
    anomaly_ml.train_and_save(model_path=path)
    assert path.exists()


# --- threat_fusion entegrasyonu ----------------------------------------

def test_behavioral_anomaly_registered_in_threat_fusion():
    from arachne.adaptive import threat_fusion
    assert "behavioral_anomaly" in threat_fusion.DEFAULT_DETECTORS


def test_aggregator_coevolution_includes_behavioral_anomaly(tmp_path):
    from arachne.reporting import aggregator

    db = str(tmp_path / "t.db")
    storage.init_db(db_path=db)
    result = aggregator.coevolution_advanced(db_path=db)
    assert "behavioral_anomaly" in result
    assert result["behavioral_anomaly"]["count"] == 0  # bos DB -> 0-guvenli
