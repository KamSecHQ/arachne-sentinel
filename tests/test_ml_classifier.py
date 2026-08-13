import tempfile
from pathlib import Path

from arachne.detection import ml_classifier


def test_train_and_save_creates_model_file():
    tmp_path = Path(tempfile.mkdtemp()) / "model.joblib"
    model = ml_classifier.train_and_save(model_path=tmp_path)
    assert tmp_path.exists()
    assert model is not None


def test_classify_flags_obvious_sql_injection():
    is_malicious, confidence = ml_classifier.classify("' OR '1'='1' --")
    assert is_malicious is True
    assert confidence > 0.5


def test_classify_does_not_flag_obvious_benign_text():
    is_malicious, confidence = ml_classifier.classify("emirhan")
    assert is_malicious is False


def test_classify_handles_empty_payload():
    is_malicious, confidence = ml_classifier.classify("")
    assert is_malicious is False
    assert confidence == 0.0
