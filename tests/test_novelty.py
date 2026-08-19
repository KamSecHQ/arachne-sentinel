"""Faz 42 - Sifir-gun sezgisi / yenilik (novelty) tespiti testleri."""
from arachne.adaptive import novelty


def test_char_ngrams_basic():
    grams = novelty.char_ngrams("abcd", 3)
    assert grams == ["abc", "bcd"]


def test_char_ngrams_short_text():
    # n'den kisa metin tek n-gram olarak dondurulur.
    assert novelty.char_ngrams("ab", 3) == ["ab"]
    assert novelty.char_ngrams("", 3) == []


def test_train_builds_profile():
    model = novelty.NoveltyModel(n=3)
    ret = model.train(["hello world", "hello there"])
    assert ret is model  # zincirlenebilir
    # Egitilmis payload'un yeniligi dusuk olmali (kendisiyle tanidik).
    res = model.novelty("hello world")
    assert res["novelty"] < 0.3
    assert res["is_novel"] is False


def test_novel_payload_flagged():
    model = novelty.NoveltyModel(n=3)
    model.train(["' OR '1'='1", "admin' --", "UNION SELECT password FROM users"])
    # Tamamen alakasiz/gorulmemis bir desen -> yuksek yenilik.
    res = model.novelty("zzqwxk_jjvvbb_plmnko_9382")
    assert res["is_novel"] is True
    assert res["novelty"] >= 0.6


def test_known_attack_low_novelty():
    model = novelty.default_model()
    res = model.novelty("' OR '1'='1")
    assert res["is_novel"] is False
    assert res["novelty"] < 0.6


def test_default_model_scores_out_of_box():
    model = novelty.default_model()
    res = model.novelty("<script>alert(1)</script>")
    assert "novelty" in res
    assert res["is_novel"] is False  # yerlesik korpusta var


def test_default_model_flags_unusual():
    model = novelty.default_model()
    res = model.novelty("テストçğıö novel payload xyzzy")
    assert res["is_novel"] is True


def test_empty_payload():
    model = novelty.default_model()
    res = model.novelty("")
    assert res["novelty"] == 0.0
    assert res["is_novel"] is False


def test_untrained_model_is_honest():
    model = novelty.NoveltyModel(n=3)
    res = model.novelty("anything")
    # Egitilmemis model: her sey yeni gorunur ama durustce belirtilir.
    assert res["is_novel"] is True
    assert "egitilmemis" in res["verdict"].lower()


def test_novelty_output_keys():
    model = novelty.default_model()
    res = model.novelty("some input here")
    for key in ("novelty", "rare_ngram_ratio", "verdict", "is_novel"):
        assert key in res
    assert isinstance(res["verdict"], str)


def test_determinism_same_input_same_output():
    model = novelty.default_model()
    payload = "'; DROP TABLE sessions; -- unusual tail 9931"
    assert model.novelty(payload) == model.novelty(payload)


def test_rare_count_threshold_effect():
    model = novelty.NoveltyModel(n=3)
    model.train(["aaa aaa aaa", "aaa bbb"])
    # rare_count arttikca dusuk-frekansli n-gram'lar da nadir sayilir ->
    # yenilik artar (monotonik olmayan degil, en az esit).
    low = model.novelty("aaa ccc", rare_count=1)["novelty"]
    high = model.novelty("aaa ccc", rare_count=3)["novelty"]
    assert high >= low
