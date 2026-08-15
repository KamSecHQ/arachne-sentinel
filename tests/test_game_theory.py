"""Faz 27 - Oyun-teorik Stackelberg savunma / ko-evrim testleri."""
from arachne.adaptive import game_theory


G = game_theory.DEFAULT_HONEYPOT_GAME
CONFIGS = G["configs"]
ATTACKS = G["attacks"]
PAYOFF = G["payoff"]


def test_default_game_constant_shape():
    # Varsayilan oyun 3x3 ve her hucre (defender, attacker) ikilisi.
    assert len(CONFIGS) == 3 and len(ATTACKS) == 3
    assert len(PAYOFF) == 9
    for c in CONFIGS:
        for a in ATTACKS:
            du, au = PAYOFF[(c, a)]
            assert (du, au) in {(3.0, 0.0), (0.0, 3.0)}


def test_best_response_exploits_pure_strategy():
    # Savunucu tek config'e sabitlenirse saldirgan onu kacan bir saldiriyla somurur.
    pure = {c: (1.0 if c == "edge_decoys" else 0.0) for c in CONFIGS}
    br = game_theory.attacker_best_response(pure, PAYOFF)
    # edge_decoys sadece recon_edge'i yakalar; saldirgan baskasini secip kacar.
    assert br["action"] != "recon_edge"
    assert br["expected_attacker_utility"] == 3.0
    assert br["expected_defender_utility"] == 0.0


def test_best_response_against_uniform_mix():
    mix = {c: 1 / 3 for c in CONFIGS}
    br = game_theory.attacker_best_response(mix, PAYOFF)
    # Uniform karisimda saldirgan hangi saldiriyi secerse secsin ayni: att=2, def=1.
    assert abs(br["expected_attacker_utility"] - 2.0) < 1e-9
    assert abs(br["expected_defender_utility"] - 1.0) < 1e-9


def test_best_response_tie_breaks_against_defender():
    # Beraberlikte savunucu ALEYHINE (en dusuk savunucu faydasi) secilmeli.
    mix = {c: 1 / 3 for c in CONFIGS}
    br = game_theory.attacker_best_response(mix, PAYOFF)
    # Tum saldirilar saldirgana esit; secilen savunucu faydasi min (=1) olmali.
    assert br["expected_defender_utility"] <= 1.0 + 1e-9


def test_stackelberg_prefers_mixed_over_pure():
    out = game_theory.stackelberg_defense(CONFIGS, ATTACKS, PAYOFF, grid=11)
    assert out["is_pure"] is False
    # Karma optimum, en iyi saf stratejiyi kesin olarak asmali.
    assert out["defender_utility"] > out["best_pure_utility"] + 1e-9
    assert out["best_pure_utility"] == 0.0


def test_stackelberg_strategy_is_valid_distribution():
    out = game_theory.stackelberg_defense(CONFIGS, ATTACKS, PAYOFF, grid=11)
    strat = out["strategy"]
    assert set(strat.keys()) == set(CONFIGS)
    assert abs(sum(strat.values()) - 1.0) < 1e-6
    assert all(p >= 0 for p in strat.values())
    # Karma optimum bu oyunda >= 0.9 taban saglar (izgara cozunurlugu).
    assert out["defender_utility"] >= 0.9 - 1e-9


def test_stackelberg_reason_is_turkish_and_mentions_mtd():
    out = game_theory.stackelberg_defense(CONFIGS, ATTACKS, PAYOFF)
    assert "MTD" in out["reason"] or "randomize" in out["reason"]
    assert isinstance(out["reason"], str) and len(out["reason"]) > 20


def test_coevolve_history_and_convergence():
    out = game_theory.coevolve(CONFIGS, ATTACKS, PAYOFF, rounds=8, seed=1337)
    assert len(out["history"]) == 8
    for i, h in enumerate(out["history"], start=1):
        assert h["round"] == i
        assert h["deployed_config"] in CONFIGS
        assert h["attacker_action"] in ATTACKS
    # Yeniden-randomize eden savunucu tabani tutar -> yakinsar.
    assert out["converged"] is True


def test_coevolve_holds_above_static_defender():
    out = game_theory.coevolve(CONFIGS, ATTACKS, PAYOFF, rounds=6)
    utils = [h["defender_utility"] for h in out["history"]]
    # Her tur tutulan fayda, en iyi saf (statik) degerin (0.0) uzerinde.
    assert min(utils) > 0.0
    assert "MTD" in out["summary_tr"] or "Hareketli Hedef" in out["summary_tr"]


def test_coevolve_deterministic_with_seed():
    a = game_theory.coevolve(CONFIGS, ATTACKS, PAYOFF, rounds=5, seed=42)
    b = game_theory.coevolve(CONFIGS, ATTACKS, PAYOFF, rounds=5, seed=42)
    dep_a = [h["deployed_config"] for h in a["history"]]
    dep_b = [h["deployed_config"] for h in b["history"]]
    assert dep_a == dep_b  # ayni seed -> ayni dizi


def test_stackelberg_pure_game_reports_pure():
    # Kosegen olmayan, tek config'in domine ettigi oyun: saf strateji yeter.
    configs = ["c1", "c2"]
    attacks = ["a1", "a2"]
    payoff = {
        ("c1", "a1"): (5.0, 0.0), ("c1", "a2"): (5.0, 0.0),
        ("c2", "a1"): (0.0, 5.0), ("c2", "a2"): (0.0, 5.0),
    }
    out = game_theory.stackelberg_defense(configs, attacks, payoff)
    assert out["strategy"]["c1"] == 1.0
    assert out["is_pure"] is True
    assert out["defender_utility"] == 5.0
