"""Faz 23 - Aldatma agi & kirinti yolu testleri."""
from arachne.adaptive import deception_grid


def _grid():
    return deception_grid.DeceptionGrid(seed=1337).build_default()


def test_build_default_has_all_kinds():
    grid = _grid()
    kinds = {n["kind"] for n in grid.nodes.values()}
    assert kinds == {"real", "breadcrumb", "decoy"}
    # En az bir gercek capa, bir kirinti, uc tier yem olmali.
    tiers = {n["tier"] for n in grid.nodes.values() if n["kind"] == "decoy"}
    assert tiers == {1, 2, 3}


def test_decoys_have_honeytokens():
    grid = _grid()
    for n in grid.nodes.values():
        if n["kind"] == "decoy":
            assert n.get("honeytoken_id", "").startswith("SAHTE-")


def test_deterministic_honeytokens_with_seed():
    a = deception_grid.DeceptionGrid(seed=42).build_default()
    b = deception_grid.DeceptionGrid(seed=42).build_default()
    ha = {i: n.get("honeytoken_id") for i, n in a.nodes.items()}
    hb = {i: n.get("honeytoken_id") for i, n in b.nodes.items()}
    assert ha == hb


def test_record_touch_unknown_node_graceful():
    grid = _grid()
    assert grid.record_touch("does-not-exist", "10.0.0.9") is False
    depth = grid.intruder_depth("10.0.0.9")
    assert depth["is_breach"] is False
    assert depth["path"] == []


def test_intruder_depth_no_touch():
    grid = _grid()
    depth = grid.intruder_depth("192.0.2.1")
    assert depth["max_tier"] == 0
    assert depth["decoy_touches"] == 0
    assert depth["is_breach"] is False


def test_breadcrumb_only_touch_not_breach():
    grid = _grid()
    grid.record_touch("ws-01", "192.0.2.5")       # gercek capa
    grid.record_touch("bc-ws-cred", "192.0.2.5")  # kirinti
    depth = grid.intruder_depth("192.0.2.5")
    assert depth["is_breach"] is False
    assert depth["path"] == ["ws-01", "bc-ws-cred"]


def test_decoy_touch_is_breach_zero_fp():
    # KILIT SENARYO: tier-1 tuzagini atlayip kirintiyi izleyen sofistike
    # saldirgan tier-2 yeminde yakalanir -> ihlal, sifir yanlis pozitif.
    grid = _grid()
    ip = "203.0.113.7"
    grid.record_touch("bc-fs-drive", ip)   # kirinti
    grid.record_touch("decoy-t2-db", ip)   # tier-2 yem (tier-1 atlandi)
    depth = grid.intruder_depth(ip)
    assert depth["is_breach"] is True
    assert depth["max_tier"] == 2
    assert depth["decoy_touches"] == 1
    assert "IHLAL" in depth["verdict"]


def test_intruder_depth_tracks_max_tier_and_order():
    grid = _grid()
    ip = "203.0.113.8"
    for node in ("bc-ws-cred", "decoy-t1-jump", "decoy-t2-db", "decoy-t3-dc"):
        grid.record_touch(node, ip)
    depth = grid.intruder_depth(ip)
    assert depth["max_tier"] == 3
    assert depth["decoy_touches"] == 3
    assert depth["path"][0] == "bc-ws-cred"
    assert depth["path"][-1] == "decoy-t3-dc"


def test_plant_breadcrumbs_are_marked_fake():
    grid = _grid()
    lures = grid.plant_breadcrumbs()
    assert lures  # bos degil
    for lure in lures:
        assert lure["is_fake"] is True
        assert "SAHTE" in lure["value"]
        assert lure["lure_type"] in deception_grid._LURE_TYPES


def test_grid_summary_counts_and_zero_fp_note():
    grid = _grid()
    grid.record_touch("decoy-t1-jump", "203.0.113.10")
    summary = grid.grid_summary()
    assert summary["by_kind"]["decoy"] == 3
    assert summary["decoys_by_tier"] == {1: 1, 2: 1, 3: 1}
    assert summary["total_breadcrumbs"] == summary["by_kind"]["breadcrumb"]
    assert summary["active_intruders"] == 1
    assert summary["breached_intruders"] == 1
    assert "yanlis pozitif" in summary["zero_false_positive_note"]


def test_multiple_intruders_independent():
    grid = _grid()
    grid.record_touch("decoy-t3-dc", "1.1.1.1")
    grid.record_touch("bc-ws-rdp", "2.2.2.2")
    a = grid.intruder_depth("1.1.1.1")
    b = grid.intruder_depth("2.2.2.2")
    assert a["is_breach"] is True and a["max_tier"] == 3
    assert b["is_breach"] is False and b["max_tier"] == 0
