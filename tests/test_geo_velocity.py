"""Faz 44 - Imkansiz seyahat / cografi hiz testleri."""
import math

from arachne.adaptive import geo_velocity as gv


def test_haversine_same_point_zero():
    assert gv.haversine_km(40.0, 29.0, 40.0, 29.0) == 0.0


def test_haversine_known_distance():
    # Londra (51.5074,-0.1278) - Paris (48.8566,2.3522) ~ 343 km.
    d = gv.haversine_km(51.5074, -0.1278, 48.8566, 2.3522)
    assert 330 < d < 360


def test_required_speed_basic():
    # 900 km, 1 saat -> 900 km/s.
    assert abs(gv.required_speed_kmh(900.0, 3600.0) - 900.0) < 1e-6


def test_required_speed_same_instant_is_inf():
    assert gv.required_speed_kmh(500.0, 0.0) == float("inf")
    assert gv.required_speed_kmh(500.0, -10.0) == float("inf")


def test_required_speed_zero_distance():
    assert gv.required_speed_kmh(0.0, 3600.0) == 0.0


def test_first_observation_not_impossible():
    mon = gv.GeoVelocityMonitor()
    r = mon.observe("alice", 51.5074, -0.1278, 1000.0)
    assert r["impossible_travel"] is False
    assert r["required_speed_kmh"] == 0.0


def test_impossible_travel_detected():
    mon = gv.GeoVelocityMonitor(max_speed_kmh=900.0)
    # Londra t=0, Singapur t=+1saat -> ~10800 km / 1saat imkansiz.
    mon.observe("bob", 51.5074, -0.1278, 0.0)
    r = mon.observe("bob", 1.3521, 103.8198, 3600.0)
    assert r["impossible_travel"] is True
    assert r["required_speed_kmh"] > 900.0
    assert "IMKANSIZ" in r["verdict_tr"]


def test_plausible_travel_not_flagged():
    mon = gv.GeoVelocityMonitor(max_speed_kmh=900.0)
    # Londra -> Paris (~343 km) 2 saatte -> ~170 km/s, mumkun.
    mon.observe("carol", 51.5074, -0.1278, 0.0)
    r = mon.observe("carol", 48.8566, 2.3522, 7200.0)
    assert r["impossible_travel"] is False
    assert r["required_speed_kmh"] < 900.0


def test_same_instant_different_place_impossible():
    mon = gv.GeoVelocityMonitor()
    mon.observe("dave", 51.5074, -0.1278, 500.0)
    r = mon.observe("dave", 40.7128, -74.0060, 500.0)  # ayni an, NYC
    assert r["impossible_travel"] is True
    assert math.isinf(r["required_speed_kmh"])


def test_report_summarizes_flags():
    mon = gv.GeoVelocityMonitor(max_speed_kmh=900.0)
    mon.observe("eve", 51.5074, -0.1278, 0.0)
    mon.observe("eve", 1.3521, 103.8198, 3600.0)   # imkansiz
    mon.observe("frank", 51.5074, -0.1278, 0.0)    # tek gozlem, temiz
    rep = mon.report()
    assert rep["flagged_count"] == 1
    assert "eve" in rep["identities"]
    assert "frank" not in rep["identities"]
    assert rep["tracked"] == 2


def test_region_coords_feed_monitor():
    # REGION_COORDS merkezleri observe()'e beslenebilmeli.
    na = gv.REGION_COORDS["north-america"]
    ap = gv.REGION_COORDS["asia-pacific"]
    mon = gv.GeoVelocityMonitor(max_speed_kmh=900.0)
    mon.observe("region-user", na[0], na[1], 0.0)
    r = mon.observe("region-user", ap[0], ap[1], 1800.0)  # 30 dk, kitalar arasi
    assert r["impossible_travel"] is True


def test_out_of_order_timestamp_not_impossible():
    mon = gv.GeoVelocityMonitor(max_speed_kmh=900.0)
    mon.observe("grace", 51.5074, -0.1278, 1000.0)
    # Daha ESKI zaman damgasi -> negatif gap, imkansiz sayilmamali.
    r = mon.observe("grace", 1.3521, 103.8198, 500.0)
    assert r["impossible_travel"] is False
    assert "SIRA-DISI" in r["verdict_tr"]
