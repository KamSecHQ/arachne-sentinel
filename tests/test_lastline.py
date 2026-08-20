"""
Son Hat (Yer Alti Ultra Savunma) — cekirdek + 50 katman testleri.

Tamamen savunma; testler yalniz deterministik hesap/dogrulama yapar. Hicbir
katman disari dokunmaz. Her "full" katmanin gercek algoritmasi (Shamir, HOTP,
hash-zinciri, Merkle, k-of-n kuorum, HKDF, homomorfik korleme, gercek kume,
tarpit) uctan uca round-trip/dogrulama ile sinanir.
"""
from arachne.lastline import (
    DefenseContext,
    HyperMTD,
    LastLineFortress,
    Layer,
    LayerResult,
    identity_at,
)
from arachne.lastline import layers as L
from arachne.lastline.layers import (
    ByzantineQuorumLayer,
    CoreVaultSealLayer,
    HomomorphicVaultLayer,
    ImmuneMemoryLayer,
    OneTimeIdentityLayer,
    ShamirSplitLayer,
    SwarmVoteLayer,
    TarpitLayer,
    TpmSealChainLayer,
    blind,
    build_layers,
    hash_chain,
    hkdf_derive,
    hotp,
    merkle_root,
    quorum_approve,
    shamir_reconstruct,
    shamir_split,
    tarpit_delay_ms,
    unblind,
    verify_hash_chain,
)

EXPECTED_NAMES = [
    "Hiper Kimlik Rotasyonu", "Port Sicratma Suru", "Parmak Izi Morfing",
    "Sahte Servis Suru", "Dinamik Ag Topolojisi", "Mikro-Segmentasyon",
    "Sifir Guven Yeniden Kimlik", "Tek-Kullanimlik Kimlik", "Aldatma Orgusu",
    "Tarpit Kuyusu", "Canary Tuzak Agi", "Honeynet Yer Degistirme",
    "Entropi Yeniden Anahtarlama", "TPM Muhur Zinciri", "Bizans Cogunluk Onayi",
    "Kuantum-Sonrasi Anahtar", "Homomorfik Kasa", "Parcalama (Sharding)",
    "Hava-Boslugu Emulasyonu", "Sinkhole Yonlendirme", "Protokol Morfing",
    "Trafik Karistirma", "Yem Veri Katmani", "Zaman Kilidi", "Cografi Dagitim",
    "Yuk Cokertme", "Oturum Parcalama", "Shamir Kripto Bolme",
    "Gorunmezlik Perdesi", "Sahte Zafiyet Bali", "Refleks Karantina",
    "Otonom Iyilesme", "Bagisiklik Hafizasi", "Suru Zekasi Oylamasi",
    "Anomali On-Sezgi", "Davranis DNA'si", "Kill-Switch Ayrimi",
    "Donanim Kok Guven", "Bellek Perdeleme", "Yan-Kanal Gurultusu",
    "Deterministik Yeniden Dogus", "Golge Cekirdek Ikizi", "Yem Cekirdek Ordusu",
    "Son-An Isinlama", "Kuantum Dolaniklik Kilidi", "Noral Bekci",
    "Kaos Kalkani", "Mutlak Sifir Katmani", "Cekirdek Kasa Muhru",
    "KORUNAN VARLIK (yer alti)",
]


# ========================= HAYALET kimlik / MTD ============================
def test_identity_at_ayni_dilim_esit():
    a = identity_at(1000, seed="arachne", interval_ms=100)
    b = identity_at(1099, seed="arachne", interval_ms=100)  # ayni 100ms dilimi
    assert a == b
    assert a["slot"] == 10


def test_identity_at_sonraki_dilim_farkli():
    a = identity_at(1000, interval_ms=100)
    b = identity_at(1100, interval_ms=100)  # bir sonraki dilim
    assert a != b
    assert b["slot"] == a["slot"] + 1
    assert a["ip"] != b["ip"] or a["port"] != b["port"] or a["token"] != b["token"]


def test_identity_at_seed_degisimi_farkli_kimlik():
    assert identity_at(1000, seed="a") != identity_at(1000, seed="b")


def test_mtd_rotasyon_hizi_bir_saniye():
    now = [0]
    mtd = HyperMTD(interval_ms=100, clock=lambda: now[0])
    mtd.engage(breach_ms=0)
    now[0] = 1000  # 1 saniye ilerlet -> 100ms araligiyla 10 rotasyon
    assert mtd.rotations() == 10


def test_mtd_reaction_ms_100_altinda():
    now = [5_000]
    mtd = HyperMTD(clock=lambda: now[0])
    # ihlal aninda devreye girme; tepki suresi <= 100 ms olmali
    reaction = mtd.engage(breach_ms=5_000)
    assert reaction <= 100.0
    assert reaction == 0.0


def test_mtd_standby_rotasyon_sifir():
    mtd = HyperMTD(clock=lambda: 10_000)
    assert mtd.rotations() == 0  # devreye girmeden rotasyon yok


# ========================= should_engage senaryolari ======================
def test_should_engage_drill():
    ok, reason = LastLineFortress.should_engage(DefenseContext(extra={"drill": True}))
    assert ok and "Tatbikat" in reason


def test_should_engage_18_halka():
    ok, reason = LastLineFortress.should_engage(DefenseContext(bypassed_layers=18))
    assert ok and "18" in reason


def test_should_engage_yuksek_fuzyon_ve_honeytoken():
    ctx = DefenseContext(fused_posterior=0.95, honeytoken_tripped=True)
    ok, reason = LastLineFortress.should_engage(ctx)
    assert ok and "fuzyon" in reason.lower()


def test_should_engage_honeytoken_derin():
    ctx = DefenseContext(honeytoken_tripped=True, bypassed_layers=16)
    ok, _ = LastLineFortress.should_engage(ctx)
    assert ok


def test_should_engage_esik_alti():
    ctx = DefenseContext(fused_posterior=0.3, bypassed_layers=2)
    ok, reason = LastLineFortress.should_engage(ctx)
    assert not ok and "Esik altinda" in reason


def test_should_engage_yuksek_fuzyon_ama_sig_yok():
    # yuksek posterior tek basina yetmez (honeytoken/derinlik gerek)
    ctx = DefenseContext(fused_posterior=0.99, honeytoken_tripped=False, bypassed_layers=0)
    ok, _ = LastLineFortress.should_engage(ctx)
    assert not ok


# ========================= fortress.engage() ==============================
def _fortress():
    now = [1_000_000]
    return LastLineFortress(clock=lambda: now[0]), now


def test_engage_50_katman_ve_hepsi_layerresult():
    f, _ = _fortress()
    status = f.engage(DefenseContext(extra={"drill": True}), breach_ms=1_000_000)
    assert status["summary"]["total_layers"] == 50
    assert len(status["layers"]) == 50
    assert len(f.last_results) == 50
    assert all(isinstance(r, LayerResult) for r in f.last_results)


def test_engage_reaction_ok_ve_100_altinda():
    f, now = _fortress()
    status = f.engage(DefenseContext(extra={"drill": True}), breach_ms=now[0])
    assert status["reaction_ok"] is True
    assert status["reaction_ms"] <= 100.0


def test_engage_integrity_root_deterministik():
    f1, _ = _fortress()
    f2, _ = _fortress()
    ctx = DefenseContext(now_ms=777, attempts=4, bypassed_layers=18)
    s1 = f1.engage(ctx, breach_ms=1_000_000)
    s2 = f2.engage(ctx, breach_ms=1_000_000)
    assert s1["integrity_root"] == s2["integrity_root"]
    assert len(s1["integrity_root"]) == 8  # 32-bit hex


def test_engage_integrity_root_degisime_duyarli():
    f, _ = _fortress()
    f.engage(DefenseContext(extra={"drill": True}), breach_ms=1_000_000)
    root_before = f.integrity_root
    # bir sonucu kurcalayip kok'un degistigini dogrula (kurcalama-kaniti)
    tampered = list(f.last_results)
    orig = tampered[0]
    tampered[0] = LayerResult(orig.layer_id, orig.name, orig.tier,
                              engaged=not orig.engaged, action="TAMPERED",
                              blocks_lock=orig.blocks_lock)
    root_after = LastLineFortress._integrity_root(tampered)
    assert root_after != root_before


def test_engage_decoys_pozitif_ve_reached_false():
    f, _ = _fortress()
    status = f.engage(DefenseContext(extra={"drill": True}), breach_ms=1_000_000)
    assert status["summary"]["decoys"] > 0
    assert status["summary"]["reached_real_asset"] is False


def test_engage_katman_exception_sizdirmaz():
    # her katman engage'i asla exception sizdirmaz; fortress yine de sarar
    for layer in build_layers():
        r = layer.engage(DefenseContext(now_ms=0))
        assert isinstance(r, LayerResult)


# ========================= build_layers() sozlesmesi ======================
def test_build_layers_tam_50():
    assert len(build_layers()) == 50


def test_build_layers_idler_L01_L50_benzersiz():
    ids = [l.layer_id for l in build_layers()]
    assert ids == [f"L{i:02d}" for i in range(1, 51)]
    assert len(set(ids)) == 50


def test_build_layers_adlar_listeyle_eslesir():
    names = [l.name for l in build_layers()]
    assert names == EXPECTED_NAMES


def test_build_layers_en_az_12_full():
    full = [l for l in build_layers() if l.depth == "full"]
    assert len(full) >= 12
    ids = {l.layer_id for l in full}
    # sozlesmede istenen full katmanlar
    for want in ("L28", "L08", "L14", "L49", "L15", "L34", "L10",
                 "L43", "L04", "L09", "L13", "L16", "L33", "L17"):
        assert want in ids


def test_build_layers_hepsi_layer_altsinifi():
    assert all(isinstance(l, Layer) for l in build_layers())


def test_build_layers_depth_gecerli_etiket():
    assert all(l.depth in ("full", "model") for l in build_layers())


def test_engage_determinizmi_ayni_ctx_ayni_sonuc():
    ctx = DefenseContext(now_ms=54321, attempts=7, fused_posterior=0.85,
                         honeytoken_tripped=True, bypassed_layers=17, novelty=0.7)
    a = [l.engage(ctx) for l in build_layers()]
    b = [l.engage(ctx) for l in build_layers()]
    for x, y in zip(a, b):
        assert (x.engaged, x.action, x.blocks_lock, x.metric, x.detail) == \
               (y.engaged, y.action, y.blocks_lock, y.metric, y.detail)


# ========================= FULL: Shamir (GF256) ===========================
def test_shamir_roundtrip_k_paylasim():
    secret = b"cekirdek-anahtari-16"
    shares = shamir_split(secret, k=3, n=5, seed=b"seed")
    assert len(shares) == 5
    # herhangi 3 pay ile birebir kurulur
    assert shamir_reconstruct(shares[:3]) == secret
    assert shamir_reconstruct([shares[0], shares[2], shares[4]]) == secret


def test_shamir_k_eksi_bir_ile_cozulmez():
    secret = b"gizli-deger-0123"
    shares = shamir_split(secret, k=3, n=5, seed=b"seed")
    # 2 pay (k-1) sirri VERMEZ
    assert shamir_reconstruct(shares[:2]) != secret


def test_shamir_deterministik():
    s = b"abcdef0123456789"
    assert shamir_split(s, 3, 5, seed=b"z") == shamir_split(s, 3, 5, seed=b"z")


def test_shamir_katman_metric_ve_roundtrip():
    r = ShamirSplitLayer().engage(DefenseContext(seed="arachne"))
    assert r.metric["n"] == 5 and r.metric["k"] == 3
    assert r.metric["shares_needed"] == 3
    assert r.metric["roundtrip_ok"] is True
    assert r.metric["under_threshold_leaks"] is False
    assert r.blocks_lock is True


# ========================= FULL: HOTP (RFC 4226) ==========================
def test_hotp_ayni_sayac_ayni_kod():
    key = b"key"
    assert hotp(key, 1) == hotp(key, 1)


def test_hotp_farkli_sayac_genelde_farkli():
    key = b"key"
    codes = {hotp(key, c) for c in range(10)}
    assert len(codes) >= 8  # neredeyse hepsi benzersiz


def test_hotp_tek_kullanimlik_verify_once():
    layer = OneTimeIdentityLayer()
    ctx = DefenseContext(seed="arachne", now_ms=1000)
    counter = 42
    code = layer.code_for(ctx, counter)
    assert layer.verify_once(ctx, counter, code) is True   # ilk kez gecerli
    assert layer.verify_once(ctx, counter, code) is False  # ayni sayac TEKRAR gecersiz


def test_hotp_yanlis_kod_reddedilir():
    layer = OneTimeIdentityLayer()
    ctx = DefenseContext(seed="arachne")
    assert layer.verify_once(ctx, 7, "000000") is False


def test_hotp_katman_engage_deterministik_ve_pure():
    layer = OneTimeIdentityLayer()
    ctx = DefenseContext(seed="arachne", now_ms=2000, attempts=3)
    r1 = layer.engage(ctx)
    r2 = layer.engage(ctx)  # engage tuketmez -> ayni sonuc
    assert r1.metric == r2.metric
    assert len(r1.metric["otp"]) == 6


# ========================= FULL: hash-zinciri / Merkle ====================
def test_hash_chain_dogrulama():
    items = [b"a", b"b", b"c"]
    chain = hash_chain(items)
    assert verify_hash_chain(items, chain) is True


def test_hash_chain_kurcalama_tespiti():
    items = [b"a", b"b", b"c"]
    chain = hash_chain(items)
    assert verify_hash_chain([b"a", b"X", b"c"], chain) is False
    bad = list(chain)
    bad[1] = "deadbeef"
    assert verify_hash_chain(items, bad) is False


def test_tpm_katman_zincir_dogru():
    r = TpmSealChainLayer().engage(DefenseContext(seed="arachne", now_ms=500))
    assert r.metric["verified"] is True
    assert r.metric["links"] == 8


def test_merkle_root_deterministik_ve_duyarli():
    leaves = [b"l0", b"l1", b"l2", b"l3"]
    root = merkle_root(leaves)
    assert root == merkle_root(leaves)
    assert merkle_root([b"l0", b"l1", b"l2", b"X"]) != root


def test_merkle_katman_tamper_tespiti():
    r = CoreVaultSealLayer().engage(DefenseContext(seed="arachne"))
    assert r.metric["tamper_detected"] is True
    assert r.metric["leaves"] == 8


# ========================= FULL: k-of-n kuorum ============================
def test_quorum_approve_kabul_ve_ret():
    assert quorum_approve([True, True, True, False, False], 3) is True
    assert quorum_approve([True, True, False, False, False], 3) is False


def test_byzantine_dusuk_derinlik_reddeder():
    # az sizma -> ele gecen dugum k'dan az -> erisim reddedilir
    r = ByzantineQuorumLayer().engage(DefenseContext(bypassed_layers=4))
    assert r.metric["approved"] is False
    assert r.blocks_lock is True


def test_byzantine_tam_ele_gecirme_onaylar():
    # tum dugumler ele gecerse kuorum saglanir (algoritma dogrulugu)
    r = ByzantineQuorumLayer().engage(DefenseContext(bypassed_layers=100))
    assert r.metric["controlled"] == ByzantineQuorumLayer.N
    assert r.metric["approved"] is True


def test_swarm_yuksek_posterior_konsensus_blok():
    r = SwarmVoteLayer().engage(DefenseContext(fused_posterior=1.0))
    assert r.metric["consensus_block"] is True
    assert r.blocks_lock is True


def test_swarm_dusuk_posterior_konsensus_yok():
    r = SwarmVoteLayer().engage(DefenseContext(fused_posterior=0.1))
    assert r.metric["consensus_block"] is False


# ========================= FULL: Tarpit ===================================
def test_tarpit_gecikme_monoton_artar():
    delays = [tarpit_delay_ms(a) for a in range(0, 12)]
    assert delays[0] == 0
    for i in range(1, len(delays)):
        assert delays[i] >= delays[i - 1]  # monoton (azalmayan)
    # baslarda kesin artis
    assert tarpit_delay_ms(1) < tarpit_delay_ms(2) < tarpit_delay_ms(3)


def test_tarpit_tavan_uygulanir():
    assert tarpit_delay_ms(1000) == 30000  # cap_ms
    assert tarpit_delay_ms(10_000) == 30000  # tasma yok


def test_tarpit_katman_deneme_yoksa_devreye_girmez():
    r = TarpitLayer().engage(DefenseContext(attempts=0))
    assert r.engaged is False and r.metric["delay_ms"] == 0
    r2 = TarpitLayer().engage(DefenseContext(attempts=5))
    assert r2.engaged is True and r2.metric["delay_ms"] > 0


# ========================= FULL: HKDF ====================================
def test_hkdf_deterministik_ve_uzunluk():
    k1 = hkdf_derive(b"ikm", b"salt", b"info", 32)
    k2 = hkdf_derive(b"ikm", b"salt", b"info", 32)
    assert k1 == k2 and len(k1) == 32


def test_hkdf_farkli_salt_farkli_anahtar():
    assert hkdf_derive(b"ikm", b"s1", b"info") != hkdf_derive(b"ikm", b"s2", b"info")


def test_entropi_rekey_dilim_basi_yenilenir():
    layer = L.EntropyRekeyLayer()
    k_a = layer.derive(DefenseContext(now_ms=0))
    k_b = layer.derive(DefenseContext(now_ms=100))   # sonraki dilim
    k_a2 = layer.derive(DefenseContext(now_ms=50))   # ayni dilim (0)
    assert k_a != k_b
    assert k_a == k_a2


def test_pq_key_512_bit():
    r = L.PostQuantumKeyLayer().engage(DefenseContext(now_ms=300))
    assert r.metric["bits"] == 512


# ========================= FULL: Homomorfik korleme =======================
def test_blind_unblind_roundtrip():
    mod = (1 << 127) - 1
    secret, mask = 123456789, 987654321
    c = blind(secret, mask, mod)
    assert c != secret
    assert unblind(c, mask, mod) == secret


def test_homomorphic_katman_roundtrip_ve_maskesiz_okunamaz():
    r = HomomorphicVaultLayer().engage(DefenseContext(seed="arachne", now_ms=100))
    assert r.metric["roundtrip_ok"] is True
    assert r.metric["readable_without_mask"] is False
    assert r.blocks_lock is True


# ========================= FULL: Bagisiklik hafizasi (kume) ===============
def test_immune_memory_uyelik_ekle_ve_test():
    layer = ImmuneMemoryLayer()
    fp = "deadbeef"
    assert layer.is_known(fp) is False
    layer.remember(fp)
    assert layer.is_known(fp) is True
    assert layer.is_known("00000000") is False


def test_immune_memory_engage_deterministik():
    layer = ImmuneMemoryLayer()
    ctx = DefenseContext(attacker_ip="203.0.113.9", seed="arachne")
    r1 = layer.engage(ctx)
    r2 = layer.engage(ctx)  # engage kume'yi mutasyona ugratmaz
    assert r1.metric == r2.metric
    assert isinstance(r1.metric["known"], bool)


# ========================= Model katmanlar: gercek hesap ==================
def test_micro_segmentasyon_ip_bazli_izolasyon():
    r = L.MicroSegmentationLayer().engage(DefenseContext(attacker_ip="198.51.100.7"))
    assert 0 <= r.metric["segment_id"] < 256
    assert r.metric["isolated"] is True


def test_refleks_karantina_esik_karari():
    lo = L.ReflexQuarantineLayer().engage(DefenseContext(fused_posterior=0.1))
    hi = L.ReflexQuarantineLayer().engage(DefenseContext(fused_posterior=0.95))
    assert lo.engaged is False and hi.engaged is True


def test_anomali_on_sezgi_novelty_esigi():
    lo = L.AnomalyPrecogLayer().engage(DefenseContext(novelty=0.2))
    hi = L.AnomalyPrecogLayer().engage(DefenseContext(novelty=0.9))
    assert lo.metric["anomaly"] is False and hi.metric["anomaly"] is True


def test_zaman_kilidi_pencere_now_ms_ten():
    r = L.TimeLockLayer().engage(DefenseContext(now_ms=12_000))
    assert r.metric["window"] == 12_000 // L.TimeLockLayer.WINDOW_MS
    assert r.metric["unlock_at_ms"] > 12_000


def test_noral_bekci_skor_monoton_tehditle_artar():
    low = L.NeuralSentinelLayer().score(DefenseContext(fused_posterior=0.0, novelty=0.0))
    high = L.NeuralSentinelLayer().score(
        DefenseContext(fused_posterior=1.0, novelty=1.0, bypassed_layers=10))
    assert 0.0 < low < high < 1.0


def test_kaos_kalkani_deterministik_aralikta():
    layer = L.ChaosShieldLayer()
    ctx = DefenseContext(seed="arachne", now_ms=999)
    c1 = layer.chaos(ctx)
    c2 = layer.chaos(ctx)
    assert c1 == c2 and 0.0 <= c1 <= 1.0


def test_korunan_varlik_ulasilmaz():
    r = L.ProtectedAssetLayer().engage(DefenseContext(bypassed_layers=18))
    assert r.metric["reachable"] is False   # all_lastline_failed yok
    assert r.blocks_lock is True


def test_decoy_katmanlari_pozitif_yem():
    ctx = DefenseContext(seed="arachne")
    for cls in (L.DecoyServiceSwarmLayer, L.DeceptionMeshLayer, L.DecoyCoreArmyLayer):
        r = cls().engage(ctx)
        assert r.metric["decoys"] > 0
        assert 0.0 < r.metric["real_pick_odds"] <= 0.5


def test_zero_trust_taze_jeton_now_ms_ten():
    layer = L.ZeroTrustReauthLayer()
    t0 = layer.required_token(DefenseContext(now_ms=0))
    t1 = layer.required_token(DefenseContext(now_ms=100))
    assert t0 != t1  # her dilimde taze jeton


# ---------------------------------------------------------------------------
# GOLDEN VEKTORLER — Python<->JS FNV-1a paritesi (bunker3d.js ile birebir).
# Bu degerler Node.js'te ayni algoritmayla uretildi; identity_at degisirse
# (ya da JS'teki fnv1a bozulursa) bu test kirilir -> parite korunur.
# ---------------------------------------------------------------------------
def test_golden_identity_vectors_js_parity():
    from arachne.lastline.identity import identity_at
    golden = {
        1755700000000: {"slot": 17557000000, "ip": "198.18.12.197", "port": 54751,
                        "fingerprint": "a6f8f159eca0", "token": "de4a69e2"},
        1755700000123: {"slot": 17557000001, "ip": "198.18.3.150", "port": 16010,
                        "fingerprint": "67f1f222f08f", "token": "ef6f7539"},
        0:             {"slot": 0, "ip": "198.18.115.6", "port": 4346,
                        "fingerprint": "f199829280ff", "token": "b3c34f09"},
        999999999999:  {"slot": 9999999999, "ip": "198.18.199.90", "port": 20886,
                        "fingerprint": "e67f183e16ab", "token": "8b977f6d"},
    }
    for now_ms, exp in golden.items():
        assert identity_at(now_ms) == exp, now_ms


def test_golden_fnv1a_values():
    from arachne.lastline.base import fnv1a
    # Node.js Math.imul tabanli fnv1a ile birebir
    assert fnv1a("arachne:0") == 1441947497
    assert fnv1a("") == 0x811C9DC5


# ---------------------------------------------------------------------------
# API uc noktalari — /api/fortress (GET/engage/standby) GERCEK motoru surer.
# ---------------------------------------------------------------------------
def test_api_fortress_get_roster():
    from arachne.reporting import dashboard
    c = dashboard.app.test_client()
    d = c.get("/api/fortress").get_json()
    assert len(d["layers"]) == 50           # beklemede bile 50 katman rosteri
    assert d["identity"]["ip"].startswith("198.18.")
    assert d["identity_params"]["seed"] == "arachne"
    assert d["identity_params"]["interval_ms"] == 100


def test_api_fortress_engage_and_standby():
    from arachne.reporting import dashboard
    c = dashboard.app.test_client()
    d = c.post("/api/fortress/engage").get_json()
    assert d["engaged"] is True
    assert d["summary"]["total_layers"] == 50
    assert d["summary"]["sealed_layers"] >= 40      # gercek katmanlar muhurlendi
    assert d["summary"]["decoys"] > 0               # gercek yem sayisi
    assert d["reaction_ok"] is True                 # 0.1 sn altinda
    assert d["reaction_ms"] <= 100.0
    assert len(d["integrity_root"]) == 8            # hash-zinciri koku
    assert d["summary"]["reached_real_asset"] is False
    d2 = c.post("/api/fortress/standby").get_json()
    assert d2["engaged"] is False
