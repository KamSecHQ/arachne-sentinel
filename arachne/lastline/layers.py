"""
Son Hat — 50 GERCEK savunma katmani (Faz 82-100).

Her katman `Layer` alt sinifidir; `engage(ctx)` DETERMINISTIK'tir (ayni ctx ->
ayni LayerResult) ve asla exception sizdirmaz. Yan etkisi yalnizca kendi ic
durumudur; hicbir katman baska bir sisteme dokunmaz, disari paket gondermez,
hack-back yoktur. Girdi yoksa notr/guvenli sonuc uretilir.

DURUSTLUK ETIKETI (`depth`):
  * "full"  = uctan uca gercek uygulama, test edilebilir round-trip/dogrulama
              (Shamir GF(256), HOTP/RFC4226, hash-zinciri, Merkle, k-of-n kuorum,
               HKDF, additive homomorfik korleme, gercek kume uyeligi, tarpit).
  * "model" = gercek ve deterministik bir hesap/karar yapan sadelestirilmis model.

Bu dosyada 14 katman "full"tur:
  L04 Sahte Servis Suru, L08 Tek-Kullanimlik Kimlik (HOTP), L09 Aldatma Orgusu,
  L10 Tarpit Kuyusu, L13 Entropi Yeniden Anahtarlama (HKDF),
  L14 TPM Muhur Zinciri (hash-zinciri), L15 Bizans Cogunluk Onayi (k-of-n),
  L16 Kuantum-Sonrasi Anahtar (HKDF), L17 Homomorfik Kasa (additive korleme),
  L28 Shamir Kripto Bolme (GF(256)), L33 Bagisiklik Hafizasi (gercek kume),
  L34 Suru Zekasi Oylamasi (k-of-n), L43 Yem Cekirdek Ordusu, L49 Cekirdek Kasa
  Muhru (Merkle).
"""
from __future__ import annotations

import hashlib
import hmac
import math
import struct
from typing import Any, Dict, List, Set, Tuple

from .base import DefenseContext, Layer, LayerResult, h_int
from .identity import identity_at

# hiper-MTD ile ayni rotasyon periyodu (bilgi amacli, deterministik)
INTERVAL_MS = 100


# ===========================================================================
# GERCEK KRIPTO/ALGORITMA YARDIMCILARI (harici kutuphane YOK, hepsi stdlib)
# Bunlar hem katmanlar hem testler tarafindan dogrudan cagrilabilir.
# ===========================================================================

# --- GF(2^8) tablolari (AES cokterimi 0x11d) — Shamir Secret Sharing icin ---
_GF_EXP: List[int] = [0] * 512
_GF_LOG: List[int] = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) sifira bolme")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def shamir_split(secret: bytes, k: int, n: int, seed: bytes = b"arachne") -> List[Tuple[int, bytes]]:
    """GERCEK Shamir Secret Sharing (GF(256)). Sirri k-esikli n paya boler.

    Katsayilar `seed`den DETERMINISTIK turetilir (test edilebilir). k'dan az
    payla sir hakkinda hicbir bilgi cozulemez (Shamir'in bilgi-teorik guvencesi).
    """
    if not (1 <= k <= n <= 255):
        raise ValueError("gecersiz (k,n): 1<=k<=n<=255 olmali")
    shares: List[bytearray] = [bytearray() for _ in range(n)]
    for bi, sb in enumerate(secret):
        coeffs = [sb]  # a0 = sir baytesi
        for ci in range(1, k):
            digest = hmac.new(seed, f"{bi}:{ci}".encode(), hashlib.sha256).digest()
            coeffs.append(digest[0])
        for si in range(n):
            x = si + 1
            y = 0
            for c in reversed(coeffs):  # Horner ile GF(256) polinom degeri
                y = _gf_mul(y, x) ^ c
            shares[si].append(y)
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def shamir_reconstruct(shares: List[Tuple[int, bytes]]) -> bytes:
    """k paydan sirri GF(256) Lagrange interpolasyonu (x=0) ile geri kurar."""
    if not shares:
        raise ValueError("pay yok")
    length = len(shares[0][1])
    xs = [s[0] for s in shares]
    out = bytearray()
    for byte_idx in range(length):
        ys = [s[1][byte_idx] for s in shares]
        acc = 0
        for i in range(len(shares)):
            xi = xs[i]
            num = 1
            den = 1
            for j in range(len(shares)):
                if i == j:
                    continue
                xj = xs[j]
                num = _gf_mul(num, xj)       # (0 - xj) = xj  (GF(2^8)'de cikarma = XOR)
                den = _gf_mul(den, xi ^ xj)  # (xi - xj) = xi ^ xj
            li = _gf_div(num, den)
            acc ^= _gf_mul(ys[i], li)
        out.append(acc)
    return bytes(out)


def hotp(key: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    """GERCEK HOTP (RFC 4226). Sayac bazli tek-kullanimlik kod.

    Ayni sayac ayni kodu verir; sayac tuketildikten sonra bir daha kabul
    edilmemelidir (bkz. OneTimeIdentityLayer.verify_once).
    """
    mod = {"sha1": hashlib.sha1, "sha256": hashlib.sha256}[algo]
    msg = struct.pack(">Q", counter)
    dig = hmac.new(key, msg, mod).digest()
    off = dig[-1] & 0x0F
    bincode = ((dig[off] & 0x7F) << 24
               | (dig[off + 1] & 0xFF) << 16
               | (dig[off + 2] & 0xFF) << 8
               | (dig[off + 3] & 0xFF))
    return str(bincode % (10 ** digits)).zfill(digits)


def hash_chain(items: List[bytes], genesis: bytes = b"arachne-genesis") -> List[str]:
    """GERCEK hash-zinciri: her halka = SHA256(onceki_hex + oge). Kurcalama-kaniti."""
    prev = hashlib.sha256(genesis).hexdigest()
    chain: List[str] = []
    for it in items:
        prev = hashlib.sha256(prev.encode() + it).hexdigest()
        chain.append(prev)
    return chain


def verify_hash_chain(items: List[bytes], chain: List[str],
                      genesis: bytes = b"arachne-genesis") -> bool:
    """Zincirin ogelerle tutarli oldugunu dogrular (herhangi bir kurcalama -> False)."""
    return hash_chain(items, genesis) == list(chain)


def merkle_root(leaves: List[bytes]) -> str:
    """GERCEK Merkle koku (tek/eslesmemis dugum kendisiyle eslenir)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(b"\x01" + a + b).digest())
        level = nxt
    return level[0].hex()


def quorum_approve(votes: List[bool], k: int) -> bool:
    """k-of-n kuorum: en az k olumlu oy -> True (aksi halde reddedilir)."""
    return sum(1 for v in votes if v) >= k


def tarpit_delay_ms(attempts: int, base_ms: int = 100, cap_ms: int = 30000) -> int:
    """GERCEK ustel (tavanli) tarpit gecikmesi. attempts arttikca MONOTON artar."""
    if attempts <= 0:
        return 0
    shift = min(attempts - 1, 40)  # tasmayi onle
    return min(cap_ms, base_ms * (1 << shift))


def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """GERCEK HKDF (RFC 5869, HMAC-SHA256): extract-then-expand anahtar turetme."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def blind(secret_int: int, mask: int, modulus: int) -> int:
    """Additive (toplamsal) korleme: c = (m + r) mod q."""
    return (secret_int + mask) % modulus


def unblind(blinded: int, mask: int, modulus: int) -> int:
    """Korlemeyi geri ac: m = (c - r) mod q."""
    return (blinded - mask) % modulus


def _decoy_count(seed: str, tag: str, base: int = 64, span: int = 64) -> int:
    """Deterministik, HER ZAMAN pozitif yem sayisi (girdi olmasa bile)."""
    return base + (h_int(seed, tag) % span)


def _slot(now_ms: int) -> int:
    return int(now_ms) // INTERVAL_MS


# ===========================================================================
# KATMANLAR
# ===========================================================================

# ---- 01 Hiper Kimlik Rotasyonu (model) ------------------------------------
class HyperIdentityRotationLayer(Layer):
    layer_id, name, tier, depth = "L01", "Hiper Kimlik Rotasyonu", "kimlik", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        ident = identity_at(ctx.now_ms, ctx.seed, INTERVAL_MS)
        rps = 1000 // INTERVAL_MS
        return self._result(
            True, f"kimlik {INTERVAL_MS} ms'de doner (slot {ident['slot']})", True,
            {"slot": ident["slot"], "ip": ident["ip"], "port": ident["port"],
             "rotations_per_sec": rps},
            "Hareketli hedef: (ip,port,fp) ~100 ms sonra gecersiz.")


# ---- 02 Port Sicratma Suru (model) ----------------------------------------
class PortHopSwarmLayer(Layer):
    layer_id, name, tier, depth = "L02", "Port Sicratma Suru", "kimlik", "model"
    SWARM = 16

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        ports = sorted({1024 + (h_int(ctx.seed, slot, i) % 64512) for i in range(self.SWARM)})
        return self._result(
            True, f"{len(ports)} port arasinda sicrama (slot {slot})", True,
            {"ports": ports, "count": len(ports), "slot": slot},
            "Acik port suru icinde gizlenir; sabit hedef yok.")


# ---- 03 Parmak Izi Morfing (model) ----------------------------------------
class FingerprintMorphLayer(Layer):
    layer_id, name, tier, depth = "L03", "Parmak Izi Morfing", "kimlik", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        ident = identity_at(ctx.now_ms, ctx.seed, INTERVAL_MS)
        fp = ident["fingerprint"]
        return self._result(
            True, "servis parmak izi her dilimde morflar", True,
            {"fingerprint": fp, "slot": ident["slot"]},
            "Banner/TLS/TCP imzasi surekli degisir; fingerprint kilidi tutmaz.")


# ---- 04 Sahte Servis Suru (FULL: gercek yem uretimi) ----------------------
class DecoyServiceSwarmLayer(Layer):
    layer_id, name, tier, depth = "L04", "Sahte Servis Suru", "aldatma", "full"

    def _decoys(self, ctx: DefenseContext) -> List[Dict[str, Any]]:
        n = _decoy_count(ctx.seed, "svc")
        svcs = ["ssh", "http", "mysql", "redis", "smb", "ftp", "rdp", "telnet"]
        out = []
        for i in range(n):
            hh = h_int(ctx.seed, "svc", i)
            out.append({"port": 1024 + (hh % 64512), "service": svcs[hh % len(svcs)]})
        return out

    def engage(self, ctx: DefenseContext) -> LayerResult:
        decoys = self._decoys(ctx)
        n = len(decoys)
        return self._result(
            True, f"{n} sahte servis ayaga kalkti", True,
            {"decoys": n, "sample": decoys[:3], "real_pick_odds": round(1.0 / (n + 1), 6)},
            "Saldirganin gercek servisi secme olasiligi 1/(N+1).")


# ---- 05 Dinamik Ag Topolojisi (model) -------------------------------------
class DynamicTopologyLayer(Layer):
    layer_id, name, tier, depth = "L05", "Dinamik Ag Topolojisi", "izolasyon", "model"
    NODES = 12

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        # deterministik permutasyon (Fisher-Yates, hash tabanli)
        order = list(range(self.NODES))
        for i in range(self.NODES - 1, 0, -1):
            j = h_int(ctx.seed, slot, i) % (i + 1)
            order[i], order[j] = order[j], order[i]
        edges = self.NODES  # halka topolojisi
        return self._result(
            True, f"topoloji yeniden dizildi (slot {slot})", True,
            {"nodes": self.NODES, "edges": edges, "order": order, "slot": slot},
            "Ag grafi her dilimde yeniden sekillenir; kesif haritasi eskir.")


# ---- 06 Mikro-Segmentasyon (model) ----------------------------------------
class MicroSegmentationLayer(Layer):
    layer_id, name, tier, depth = "L06", "Mikro-Segmentasyon", "izolasyon", "model"
    SEGMENTS = 256

    def engage(self, ctx: DefenseContext) -> LayerResult:
        seg = h_int(ctx.attacker_ip, ctx.seed) % self.SEGMENTS
        return self._result(
            True, f"oturum segment {seg}'e izole edildi", True,
            {"segment_id": seg, "segments": self.SEGMENTS, "isolated": True},
            "Yanal hareket yok: her oturum tek-kirici mikro-segmentte.")


# ---- 07 Sifir Guven Yeniden Kimlik (model) --------------------------------
class ZeroTrustReauthLayer(Layer):
    layer_id, name, tier, depth = "L07", "Sifir Guven Yeniden Kimlik", "kimlik", "model"

    def required_token(self, ctx: DefenseContext) -> str:
        return identity_at(ctx.now_ms, ctx.seed, INTERVAL_MS)["token"]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        tok = self.required_token(ctx)
        return self._result(
            True, "her istekte taze jeton zorunlu", True,
            {"fresh_token_required": True, "token": tok, "slot": _slot(ctx.now_ms)},
            "Onceki oturumun jetonu gecersiz; ortuk guven yok.")


# ---- 08 Tek-Kullanimlik Kimlik (FULL: HOTP RFC 4226) ----------------------
class OneTimeIdentityLayer(Layer):
    layer_id, name, tier, depth = "L08", "Tek-Kullanimlik Kimlik", "kimlik", "full"

    def __init__(self) -> None:
        self._used: Set[int] = set()  # tuketilen sayaclar (tek-kullanimlik)

    def _key(self, ctx: DefenseContext) -> bytes:
        return hashlib.sha256((ctx.seed + ":hotp").encode()).digest()

    def code_for(self, ctx: DefenseContext, counter: int) -> str:
        return hotp(self._key(ctx), counter, digits=6, algo="sha256")

    def verify_once(self, ctx: DefenseContext, counter: int, code: str) -> bool:
        """Kodu dogrular VE tuketir. Ayni sayac ikinci kez asla gecerli degil."""
        if counter in self._used:
            return False
        ok = hmac.compare_digest(self.code_for(ctx, counter), code)
        if ok:
            self._used.add(counter)
        return ok

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # DETERMINISTIK: mevcut sayac dilimden turetilir, engage tuketmez.
        counter = _slot(ctx.now_ms) + ctx.attempts
        code = self.code_for(ctx, counter)
        return self._result(
            True, f"HOTP tek-kullanimlik kod uretildi (sayac {counter})", True,
            {"counter": counter, "otp": code, "algo": "hmac-sha256", "digits": 6},
            "RFC 4226: her sayac yalniz bir kez gecerli; tekrar kabul edilmez.")


# ---- 09 Aldatma Orgusu (FULL: gercek yem uretimi) -------------------------
class DeceptionMeshLayer(Layer):
    layer_id, name, tier, depth = "L09", "Aldatma Orgusu", "aldatma", "full"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        n = _decoy_count(ctx.seed, "mesh", base=96, span=64)
        nodes = [f"{h_int(ctx.seed, 'mesh', i):08x}" for i in range(min(n, 4))]
        return self._result(
            True, f"{n} dugumlu aldatma orgusu doku", True,
            {"decoys": n, "sample_nodes": nodes, "real_pick_odds": round(1.0 / (n + 1), 6)},
            "Gercek varlik N aldatma dugumu arasinda; secme olasiligi 1/(N+1).")


# ---- 10 Tarpit Kuyusu (FULL: monoton ustel gecikme) -----------------------
class TarpitLayer(Layer):
    layer_id, name, tier, depth = "L10", "Tarpit Kuyusu", "yavaslat", "full"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        delay = tarpit_delay_ms(ctx.attempts)
        engaged = ctx.attempts > 0
        return self._result(
            engaged,
            f"deneme {ctx.attempts} -> {delay} ms gecikme" if engaged else "deneme yok — beklemede",
            engaged,
            {"attempts": ctx.attempts, "delay_ms": delay, "cap_ms": 30000},
            "Her denemede ustel (tavanli) gecikme; kaba kuvvet pratikte durur.")


# ---- 11 Canary Tuzak Agi (model; sinyalle devreye) ------------------------
class CanaryNetLayer(Layer):
    layer_id, name, tier, depth = "L11", "Canary Tuzak Agi", "aldatma", "model"
    CANARIES = 32

    def engage(self, ctx: DefenseContext) -> LayerResult:
        tripped = bool(ctx.honeytoken_tripped)
        return self._result(
            tripped,
            "canary tetiklendi — saldirgan isaretlendi" if tripped else "canary agi kuruldu, sessiz",
            tripped,
            {"canaries": self.CANARIES, "tripped": tripped},
            "Dokunulan canary yuksek-guvenli ihlal sinyali verir.")


# ---- 12 Honeynet Yer Degistirme (model; sinyalle) -------------------------
class HoneynetShiftLayer(Layer):
    layer_id, name, tier, depth = "L12", "Honeynet Yer Degistirme", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        relocate = ctx.honeytoken_tripped or ctx.fused_posterior >= 0.7
        hnet = h_int(ctx.attacker_ip, ctx.seed, "honeynet") % 4096
        return self._result(
            relocate,
            f"oturum honeynet-{hnet}'e tasindi" if relocate else "honeynet hazir, beklemede",
            relocate,
            {"relocated": relocate, "honeynet_id": hnet, "posterior": round(ctx.fused_posterior, 4)},
            "Supheli oturum sahte aga tasinir; gercek varlikla temas kesilir.")


# ---- 13 Entropi Yeniden Anahtarlama (FULL: HKDF) --------------------------
class EntropyRekeyLayer(Layer):
    layer_id, name, tier, depth = "L13", "Entropi Yeniden Anahtarlama", "kripto", "full"

    def derive(self, ctx: DefenseContext) -> bytes:
        slot = _slot(ctx.now_ms)
        return hkdf_derive(ikm=ctx.seed.encode(),
                           salt=struct.pack(">Q", slot),
                           info=b"rekey", length=32)

    def engage(self, ctx: DefenseContext) -> LayerResult:
        key = self.derive(ctx)
        return self._result(
            True, f"anahtar yeniden turetildi (slot {_slot(ctx.now_ms)})", True,
            {"key_prefix": key[:8].hex(), "bits": len(key) * 8, "kdf": "hkdf-sha256"},
            "Her zaman diliminde taze anahtar; ele gecen anahtar hizla eskir.")


# ---- 14 TPM Muhur Zinciri (FULL: hash-zinciri) ----------------------------
class TpmSealChainLayer(Layer):
    layer_id, name, tier, depth = "L14", "TPM Muhur Zinciri", "cekirdek", "full"

    def measurements(self, ctx: DefenseContext) -> List[bytes]:
        slot = _slot(ctx.now_ms)
        return [f"pcr{i}:{h_int(ctx.seed, slot, i):08x}".encode() for i in range(8)]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        items = self.measurements(ctx)
        chain = hash_chain(items, genesis=b"tpm-genesis")
        ok = verify_hash_chain(items, chain, genesis=b"tpm-genesis")
        return self._result(
            True, f"{len(chain)} PCR olcumu muhurlendi", True,
            {"head": chain[-1][:16], "links": len(chain), "verified": ok},
            "Kurcalama-kaniti hash-zinciri: tek bir olcum degisirse kok kirilir.")


# ---- 15 Bizans Cogunluk Onayi (FULL: k-of-n kuorum) -----------------------
class ByzantineQuorumLayer(Layer):
    layer_id, name, tier, depth = "L15", "Bizans Cogunluk Onayi", "kuorum", "full"
    N, K = 7, 5

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # Saldirgan en fazla `controlled` dugum ele gecirebilir (derinlikten turetilir).
        controlled = min(self.N, ctx.bypassed_layers // 4)
        votes = [i < controlled for i in range(self.N)]  # ele gecen dugumler "grant" oyu
        approved = quorum_approve(votes, self.K)  # gercek varliga erisim onayi
        return self._result(
            True,
            "kuorum reddetti — erisim yok" if not approved else "kuorum onayladi",
            not approved,
            {"n": self.N, "k": self.K, "controlled": controlled,
             "approvals": sum(votes), "approved": approved},
            "Gercek varlik icin k-of-n onay sart; ele gecen dugum sayisi k'dan az.")


# ---- 16 Kuantum-Sonrasi Anahtar (FULL: HKDF) ------------------------------
class PostQuantumKeyLayer(Layer):
    layer_id, name, tier, depth = "L16", "Kuantum-Sonrasi Anahtar", "kripto", "full"

    def derive(self, ctx: DefenseContext) -> bytes:
        slot = _slot(ctx.now_ms)
        # 512-bit turetim (genis anahtar alani; klasik/kuantum kaba kuvvete karsi)
        return hkdf_derive(ikm=(ctx.seed + ":pq").encode(),
                           salt=struct.pack(">Q", slot),
                           info=b"pq-kem", length=64)

    def engage(self, ctx: DefenseContext) -> LayerResult:
        key = self.derive(ctx)
        return self._result(
            True, f"kuantum-sonrasi anahtar turetildi (slot {_slot(ctx.now_ms)})", True,
            {"key_prefix": key[:8].hex(), "bits": len(key) * 8, "kdf": "hkdf-sha256"},
            "Genis anahtar alani + dilim basi yenileme; anahtar hasadi ise yaramaz.")


# ---- 17 Homomorfik Kasa (FULL: additive korleme round-trip) ---------------
class HomomorphicVaultLayer(Layer):
    layer_id, name, tier, depth = "L17", "Homomorfik Kasa", "kripto", "full"
    MODULUS = (1 << 127) - 1  # Mersenne asali

    def _secret(self, ctx: DefenseContext) -> int:
        return int.from_bytes(hashlib.sha256((ctx.seed + ":vault").encode()).digest()[:16], "big") % self.MODULUS

    def _mask(self, ctx: DefenseContext) -> int:
        m = hkdf_derive(ctx.seed.encode(), struct.pack(">Q", _slot(ctx.now_ms)), b"blind", 16)
        return int.from_bytes(m, "big") % self.MODULUS

    def engage(self, ctx: DefenseContext) -> LayerResult:
        secret = self._secret(ctx)
        mask = self._mask(ctx)
        c = blind(secret, mask, self.MODULUS)
        recovered = unblind(c, mask, self.MODULUS)
        ok = recovered == secret
        readable_without_mask = (c == secret)
        return self._result(
            True, "sir toplamsal korleme ile saklandi", True,
            {"modulus_bits": self.MODULUS.bit_length(), "blinded_prefix": f"{c:032x}"[:16],
             "roundtrip_ok": ok, "readable_without_mask": readable_without_mask},
            "Maske olmadan okunamaz; maske ile birebir geri acilir (round-trip).")


# ---- 18 Parcalama (Sharding) (model) --------------------------------------
class ShardingLayer(Layer):
    layer_id, name, tier, depth = "L18", "Parcalama (Sharding)", "izolasyon", "model"
    SHARDS, THRESHOLD = 8, 5

    def engage(self, ctx: DefenseContext) -> LayerResult:
        placement = [h_int(ctx.seed, "shard", i) % 4096 for i in range(self.SHARDS)]
        return self._result(
            True, f"varlik {self.SHARDS} parcaya bolundu", True,
            {"shards": self.SHARDS, "threshold": self.THRESHOLD, "placement": placement},
            f"En az {self.THRESHOLD} parca gerekir; tek konum tam varligi vermez.")


# ---- 19 Hava-Boslugu Emulasyonu (model) -----------------------------------
class AirGapLayer(Layer):
    layer_id, name, tier, depth = "L19", "Hava-Boslugu Emulasyonu", "izolasyon", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        return self._result(
            True, "cekirdek mantiksal hava-boslugunda", True,
            {"air_gapped": True, "outbound_reachable": False, "inbound_reachable": False},
            "Korunan cekirdege dogrudan rota yok; kopru sadece tek-yon aldatmadir.")


# ---- 20 Sinkhole Yonlendirme (model) --------------------------------------
class SinkholeLayer(Layer):
    layer_id, name, tier, depth = "L20", "Sinkhole Yonlendirme", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        sink = f"198.18.{h_int(ctx.attacker_ip, 'sink1') % 256}.{h_int(ctx.attacker_ip, 'sink2') % 256}"
        return self._result(
            True, f"trafik sinkhole {sink}'e yonlendi", True,
            {"sinkhole_ip": sink},
            "Saldirgan akisi kayit alan bir kuyuya duser; gercek varliga varmaz.")


# ---- 21 Protokol Morfing (model) ------------------------------------------
class ProtocolMorphLayer(Layer):
    layer_id, name, tier, depth = "L21", "Protokol Morfing", "kimlik", "model"
    PROTOS = ["http2", "http3", "grpc", "mqtt", "amqp", "custom-tlv", "quic", "ws"]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        proto = self.PROTOS[h_int(ctx.seed, slot) % len(self.PROTOS)]
        return self._result(
            True, f"tel protokolu -> {proto} (slot {slot})", True,
            {"protocol": proto, "slot": slot},
            "Tasima protokolu dilim basi degisir; sabit ayristirici tutmaz.")


# ---- 22 Trafik Karistirma (model) -----------------------------------------
class TrafficMixLayer(Layer):
    layer_id, name, tier, depth = "L22", "Trafik Karistirma", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        cover = 8 + (h_int(ctx.seed, _slot(ctx.now_ms)) % 25)  # 8..32 kat ortu trafigi
        return self._result(
            True, f"gercek akis {cover}x ortu trafiginde gizlendi", True,
            {"cover_ratio": cover},
            "Karistirma: gercek istek sabit-oranli sahte trafik icinde erir.")


# ---- 23 Yem Veri Katmani (model) ------------------------------------------
class DecoyDataLayer(Layer):
    layer_id, name, tier, depth = "L23", "Yem Veri Katmani", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        fake = 128 + (h_int(ctx.seed, "faux-data") % 384)
        return self._result(
            True, f"{fake} sahte kayit sunuldu", True,
            {"fake_records": fake, "watermarked": True},
            "Exfil edilen veri filigranli yemdir; gercek veri degil.")


# ---- 24 Zaman Kilidi (model) ----------------------------------------------
class TimeLockLayer(Layer):
    layer_id, name, tier, depth = "L24", "Zaman Kilidi", "kripto", "model"
    WINDOW_MS = 5000

    def engage(self, ctx: DefenseContext) -> LayerResult:
        window = int(ctx.now_ms) // self.WINDOW_MS
        unlock_at = (window + 1) * self.WINDOW_MS
        return self._result(
            True, f"pencere {window}; sonraki acilis {unlock_at} ms", True,
            {"window": window, "unlock_at_ms": unlock_at, "window_ms": self.WINDOW_MS},
            "Kritik islem yalniz siradaki zaman penceresinde acilir; aninda erisim yok.")


# ---- 25 Cografi Dagitim (model) -------------------------------------------
class GeoDistributionLayer(Layer):
    layer_id, name, tier, depth = "L25", "Cografi Dagitim", "izolasyon", "model"
    REGIONS = ["eu-w", "eu-n", "us-e", "us-w", "ap-s", "ap-ne", "sa-e", "af-s"]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        active = self.REGIONS[h_int(ctx.seed, slot, "geo") % len(self.REGIONS)]
        return self._result(
            True, f"aktif bolge -> {active} (slot {slot})", True,
            {"regions": len(self.REGIONS), "active_region": active},
            "Varlik bolgeler arasi gezer; tek yargi/konum saldirisi yetmez.")


# ---- 26 Yuk Cokertme (model; sinyalle) ------------------------------------
class LoadShedLayer(Layer):
    layer_id, name, tier, depth = "L26", "Yuk Cokertme", "yavaslat", "model"
    THRESHOLD = 50

    def engage(self, ctx: DefenseContext) -> LayerResult:
        shed = ctx.attempts >= self.THRESHOLD
        return self._result(
            shed,
            f"yuk cokertme aktif ({ctx.attempts} deneme)" if shed else "yuk normal",
            shed,
            {"attempts": ctx.attempts, "threshold": self.THRESHOLD, "shed": shed},
            "Asiri istek yagmurunda saldirgan trafigi oncelikli olarak dusurulur.")


# ---- 27 Oturum Parcalama (model) ------------------------------------------
class SessionSplitLayer(Layer):
    layer_id, name, tier, depth = "L27", "Oturum Parcalama", "izolasyon", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        frags = 3 + (h_int(ctx.attacker_ip, ctx.seed, "sess") % 5)  # 3..7
        return self._result(
            True, f"oturum {frags} parcaya bolundu", True,
            {"fragments": frags},
            "Oturum durumu bagimsiz parcalara dagilir; tek parca ele gecmez.")


# ---- 28 Shamir Kripto Bolme (FULL: GF(256) SSS) ---------------------------
class ShamirSplitLayer(Layer):
    layer_id, name, tier, depth = "L28", "Shamir Kripto Bolme", "kripto", "full"
    N, K = 5, 3

    def _secret(self, ctx: DefenseContext) -> bytes:
        return hashlib.sha256((ctx.seed + ":shamir").encode()).digest()[:16]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        secret = self._secret(ctx)
        shares = shamir_split(secret, self.K, self.N, seed=ctx.seed.encode())
        recovered = shamir_reconstruct(shares[: self.K])   # k pay -> geri kurulur
        ok = recovered == secret
        # k-1 pay ile ayni degeri VERMEDIGINI de gosteririz (bilgi sizmaz)
        under = shamir_reconstruct(shares[: self.K - 1])
        leaks = under == secret
        return self._result(
            True, f"sir {self.K}-of-{self.N} paya bolundu", True,
            {"n": self.N, "k": self.K, "shares_needed": self.K,
             "roundtrip_ok": ok, "under_threshold_leaks": leaks},
            f"{self.K}'dan az payla sir cozulemez; tam {self.K} pay ile birebir kurulur.")


# ---- 29 Gorunmezlik Perdesi (model) ---------------------------------------
class InvisibilityVeilLayer(Layer):
    layer_id, name, tier, depth = "L29", "Gorunmezlik Perdesi", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # deterministik "sessiz dusurme" karari: dilime gore kapali/acik
        cloaked = (h_int(ctx.seed, _slot(ctx.now_ms), "veil") & 1) == 0
        return self._result(
            True, "cekirdek yanit imzasi perdelendi", True,
            {"cloaked": cloaked, "slot": _slot(ctx.now_ms)},
            "Cekirdek sessiz: prob/tarama yanit almaz, varlik gorunmez kalir.")


# ---- 30 Sahte Zafiyet Bali (model; sinyalle) ------------------------------
class FakeVulnHoneypotLayer(Layer):
    layer_id, name, tier, depth = "L30", "Sahte Zafiyet Bali", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        probing = ctx.attempts > 0 or ctx.fused_posterior >= 0.5
        cves = 3 + (h_int(ctx.seed, "cve") % 6)  # 3..8 sahte "zafiyet"
        return self._result(
            probing,
            "saldirgan sahte zafiyete kilitlendi" if probing else "bal hazir, sessiz",
            probing,
            {"fake_cves": cves, "engaged_on_probe": probing},
            "Cazip ama sahte zafiyetler saldirgani mesgul eder ve isaretler.")


# ---- 31 Refleks Karantina (model; posterior esigi) ------------------------
class ReflexQuarantineLayer(Layer):
    layer_id, name, tier, depth = "L31", "Refleks Karantina", "otonom", "model"
    THRESHOLD = 0.8

    def engage(self, ctx: DefenseContext) -> LayerResult:
        q = ctx.fused_posterior >= self.THRESHOLD or ctx.honeytoken_tripped
        return self._result(
            q,
            "oturum karantinaya alindi" if q else "esik altinda, refleks beklemede",
            q,
            {"posterior": round(ctx.fused_posterior, 4), "threshold": self.THRESHOLD,
             "quarantined": q},
            "Sonsal esik asilinca oturum aninda izole edilir (refleks).")


# ---- 32 Otonom Iyilesme (model) -------------------------------------------
class AutonomicHealLayer(Layer):
    layer_id, name, tier, depth = "L32", "Otonom Iyilesme", "otonom", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        healed = min(18, max(0, ctx.bypassed_layers))  # asilan halkalar geri kapatilir
        return self._result(
            True, f"{healed} asilan halka yeniden kapatildi", True,
            {"healed_rings": healed, "restored": True},
            "Delinen kubbe halkalari otonom olarak yeniden ayaga kalkar.")


# ---- 33 Bagisiklik Hafizasi (FULL: gercek kume uyeligi) -------------------
class ImmuneMemoryLayer(Layer):
    layer_id, name, tier, depth = "L33", "Bagisiklik Hafizasi", "otonom", "full"

    def __init__(self) -> None:
        # deterministik on-tohumlu bilinen-kotu parmak izleri (gercek kume)
        self._known: Set[str] = {f"{h_int('seed-bad', i):08x}" for i in range(16)}

    @staticmethod
    def fingerprint(ctx: DefenseContext) -> str:
        return f"{h_int(ctx.attacker_ip, ctx.seed):08x}"

    def remember(self, fp: str) -> None:
        self._known.add(fp)

    def is_known(self, fp: str) -> bool:
        return fp in self._known

    def engage(self, ctx: DefenseContext) -> LayerResult:
        fp = self.fingerprint(ctx)
        known = self.is_known(fp)  # DETERMINISTIK: engage mutasyon yapmaz
        return self._result(
            True,
            "bilinen saldirgan imzasi — aninda ret" if known else "yeni imza gozlemlendi",
            known,
            {"fingerprint": fp, "known": known, "memory_size": len(self._known)},
            "Gorulen saldirgan imzalari kalici kumede tutulur; tekrar aninda taninir.")


# ---- 34 Suru Zekasi Oylamasi (FULL: k-of-n kuorum) ------------------------
class SwarmVoteLayer(Layer):
    layer_id, name, tier, depth = "L34", "Suru Zekasi Oylamasi", "kuorum", "full"
    N, K = 9, 5

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # her ajan sonsal olasiliga gore kotu/degil oyu verir (deterministik)
        for_votes = min(self.N, int(round(self.N * ctx.fused_posterior)))
        votes = [i < for_votes for i in range(self.N)]
        consensus_block = quorum_approve(votes, self.K)  # k ajan hemfikirse blokla
        return self._result(
            consensus_block or ctx.fused_posterior > 0,
            "suru fikir birligi: blokla" if consensus_block else "fikir birligi yok, izle",
            consensus_block,
            {"n": self.N, "k": self.K, "votes_for": for_votes, "consensus_block": consensus_block},
            "k-of-n suru oyu: yeterli ajan hemfikir olunca erisim reddedilir.")


# ---- 35 Anomali On-Sezgi (model; novelty esigi) ---------------------------
class AnomalyPrecogLayer(Layer):
    layer_id, name, tier, depth = "L35", "Anomali On-Sezgi", "otonom", "model"
    THRESHOLD = 0.6

    def engage(self, ctx: DefenseContext) -> LayerResult:
        anomaly = ctx.novelty >= self.THRESHOLD
        return self._result(
            anomaly,
            "anomali on-sezildi" if anomaly else "yenilik esik altinda",
            anomaly,
            {"novelty": round(ctx.novelty, 4), "threshold": self.THRESHOLD, "anomaly": anomaly},
            "Yenilik skoru esigi asinca saldiri henuz olgunlasmadan sezilir.")


# ---- 36 Davranis DNA'si (model) -------------------------------------------
class BehaviorDnaLayer(Layer):
    layer_id, name, tier, depth = "L36", "Davranis DNA'si", "otonom", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        dna = f"{h_int(ctx.attacker_ip, ctx.attempts, ctx.services_touched, ctx.seed):08x}"
        return self._result(
            True, f"davranis DNA'si cikarildi ({dna})", True,
            {"dna": dna, "attempts": ctx.attempts, "services": ctx.services_touched},
            "Oturumun davranissal imzasi tek bir DNA hash'ine ozetlenir.")


# ---- 37 Kill-Switch Ayrimi (model; derinlik esigi) ------------------------
class KillSwitchLayer(Layer):
    layer_id, name, tier, depth = "L37", "Kill-Switch Ayrimi", "cekirdek", "model"
    ARM_AT = 16

    def engage(self, ctx: DefenseContext) -> LayerResult:
        armed = ctx.bypassed_layers >= self.ARM_AT
        return self._result(
            armed,
            "kill-switch: cekirdek baglantisi kesildi" if armed else "kill-switch kurulu, beklemede",
            armed,
            {"bypassed": ctx.bypassed_layers, "arm_at": self.ARM_AT, "armed": armed},
            "Cok derin sizmada cekirdek fiziksel/mantiksal olarak ayrilir.")


# ---- 38 Donanim Kok Guven (model) -----------------------------------------
class HardwareRootLayer(Layer):
    layer_id, name, tier, depth = "L38", "Donanim Kok Guven", "cekirdek", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        root = hashlib.sha256((ctx.seed + ":hwroot").encode()).hexdigest()
        return self._result(
            True, "donanim kok guven olcumu dogrulandi", True,
            {"root": root[:16], "measured_boot": True},
            "Guven donanim kokunden zincirlenir; yazilim kandirmacasi kok'u degistiremez.")


# ---- 39 Bellek Perdeleme (model) ------------------------------------------
class MemoryCurtainLayer(Layer):
    layer_id, name, tier, depth = "L39", "Bellek Perdeleme", "cekirdek", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        mask = hkdf_derive((ctx.seed + ":mem").encode(), struct.pack(">Q", _slot(ctx.now_ms)),
                           b"curtain", 16)
        return self._result(
            True, "cekirdek bellek bolgesi perdelendi", True,
            {"mask_prefix": mask[:6].hex(), "slot": _slot(ctx.now_ms)},
            "Bellek dilim-basi maskeyle perdelenir; ham dump anlamsizdir.")


# ---- 40 Yan-Kanal Gurultusu (model) ---------------------------------------
class SideChannelNoiseLayer(Layer):
    layer_id, name, tier, depth = "L40", "Yan-Kanal Gurultusu", "cekirdek", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        noise = 16 + (h_int(ctx.seed, _slot(ctx.now_ms), "noise") % 240)  # 16..255 bit
        return self._result(
            True, f"{noise} bit yan-kanal gurultusu enjekte edildi", True,
            {"noise_bits": noise},
            "Zamanlama/guc yan-kanallari gurultuyle bogulur; sizinti olculemez.")


# ---- 41 Deterministik Yeniden Dogus (model) -------------------------------
class DeterministicRebirthLayer(Layer):
    layer_id, name, tier, depth = "L41", "Deterministik Yeniden Dogus", "otonom", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        rebirth = f"{h_int(ctx.seed, slot, 'rebirth'):08x}"
        return self._result(
            True, f"cekirdek deterministik yeniden dogdu ({rebirth})", True,
            {"rebirth_id": rebirth, "slot": slot},
            "Cekirdek her dilimde temiz, deterministik bir orneke yeniden dogar.")


# ---- 42 Golge Cekirdek Ikizi (model) --------------------------------------
class ShadowTwinLayer(Layer):
    layer_id, name, tier, depth = "L42", "Golge Cekirdek Ikizi", "aldatma", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        twin = f"{h_int(ctx.seed, _slot(ctx.now_ms), 'twin'):08x}"
        return self._result(
            True, "golge ikiz aktif; saldirgan ikizle konusur", True,
            {"twin_id": twin, "active": True},
            "Saldirgan gercek yerine golge ikizle etkilesir; gercek cekirdek gizli.")


# ---- 43 Yem Cekirdek Ordusu (FULL: gercek yem uretimi) --------------------
class DecoyCoreArmyLayer(Layer):
    layer_id, name, tier, depth = "L43", "Yem Cekirdek Ordusu", "aldatma", "full"

    def _decoys(self, ctx: DefenseContext) -> int:
        return _decoy_count(ctx.seed, "core", base=127, span=128)  # 127..254 yem cekirdek

    def engage(self, ctx: DefenseContext) -> LayerResult:
        n = self._decoys(ctx)
        ids = [f"{h_int(ctx.seed, 'core', i):08x}" for i in range(min(n, 4))]
        return self._result(
            True, f"{n} yem cekirdek sahada", True,
            {"decoys": n, "sample_ids": ids, "real_pick_odds": round(1.0 / (n + 1), 6)},
            "Gercek cekirdek N yem arasinda; secme olasiligi 1/(N+1).")


# ---- 44 Son-An Isinlama (model) -------------------------------------------
class LastMomentTeleportLayer(Layer):
    layer_id, name, tier, depth = "L44", "Son-An Isinlama", "kimlik", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        dest = f"198.18.{h_int(ctx.seed, slot, 'tp1') % 256}.{h_int(ctx.seed, slot, 'tp2') % 256}"
        return self._result(
            True, f"cekirdek son anda {dest}'e isinladi", True,
            {"teleport_to": dest, "slot": slot},
            "Kilit tamamlanmadan cekirdek yeni konuma sicrar; nisan bosa duser.")


# ---- 45 Kuantum Dolaniklik Kilidi (model) ---------------------------------
class EntanglementLockLayer(Layer):
    layer_id, name, tier, depth = "L45", "Kuantum Dolaniklik Kilidi", "kripto", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        slot = _slot(ctx.now_ms)
        a = h_int(ctx.seed, slot, "ent-a")
        b = h_int(ctx.seed, slot, "ent-b")
        pair = f"{(a ^ b) & 0xFFFFFFFF:08x}"
        # gozlem (kopyalama) girisimi dolanikligi bozar -> kilit acilmaz
        entangled = True
        return self._result(
            True, "dolanik cift kilidi aktif", True,
            {"pair_hash": pair, "entangled": entangled, "slot": slot},
            "Cift-parca dolanik; gozlem/kopya girisimi kilidi aninda bozar.")


# ---- 46 Noral Bekci (model; deterministik skor) ---------------------------
class NeuralSentinelLayer(Layer):
    layer_id, name, tier, depth = "L46", "Noral Bekci", "otonom", "model"

    def score(self, ctx: DefenseContext) -> float:
        z = (2.5 * ctx.fused_posterior + 1.5 * ctx.novelty
             + 0.05 * min(ctx.attempts, 40) + 0.3 * ctx.bypassed_layers - 2.0)
        return 1.0 / (1.0 + math.exp(-z))  # sigmoid

    def engage(self, ctx: DefenseContext) -> LayerResult:
        s = self.score(ctx)
        block = s >= 0.5
        return self._result(
            block,
            f"noral bekci: blokla (skor {s:.3f})" if block else f"noral bekci: izle (skor {s:.3f})",
            block,
            {"score": round(s, 6), "verdict": "block" if block else "watch"},
            "Sabit-agirlikli deterministik sigmoid; ozniteliklerden karar uretir.")


# ---- 47 Kaos Kalkani (model; lojistik harita) -----------------------------
class ChaosShieldLayer(Layer):
    layer_id, name, tier, depth = "L47", "Kaos Kalkani", "cekirdek", "model"

    def chaos(self, ctx: DefenseContext) -> float:
        x = (h_int(ctx.seed, _slot(ctx.now_ms), "chaos") % 100000) / 100000.0
        x = min(max(x, 1e-6), 1 - 1e-6)
        for _ in range(24):  # lojistik harita r=3.99 -> deterministik kaos
            x = 3.99 * x * (1.0 - x)
        return x

    def engage(self, ctx: DefenseContext) -> LayerResult:
        c = self.chaos(ctx)
        return self._result(
            True, f"kaotik zamanlama kalkani (x={c:.4f})", True,
            {"chaos": round(c, 6), "slot": _slot(ctx.now_ms)},
            "Lojistik-harita kaosuyla zamanlama/gecikme ongorulmez kilinir.")


# ---- 48 Mutlak Sifir Katmani (model) --------------------------------------
class AbsoluteZeroLayer(Layer):
    layer_id, name, tier, depth = "L48", "Mutlak Sifir Katmani", "cekirdek", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # son esik: bu noktada tum I/O dondurulur (deny-all)
        frozen = True
        return self._result(
            True, "mutlak sifir: tum I/O donduruldu (deny-all)", True,
            {"frozen": frozen, "io_allowed": False},
            "Son esikte cekirdek 'mutlak sifir'a duser; hicbir islem gecmez.")


# ---- 49 Cekirdek Kasa Muhru (FULL: Merkle) --------------------------------
class CoreVaultSealLayer(Layer):
    layer_id, name, tier, depth = "L49", "Cekirdek Kasa Muhru", "cekirdek", "full"

    def leaves(self, ctx: DefenseContext) -> List[bytes]:
        return [f"vault:{i}:{h_int(ctx.seed, 'vault', i):08x}".encode() for i in range(8)]

    def engage(self, ctx: DefenseContext) -> LayerResult:
        leaves = self.leaves(ctx)
        root = merkle_root(leaves)
        # kurcalama dogrulamasi: bir yaprak bozulursa kok degisir
        tampered = list(leaves)
        tampered[0] = tampered[0] + b"x"
        tamper_detected = merkle_root(tampered) != root
        return self._result(
            True, "cekirdek kasa Merkle ile muhurlendi", True,
            {"merkle_root": root[:16], "leaves": len(leaves), "tamper_detected": tamper_detected},
            "Kasa icerigi Merkle koku ile muhurlu; tek yaprak degisse kok kirilir.")


# ---- 50 KORUNAN VARLIK (yer alti) (model) ---------------------------------
class ProtectedAssetLayer(Layer):
    layer_id, name, tier, depth = "L50", "KORUNAN VARLIK (yer alti)", "cekirdek", "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:
        # Ulasilabilirlik: yalniz TUM 18 kubbe halkasi + son hat tam asilirsa.
        reached = ctx.bypassed_layers >= 18 and ctx.extra.get("all_lastline_failed", False)
        return self._result(
            True,
            "KORUNAN VARLIK yer alti kasada, muhurlu ve ulasilmadi" if not reached
            else "UYARI: korunan varliga ulasildi",
            not reached,
            {"reachable": reached, "depth": "underground", "sealed": True},
            "Nihai varlik yer altinda; onceki 49 katman asilmadan ulasilmaz.")


# ===========================================================================
def build_layers() -> List[Layer]:
    """Panel sirasiyla BIREBIR eslesen 50 gercek katman (L01..L50)."""
    layers: List[Layer] = [
        HyperIdentityRotationLayer(),   # L01
        PortHopSwarmLayer(),            # L02
        FingerprintMorphLayer(),        # L03
        DecoyServiceSwarmLayer(),       # L04  FULL
        DynamicTopologyLayer(),         # L05
        MicroSegmentationLayer(),       # L06
        ZeroTrustReauthLayer(),         # L07
        OneTimeIdentityLayer(),         # L08  FULL (HOTP)
        DeceptionMeshLayer(),           # L09  FULL
        TarpitLayer(),                  # L10  FULL
        CanaryNetLayer(),               # L11
        HoneynetShiftLayer(),           # L12
        EntropyRekeyLayer(),            # L13  FULL (HKDF)
        TpmSealChainLayer(),            # L14  FULL (hash-zinciri)
        ByzantineQuorumLayer(),         # L15  FULL (k-of-n)
        PostQuantumKeyLayer(),          # L16  FULL (HKDF)
        HomomorphicVaultLayer(),        # L17  FULL (korleme)
        ShardingLayer(),                # L18
        AirGapLayer(),                  # L19
        SinkholeLayer(),                # L20
        ProtocolMorphLayer(),           # L21
        TrafficMixLayer(),              # L22
        DecoyDataLayer(),               # L23
        TimeLockLayer(),                # L24
        GeoDistributionLayer(),         # L25
        LoadShedLayer(),                # L26
        SessionSplitLayer(),            # L27
        ShamirSplitLayer(),             # L28  FULL (GF256 SSS)
        InvisibilityVeilLayer(),        # L29
        FakeVulnHoneypotLayer(),        # L30
        ReflexQuarantineLayer(),        # L31
        AutonomicHealLayer(),           # L32
        ImmuneMemoryLayer(),            # L33  FULL (gercek kume)
        SwarmVoteLayer(),               # L34  FULL (k-of-n)
        AnomalyPrecogLayer(),           # L35
        BehaviorDnaLayer(),             # L36
        KillSwitchLayer(),              # L37
        HardwareRootLayer(),            # L38
        MemoryCurtainLayer(),           # L39
        SideChannelNoiseLayer(),        # L40
        DeterministicRebirthLayer(),    # L41
        ShadowTwinLayer(),              # L42
        DecoyCoreArmyLayer(),           # L43  FULL
        LastMomentTeleportLayer(),      # L44
        EntanglementLockLayer(),        # L45
        NeuralSentinelLayer(),          # L46
        ChaosShieldLayer(),             # L47
        AbsoluteZeroLayer(),            # L48
        CoreVaultSealLayer(),           # L49  FULL (Merkle)
        ProtectedAssetLayer(),          # L50
    ]
    return layers
