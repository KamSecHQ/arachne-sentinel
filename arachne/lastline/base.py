"""
Son Hat (Yer Alti Ultra Savunma) — ortak sozlesme/temel tipler.

Buradaki tipler HEM fortress orkestratoru HEM de 50 katmanin uzerinde anlastigi
arayuzdur. Tamamen savunma: hicbir katman baska bir sisteme dokunmaz, disari
paket gondermez. Her katman GERCEK bir hesap yapar ve GERCEK bir sonuc dondurur
(uydurma yok); veri yoksa notr/guvenli sonuc uretir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DefenseContext:
    """Bir saldirgan oturumunun + korunan varligin son-hat icin gereken durumu.

    Alanlar GERCEK sinyallerden doldurulur (aggregator/storage) ya da tatbikat
    icin acikca verilir. Hicbiri disari bir eylem tetiklemez.
    """
    attacker_ip: str = "198.18.0.1"
    fused_posterior: float = 0.0        # Faz 43 tehdit fuzyonu sonsal olasiligi
    honeytoken_tripped: bool = False    # Faz 12 tuzak tetiklendi mi
    bypassed_layers: int = 0            # kubbede kac derin halka asildi (0..18)
    attempts: int = 0                   # bu oturumdaki deneme sayisi
    services_touched: int = 1           # kac farkli servis
    novelty: float = 0.0                # Faz 42 yenilik skoru (0..1)
    now_ms: int = 0                     # deterministik saat (ms) — testlerde enjekte edilir
    seed: str = "arachne"               # deterministik cekirdek (kimlik/karar uretimi)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LayerResult:
    """Tek bir katmanin GERCEK cikti/karari."""
    layer_id: str
    name: str
    tier: str
    engaged: bool                       # katman devreye girdi mi (muhurlendi)
    action: str                         # ne yapti (kisa, insan-okur)
    blocks_lock: bool                   # saldirganin gercek varligi KILITLEMESINI engelledi mi
    metric: Dict[str, Any] = field(default_factory=dict)   # gercek olculer
    detail: str = ""


class Layer:
    """50 katmanin ortak temeli. Her somut katman `engage()`'i override eder.

    SOZLESME:
      * engage(ctx) DETERMINISTIK olmali (ayni ctx -> ayni sonuc), test edilebilsin.
      * Yan etkisi yalnizca kendi ic durumu olabilir; DISARI dokunamaz.
      * Her zaman bir LayerResult dondurur; asla exception sizdirmaz (fortress
        yine de try/except ile sarar).
    """
    layer_id: str = "base"
    name: str = "Temel Katman"
    tier: str = "genel"
    #: kavramin gercek uygulama derinligi — dürüstlük etiketi
    #: "full"  = tam, uctan uca gercek uygulama ( or. Shamir, HOTP, hash-zinciri)
    #: "model" = gercek hesap yapan ama sadelestirilmis deterministik model
    depth: str = "model"

    def engage(self, ctx: DefenseContext) -> LayerResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # kolaylik: alt siniflarin standart bir sonuc uretmesi icin yardimci
    def _result(self, engaged: bool, action: str, blocks_lock: bool,
                metric: Optional[Dict[str, Any]] = None, detail: str = "") -> LayerResult:
        return LayerResult(layer_id=self.layer_id, name=self.name, tier=self.tier,
                           engaged=engaged, action=action, blocks_lock=blocks_lock,
                           metric=metric or {}, detail=detail)


# --- deterministik yardimci hash (Python <-> JS PARITE) ---------------------
# FNV-1a 32-bit. Ayni algoritma bunker3d.js'te de var; boylece sunucu ve
# tarayici AYNI kimligi uretir (gercek, dogrulanabilir determinizm).
def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def h_int(*parts: Any) -> int:
    return fnv1a(":".join(str(p) for p in parts))
