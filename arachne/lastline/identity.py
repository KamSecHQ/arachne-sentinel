"""
HAYALET — Hiper Hareketli Hedef Kimlik motoru (GERCEK, deterministik).

Korunan varligin kimligini (IP/port/parmak-izi/tek-kullanimlik jeton) her
`interval_ms` (varsayilan 100 ms) DETERMINISTIK olarak dondurur. "Deterministik"
onemli: ayni (seed, zaman-dilimi) -> AYNI kimlik. Boylece:
  * sunucu ve tarayici BIREBIR AYNI kimligi uretir (bunker3d.js ayni FNV-1a'yi
    kullanir) — gosterge rastgele degil, dogrulanabilir gercek bir MTD akisidir;
  * test edilebilir: bir saati enjekte edip rotasyonu birebir dogrularsin.

Savunma mantigi: hedef 100 ms'de bir yer degistirdigi icin bir saldirgan gercek
varligi "kilitleyemez" — elindeki (IP,port,fp) uclusu ~100 ms sonra gecersizdir.
Adresler RFC 2544/5737 test araliklarindandir (lab; gercek yonlendirilebilir
adres iddiasi yoktur). Tamamen savunma.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional

from .base import fnv1a


def _slot(now_ms: int, interval_ms: int) -> int:
    return now_ms // max(1, interval_ms)


def identity_at(now_ms: int, seed: str = "arachne", interval_ms: int = 100) -> Dict[str, object]:
    """Verilen zaman icin DETERMINISTIK kimlik. (bunker3d.js ile birebir ayni.)"""
    slot = _slot(now_ms, interval_ms)
    base = f"{seed}:{slot}"
    ip1 = fnv1a(base + ":ip1") % 256
    ip2 = fnv1a(base + ":ip2") % 256
    ip = f"198.18.{ip1}.{ip2}"                 # RFC 2544 test araligi
    port = 1024 + (fnv1a(base + ":port") % 64512)
    fp = f"{fnv1a(base + ':fp1'):08x}{fnv1a(base + ':fp2') % 0x10000:04x}"  # 12 hex
    token = f"{fnv1a(base + ':tok'):08x}"      # tek-kullanimlik oturum jetonu
    return {"slot": slot, "ip": ip, "port": int(port), "fingerprint": fp, "token": token}


@dataclass
class HyperMTD:
    """Hiper hareketli hedef durum makinesi.

    `clock` enjekte edilebilir (testte deterministik). `engage()` cagrildiginda
    tepki suresini (ms) olcer ve devreye girer; ondan sonra `current()` gecerli
    zaman dilimine ait kimligi verir. `rotations()` epoch'tan bu yana kac kez
    dondugunu dogru sekilde raporlar.
    """
    seed: str = "arachne"
    interval_ms: int = 100
    clock: Optional[object] = None      # callable -> now_ms; None ise gercek saat
    engaged: bool = False
    epoch_ms: int = 0
    reaction_ms: float = 0.0

    def _now(self) -> int:
        if self.clock is not None:
            return int(self.clock())
        return int(time.time() * 1000)

    def engage(self, breach_ms: Optional[int] = None) -> float:
        """Ihlal aninda devreye gir. Tepki suresi = simdi - breach_ms (ms).
        Gercek makinede devreye girme anlik oldugu icin tepki suresi ~0'dir;
        garanti butcesi 100 ms'nin ALTINDA olmalidir (test bunu dogrular)."""
        now = self._now()
        self.epoch_ms = now
        self.engaged = True
        self.reaction_ms = float(max(0, now - breach_ms)) if breach_ms is not None else 0.0
        return self.reaction_ms

    def standby(self) -> None:
        self.engaged = False

    def current(self) -> Dict[str, object]:
        return identity_at(self._now(), self.seed, self.interval_ms)

    def rotations(self) -> int:
        if not self.engaged:
            return 0
        return _slot(self._now(), self.interval_ms) - _slot(self.epoch_ms, self.interval_ms)

    def params(self) -> Dict[str, object]:
        """Tarayicinin AYNI kimligi uretebilmesi icin gereken parametreler."""
        return {"seed": self.seed, "interval_ms": self.interval_ms,
                "engaged": self.engaged, "epoch_ms": self.epoch_ms}
