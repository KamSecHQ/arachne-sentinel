"""
Son Hat — Yer Alti Ultra Savunma Kalesi (GERCEK motor, Faz 82-100).

Kubbe delinince devreye giren, 50 GERCEK savunma katmani + deterministik hiper
hareketli hedef (HAYALET) kimlik motoru. Tamamen savunma; hicbir katman disari
dokunmaz. Tum davranis deterministik ve test edilebilirdir.
"""
from .base import DefenseContext, LayerResult, Layer, fnv1a, h_int
from .identity import HyperMTD, identity_at
from .fortress import LastLineFortress, context_from_live

__all__ = [
    "DefenseContext", "LayerResult", "Layer", "fnv1a", "h_int",
    "HyperMTD", "identity_at", "LastLineFortress", "context_from_live",
]
