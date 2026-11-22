"""
Arachne Adversary — kirmizi takim (red team) test motoru.

AMAC: Kendi savunma platformumuzu (Arachne Sentinel) test etmek. Saldiri
tarafinda ne kadar gelisirsek, savunmanin zayif noktalarini o kadar erken
bulur ve onu yukari çekeriz (kirmizi-mavi ko-evrimi).

ETIK SINIR (kod seviyesinde zorlanir — bkz. safety.py):
  * Yalnizca localhost / kendi izole lab hedefimize saldirir.
  * Disariya saldiri, veri sizdirma, gerçek RCE, kalicilik YOKTUR.
  * Yukler test dizeleridir; hedef bilinçli-zafiyetli kendi lab uygulamamizdir.
"""
from .safety import assert_local_target, is_local_target, RedTeamSafetyError
from . import payloads, mutators, engine

__all__ = [
    "assert_local_target", "is_local_target", "RedTeamSafetyError",
    "payloads", "mutators", "engine",
]
