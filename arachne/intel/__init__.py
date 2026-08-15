"""
Faz 6 - Tehdit Istihbarati ve Saldirgan Profilleme.

Faz 5 tek bir saldiriyi analiz eder; bu katman ise saldirganlari
ZAMAN ICINDE ve BIRBIRLERINE GORE degerlendirir:

  * profiler.py    - her IP icin davranissal parmak izi cikarir
                     (zamanlama, servis tercihi, yuk stili)
  * profiler.py    - ayni parmak izine sahip farkli IP'leri "kampanya"
                     olarak birlestirir (correlation)
  * geo.py         - cevrimdisi IP siniflandirmasi ve bolge tahmini
  * stix_export.py - bulgulari STIX 2.1 formatinda disari aktarir
  * attck.py       - MITRE ATT&CK / CWE / CAPEC / Kill Chain eslemesi

Neden onemli: Tek bir alarm gurultu olabilir. Ama "bu 5 farkli IP ayni
araci, ayni zamanlama parmak iziyle kullaniyor" demek, bir KAMPANYA tespit
etmektir - gercek tehdit istihbaratinin yaptigi is budur.
"""

from . import attck
from .geo import classify_ip_scope, region_hint, geo_for_ip
from .profiler import build_profile, correlate_campaigns, behavioral_signature
from .stix_export import build_stix_bundle, indicator_for_ip

__all__ = [
    "attck",
    "classify_ip_scope",
    "region_hint",
    "geo_for_ip",
    "build_profile",
    "correlate_campaigns",
    "behavioral_signature",
    "build_stix_bundle",
    "indicator_for_ip",
]
