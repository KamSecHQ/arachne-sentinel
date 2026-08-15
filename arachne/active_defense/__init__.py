"""
Faz 11-12 - Aktif Savunma ve Aldatma (Active Defense & Deception).

--- ONEMLI ETIK VE HUKUKI CERCEVE ---
Bu modulun adi "misilleme" cagristirabilir ama BASKA BIR SISTEME SALDIRMAZ
(hack-back). Baskasinin sistemine karsi saldiri (karsi-saldiri) bircok
ulkede - Turkiye dahil - suctur ve bu projenin ilkesine aykiridir.

Burada kurulan sey, "aktif savunma"nin HUKUKA UYGUN ve savunulabilir
turudur: saldirgani KENDI honeypot'umuzun icinde oyalamak, yavaslatmak,
sahte veriyle yanlis yone yonlendirmek ve tuzak (honeytoken) yerlestirmek.
Tum eylemler bizim kendi kontrolumuzdeki yuzeyde gerceklesir; disariya
tek bir paket bile saldiri amaciyla gonderilmez.

Bu ayrim, ABD MITRE "Engage" cercevesinin (adversary engagement) ve
"active defense" literaturunun temelidir - ve juri karsisinda projenin
en guclu duruslarindan biridir.

Moduller:
  tarpit.py      - saldirgani kasitli yavaslatma, zamanini harcama
  deception.py   - sahte basari/veri yanitlari, yanlis yonlendirme
  honeytokens.py - izlenebilir tuzak kimlik bilgileri (Faz 12)
"""

from .deception import (
    DeceptionEngine,
    decide_response,
    generate_fake_filesystem,
    generate_fake_credentials,
)
from .honeytokens import (
    HoneytokenVault,
    generate_honeytoken,
    check_payload_for_tokens,
)
from .tarpit import compute_tarpit_delay, TarpitPolicy

__all__ = [
    "DeceptionEngine",
    "decide_response",
    "generate_fake_filesystem",
    "generate_fake_credentials",
    "HoneytokenVault",
    "generate_honeytoken",
    "check_payload_for_tokens",
    "compute_tarpit_delay",
    "TarpitPolicy",
]
