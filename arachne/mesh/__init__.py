"""
Faz 9 - Dagitik Sensor Agi ("gercek orumcek agi").

Tek bir honeypot bir noktadir; birbirine bagli sensorler bir AGdir.

    [Sensor: DMZ]  ----+
    [Sensor: ic ag] ---+---> [Merkezi Toplayici] ---> [Tespit + SOAR + Panel]
    [Sensor: bulut] ---+          (HMAC dogrulamali)

Moduller:
    crypto.py    - HMAC-SHA256 imzalama, nonce, tekrar oynatma korumasi
    sensor.py    - sensor dugumu istemcisi (kuyruk + toplu gonderim)
    collector.py - merkezi toplayici (Flask blueprint)

--- Neden kimlik dogrulama sart? ---
Dogrulanmamis sensor raporlarini kabul eden bir SOAR sistemi, saldirganin
elinde silaha donusur: sahte raporlarla masum IP'leri engelletebilir.
Bu yuzden her mesaj HMAC ile imzalanir, zaman damgasi ve nonce ile
tekrar oynatmaya karsi korunur.
"""

from .crypto import (
    generate_nonce,
    sign_message,
    using_default_secret,
    verify_message,
)
from .sensor import Sensor

__all__ = [
    "Sensor",
    "sign_message",
    "verify_message",
    "generate_nonce",
    "using_default_secret",
]
