"""
GUVENLIK KAPISI — Arachne Adversary yalnizca YEREL/IZOLE hedefe saldirabilir.

Bu modul, motorun localhost (loopback) disina CIKAMAMASINI kod seviyesinde
zorlar. Bu bir "ayar" ya da acilip kapanan bir bayrak DEGILDIR; sabit bir
kisittir. Amac tamamen savunma testidir: kendi lab hedefimize saldirip kendi
WAF/savunmamizi olçmek. Disaridaki hicbir sisteme dokunulmaz.

Kabul edilen hedefler:
  * In-process bir WSGI uygulamasi (ag yok) — her zaman guvenli.
  * Yalnizca loopback URL'leri: 127.0.0.0/8, ::1, localhost, *.localhost.
Bunun disindaki her hedef RedTeamSafetyError ile REDDEDILIR.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

LOOPBACK_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}


class RedTeamSafetyError(RuntimeError):
    """Yerel olmayan bir hedefe saldiri girisimi engellendi."""


def _host_is_loopback(host: str) -> bool:
    if not host:
        return False
    h = host.strip().strip("[]").lower()
    if h in LOOPBACK_HOSTNAMES or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def assert_local_target(target) -> None:
    """Hedef yerel degilse RedTeamSafetyError firlatir.

    `target` bir WSGI uygulamasi (cagirilebilir/`.wsgi_app`'i olan) ise ag'a
    cikmadigimiz icin guvenlidir. String ise loopback URL olmak ZORUNDADIR.
    """
    # In-process uygulama nesnesi: ag yok, guvenli.
    if not isinstance(target, str):
        if callable(target) or hasattr(target, "wsgi_app") or hasattr(target, "test_client"):
            return
        raise RedTeamSafetyError(
            "Taninmayan hedef turu; yalnizca loopback URL ya da in-process WSGI uygulamasi.")

    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname or ""
    if not _host_is_loopback(host):
        raise RedTeamSafetyError(
            f"REDDEDILDI: '{host}' loopback degil. Arachne Adversary yalnizca "
            f"localhost/127.0.0.1 uzerindeki KENDI lab hedefine saldirabilir. "
            f"Bu kisit tasarim geregidir; disariya saldiri desteklenmez.")


def is_local_target(target) -> bool:
    try:
        assert_local_target(target)
        return True
    except RedTeamSafetyError:
        return False
