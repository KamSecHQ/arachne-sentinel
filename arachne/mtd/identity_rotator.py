"""Servis banner/surum kimliginin periyodik rotasyonu.

Fikir basit ama gercek: bir saldirgan iki farkli zamanda ayni servisi
tararsa, iki farkli "surum" gorsun - boylece guvenilir bir parmak izi
(fingerprint) cikaramasin, hangi CVE'nin uygulanabilir oldugunu
kestiremesin. Bu, akademik "moving target defense" literaturunde bilinen,
gercek bir savunma teknigidir - "hersey gorunmez olsun" gibi abartili bir
iddia tasimaz, sadece recon'u zorlastirir.

Test edilebilirlik icin saat (clock) disaridan enjekte edilebilir - gercek
zaman.monotonic() yerine sahte/kontrol edilebilir bir sayac verilebilir."""
import time

from .. import storage

# Her servis icin donen banner varyantlari. Hepsi gercekci ama farkli
# surum/dagitim bilgisi tasiyor - amaci gercekten var olan urunleri taklit
# etmek degil, "surekli degisen bir yuzey" izlenimi vermek.
BANNER_POOL = {
    "ssh": [
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        "SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n",
        "SSH-2.0-OpenSSH_8.4p1 Raspbian-5\r\n",
    ],
    "ftp": [
        "220 ProFTPD 1.3.6 Server (ArachneFTP) ready.\r\n",
        "220 vsFTPd 3.0.5 ready.\r\n",
        "220 Pure-FTPd 1.0.49 ready.\r\n",
    ],
    "mysql": [
        "J\x00\x00\x00\n8.0.34-0ubuntu0.22.04.1\x00",
        "J\x00\x00\x00\n5.7.42-log\x00",
        "J\x00\x00\x00\n8.0.29\x00",
    ],
}


class IdentityRotator:
    """rotate_interval_seconds dolunca current_banner() cagrisinda otomatik
    olarak bir sonraki varyanta gecer ve rotasyonu storage'a (mtd_rotations)
    kaydeder. Rotasyon "tembel" (lazy) calisir - ayri bir arka plan
    thread/timer gerektirmez, sadece current_banner() cagrildiginda kontrol
    eder; bu da honeypot'un asyncio dongusune ek karmasiklik eklemez."""

    def __init__(self, rotate_interval_seconds=300, clock=time.monotonic, db_path=None):
        self.rotate_interval_seconds = rotate_interval_seconds
        self._clock = clock
        self._db_path = db_path
        self._index = {name: 0 for name in BANNER_POOL}
        self._last_rotation = {name: self._clock() for name in BANNER_POOL}

    def current_banner(self, service_name: str):
        pool = BANNER_POOL.get(service_name)
        if not pool:
            return None
        self._maybe_rotate(service_name, pool)
        return pool[self._index[service_name] % len(pool)]

    def _maybe_rotate(self, service_name: str, pool):
        if len(pool) < 2:
            return
        now = self._clock()
        elapsed = now - self._last_rotation[service_name]
        if elapsed < self.rotate_interval_seconds:
            return
        old = pool[self._index[service_name] % len(pool)]
        self._index[service_name] += 1
        self._last_rotation[service_name] = now
        new = pool[self._index[service_name] % len(pool)]
        storage.log_mtd_rotation(
            component=f"banner:{service_name}",
            old_identity=old,
            new_identity=new,
            reason=f"{self.rotate_interval_seconds}sn rotasyon araligi doldu",
            db_path=self._db_path,
        )
