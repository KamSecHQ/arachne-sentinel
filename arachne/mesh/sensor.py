"""
Sensor dugumu istemcisi - agin ucundaki "orumcek ayagi".

Bir sensor, kendi bulundugu agda honeypot calistirir ve gozlemlerini
periyodik olarak merkezi toplayiciya imzali sekilde raporlar.

--- Neden dagitik? ---
Tek noktadan izleme, saldirganin sadece o noktaya gelen trafigini gorur.
Farkli aglara/segmentlere yerlestirilmis sensorler ise:
  * saldirganin yatay hareketini (lateral movement) gorunur kilar
  * bir sensordeki davranisi digerindeki gecmisle korele eder
  * tek bir sensor ele gecirilse bile agin geri kalani calismaya devam eder

Gercek urunlerdeki dagitik sensor mimarisinin (ornek: honeypot aglari,
EDR ajanlari) kucuk olcekli ama calisir bir karsiligidir.

--- Toplu gonderim (batching) ---
Her olay icin ayri HTTP istegi atmak, hem agi hem toplayiciyi bogar.
Sensor olaylari bir kuyrukta biriktirir ve periyodik olarak toplu gonderir.
Kuyruk dolarsa EN ESKI olaylar dusurulur - cunku bir saldiri sirasinda
en yeni veriler daha degerlidir.
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque

from . import crypto

logger = logging.getLogger(__name__)

DEFAULT_COLLECTOR_URL = "http://127.0.0.1:5000/mesh/ingest"
DEFAULT_FLUSH_INTERVAL = 10        # saniye
DEFAULT_QUEUE_SIZE = 500
SENSOR_VERSION = "1.0"
REQUEST_TIMEOUT = 10


class Sensor:
    """Bir honeypot sensor dugumu.

    Kullanim:
        sensor = Sensor("kenar-01", location="DMZ")
        sensor.observe("203.0.113.5", "ssh", "connect", dest_port=22)
        sensor.flush()          # ya da sensor.start_auto_flush()
    """

    def __init__(self, sensor_id: str, collector_url: str = None,
                 location: str = "", secret: str = None,
                 queue_size: int = DEFAULT_QUEUE_SIZE):
        self.sensor_id = sensor_id
        self.collector_url = collector_url or DEFAULT_COLLECTOR_URL
        self.location = location
        self.secret = secret
        # deque(maxlen=...): kuyruk dolunca en eski otomatik dusurulur
        self._queue = deque(maxlen=queue_size)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.stats = {
            "observed": 0, "sent": 0, "failed": 0,
            "dropped": 0, "last_flush": None, "last_error": None,
        }

    # --- Gozlem ------------------------------------------------------------

    def observe(self, source_ip: str, service: str, event_type: str,
                source_port=None, dest_port=None, payload=None):
        """Bir olayi kuyruga ekler (bloklamaz)."""
        event = {
            "source_ip": source_ip,
            "service": service,
            "event_type": event_type,
            "source_port": source_port,
            "dest_port": dest_port,
            "payload": payload,
        }
        with self._lock:
            if len(self._queue) == self._queue.maxlen:
                self.stats["dropped"] += 1
            self._queue.append(event)
            self.stats["observed"] += 1

    def pending_count(self) -> int:
        with self._lock:
            return len(self._queue)

    # --- Gonderim ----------------------------------------------------------

    def build_report(self, events: list) -> dict:
        """Imzali rapor zarfini olusturur."""
        payload = {
            "sensor_id": self.sensor_id,
            "location": self.location,
            "version": SENSOR_VERSION,
            "events": events,
        }
        return crypto.sign_message(payload, secret=self.secret)

    def flush(self) -> dict:
        """Kuyruktaki olaylari toplayiciya gonderir.

        Basarisiz gonderimde olaylar kuyruga GERI KONUR (basa) - gecici ag
        kesintisinde veri kaybolmaz. Bu, dagitik sistemlerde 'at-least-once'
        teslimat garantisinin basit bir uygulamasidir."""
        with self._lock:
            if not self._queue:
                return {"ok": True, "sent": 0, "detail": "kuyruk bos"}
            events = list(self._queue)
            self._queue.clear()

        envelope = self.build_report(events)
        body = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.collector_url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.stats["sent"] += result.get("accepted", 0)
            self.stats["last_flush"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.stats["last_error"] = None
            return {"ok": True, "sent": result.get("accepted", 0), "response": result}

        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                json.JSONDecodeError) as exc:
            self.stats["failed"] += 1
            self.stats["last_error"] = str(exc)
            logger.warning("Sensor %s gonderim hatasi: %s", self.sensor_id, exc)
            # Olaylari geri koy (en basa - sira korunur)
            with self._lock:
                for event in reversed(events):
                    if len(self._queue) < (self._queue.maxlen or 0):
                        self._queue.appendleft(event)
                    else:
                        self.stats["dropped"] += 1
            return {"ok": False, "error": str(exc), "requeued": len(events)}

    # --- Otomatik gonderim dongusu ----------------------------------------

    def start_auto_flush(self, interval: int = DEFAULT_FLUSH_INTERVAL):
        """Arka planda periyodik gonderim baslatir."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.flush()
                except Exception:
                    logger.exception("Sensor otomatik gonderim hatasi")

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name=f"sensor-{self.sensor_id}")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.flush()

    def status(self) -> dict:
        return {
            "sensor_id": self.sensor_id,
            "location": self.location,
            "collector_url": self.collector_url,
            "pending": self.pending_count(),
            "version": SENSOR_VERSION,
            **self.stats,
        }
