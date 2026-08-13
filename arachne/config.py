"""
Arachne Sentinel - merkezi konfigurasyon.

ONEMLI: Bu proje SADECE izole/lab ortamlarinda ve sahibi oldugunuz
sistemlerde kullanilmak uzere tasarlanmistir. Detaylar icin
docs/ETHICS_AND_LEGAL.md dosyasina bakin.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "arachne.db"
ML_MODEL_PATH = DATA_DIR / "ml_model.joblib"

# Sahte (honeypot) servisler: isim -> ayarlar
FAKE_SERVICES = {
    "ssh": {
        "port": 2222,
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
    },
    "ftp": {
        "port": 2121,
        "banner": "220 ProFTPD 1.3.6 Server (ArachneFTP) ready.\r\n",
    },
    "mysql": {
        "port": 3307,
        # Basitlestirilmis sahte MySQL handshake baytlari (gercek protokol degil,
        # sadece "bir MySQL sunucusu var" izlenimi vermek icin yeterli)
        "banner": "J\x00\x00\x00\n8.0.34-0ubuntu0.22.04.1\x00",
    },
    "http-admin": {
        "port": 8081,
        "banner": None,  # HTTP kendi response'unu listeners.py icinde uretir
    },
}

# Baglanti basina en fazla ne kadar veri okunacak (byte) - kaynak tuketimini sinirlar
MAX_PAYLOAD_BYTES = 2048
# Bir baglantidan veri okumak icin beklenecek maksimum sure (saniye)
READ_TIMEOUT_SECONDS = 5

# Skorlama esikleri (skorun bu degere ulasmasi/gecmesi durumunda ilgili seviye atanir)
SEVERITY_THRESHOLDS = {
    "low": 0,
    "medium": 30,
    "high": 60,
    "critical": 90,
}
ALERT_MIN_SCORE = 30  # bu skorun altindaki degerlendirmeler alarm olusturmaz

# scorer.evaluate_ip() bir IP'nin son kac saniyesini degerlendirmeye alsin
DEFAULT_LOOKBACK_SECONDS = 120

# Kural esikleri
PORT_SCAN_DISTINCT_PORTS = 3
BRUTE_FORCE_ATTEMPTS = 5
MULTI_SERVICE_COUNT = 2
