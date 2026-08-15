"""
Tarpit (katran cukuru) - saldirgani kasitli yavaslatma.

--- Fikir ---
Bir saldirgan honeypot'a baglandiginda, hemen cevap vermek yerine cevabi
KASITLI OLARAK yavaslatiriz. Amac:
  1. Saldirganin/botun zamanini ve kaynaklarini harcamak.
  2. Otomatik araclari zaman asimina ugratmak (cogu kisa timeout kullanir).
  3. Bir insan analiste tepki vermesi icin sure kazandirmak.

Bu, mesru "LaBrea tarpit" ve SSH tarpit (endlessh) araclarinin mantigidir
ve tamamen savunmacidir: saldirgana ZARAR vermez, sadece onu kendi
tuzagimizda bekletir.

--- Uyarlanabilir gecikme ---
Gecikme sabit degildir; saldirganin tehdit seviyesine gore artar. Dusuk
supheli bir baglanti neredeyse hic yavaslatilmaz (yanlislikla baglanan
mesru bir kullaniciyi cezalandirmamak icin); yuksek tehditli, israrli bir
saldirgan giderek daha cok yavaslatilir.

--- Guvenlik siniri ---
Maksimum gecikme sinirlidir (MAX_DELAY). Sonsuz tutmak, kendi
kaynaklarimizi (acik baglanti sayisi) tuketebilir - saldirgani degil bizi
yorar. Her savunma onlemi kendi maliyetini gozetmelidir.
"""
from dataclasses import dataclass

# Gecikme sinirlari (saniye)
MIN_DELAY = 0.0
MAX_DELAY = 8.0
BASE_DELAY = 0.5


@dataclass
class TarpitPolicy:
    """Tarpit gecikmesini belirleyen politika."""
    enabled: bool = True
    base_delay: float = BASE_DELAY
    max_delay: float = MAX_DELAY
    # Her onceki alarmda gecikmeye eklenecek carpan
    escalation_per_alert: float = 0.8


def compute_tarpit_delay(threat_score: int, prior_alerts: int = 0,
                         policy: TarpitPolicy = None) -> dict:
    """Bir baglanti icin tarpit gecikmesini hesaplar.

    threat_score : 0-100 arasi anlik tehdit skoru
    prior_alerts : bu IP'nin gecmiste urettigi alarm sayisi

    Uyarlanabilir: dusuk skorlu ilk baglanti neredeyse hic beklemez;
    yuksek skorlu, tekrarlayan saldirgan maksimuma yaklasir."""
    policy = policy or TarpitPolicy()
    if not policy.enabled:
        return {"delay": 0.0, "applied": False, "reason": "tarpit kapali"}

    # Dusuk tehdit -> minimal gecikme (mesru kullaniciyi cezalandirma)
    if threat_score < 20 and prior_alerts == 0:
        return {"delay": 0.0, "applied": False,
                "reason": "dusuk tehdit - mesru baglanti olabilir, yavaslatilmadi"}

    # Skor tabanli taban gecikme (0-100 skoru 0-1'e olcekle)
    score_factor = threat_score / 100.0
    delay = policy.base_delay + score_factor * (policy.max_delay - policy.base_delay)

    # Tekrarlayan saldirgan icin ek yavaslatma
    delay += prior_alerts * policy.escalation_per_alert

    delay = max(MIN_DELAY, min(policy.max_delay, delay))

    return {
        "delay": round(delay, 2),
        "applied": delay > 0,
        "reason": (
            f"Tarpit: {delay:.1f}sn gecikme (tehdit skoru {threat_score}, "
            f"{prior_alerts} onceki alarm) - saldirganin zamani harcaniyor"
        ),
    }


def tarpit_banner_stream(base_banner: str, delay: float, chunks: int = 8):
    """Bir banner'i, tarpit gecikmesine yayarak kucuk parcalara boler.

    Endlessh mantigi: banner'i tek seferde degil, yavas yavas byte byte
    gonderirsek saldirgan baglantiyi acik tutmak zorunda kalir. Bu fonksiyon
    (parca, parca_gecikmesi) ciftleri uretir - dinleyici bunu kullanarak
    yavas yavas gonderir."""
    if not base_banner:
        return
    per_chunk_delay = delay / max(1, chunks)
    size = max(1, len(base_banner) // chunks)
    for i in range(0, len(base_banner), size):
        yield base_banner[i:i + size], per_chunk_delay
