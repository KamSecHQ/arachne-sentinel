"""
Faz 26 - Adaptif Savunma Durusu (Threat-Informed Posture / DEFCON-benzeri).

--- Adaptif savunma fikri (bu paketin OMURGASI) ---
Savunma sabit degildir; guncel tehdit seviyesine gore YUKSELIR ve DUSER.
Dusuk tehditte sistem sessiz ve az mudahaleci kalir (mesru kullaniciyi
rahatsiz etmez); tehdit tirmandikca daha guclu ama daha maliyetli savunmalar
devreye girer. Bu, saldirganin davranisina gore savunma yapilandirmasini
yeniden duzenlemektir - ko-evrimin merkez dugmesi.

Durum makinesi (dusuk -> yuksek):
    NORMAL    : pasif izleme, standart esikler
    ELEVATED  : loglama artar, ekstra kirinti (breadcrumb) serpilir, esikler daralir
    HIGH      : MTD rotasyonu tetiklenir, Sifir-Guven guven butcesi kisilir
    CRITICAL  : izolasyon/tahliye, tam aldatma angajmani, insan analiste eskalasyon

--- Histerezis (flapping onleme) ---
Skor esigi bir kez asinca aninda en uste ziplamayiz; seviye degisimi icin
skorun M tik boyunca esigin bir tarafinda KALMASI gerekir. Boylece tek bir
gurultu tepesi tum sistemi CRITICAL'e savurmaz, ve tehdit gecince kademeli
olarak geri iner.

--- Gercek dunya karsiligi ---
CISA "Shields Up" durus yukseltmesi; MITRE Center for Threat-Informed Defense;
SOC playbook otomasyonu / kademeli mudahale (SOAR).

--- DURUSTLUK ---
Bu bir KARAR katmanidir; hangi savunmanin ACILACAGINA karar verir, savunmalari
kendisi icermez. "Tetiklenen" eylemler (MTD, izolasyon) ilgili fazlara devredilir.
Esikler ve histerezis deterministiktir, sihir yoktur.

--- ETIK ---
Tum durus eylemleri kendi yuzeyimizde kalir (izolasyon = saldirgani kendi
sahte ortamimizda tutmak; tahliye = kendi oturumunu sonlandirmak). Baska
sisteme karsi hicbir eylem yoktur.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Seviye tanimlari: esik (bu seviyeye cikmak icin gereken skor) ve acilan
# savunma yetenekleri. Esikler birikimli tehdit skoruna gore (0..100+).
LEVELS = [
    {
        "name": "NORMAL",
        "rank": 0,
        "enter_score": 0,
        "color": "45,212,191",
        "unlocks": ["pasif izleme", "standart esikler"],
        "description_tr": "Sakin durum. Mesru trafik cezalandirilmaz.",
    },
    {
        "name": "ELEVATED",
        "rank": 1,
        "enter_score": 25,
        "color": "245,166,35",
        "unlocks": ["artirilmis loglama", "ekstra kirinti serpme", "daraltilmis esikler"],
        "description_tr": "Supheli hareketlilik. Gozetim ve tuzak yogunlugu artar.",
    },
    {
        "name": "HIGH",
        "rank": 2,
        "enter_score": 55,
        "color": "255,120,60",
        "unlocks": ["MTD rotasyonu", "Sifir-Guven butce kisiti", "aktif aldatma"],
        "description_tr": "Aktif tehdit. Hareketli hedef ve sifir-guven sertlesir.",
    },
    {
        "name": "CRITICAL",
        "rank": 3,
        "enter_score": 80,
        "color": "255,59,69",
        "unlocks": ["izolasyon/tahliye", "tam aldatma angajmani", "insan analiste eskalasyon"],
        "description_tr": "Kritik. Saldirgan izole edilir, analist devreye alinir.",
    },
]

LEVEL_BY_NAME = {lv["name"]: lv for lv in LEVELS}
_ORDERED = sorted(LEVELS, key=lambda lv: lv["rank"])


@dataclass
class PostureState:
    level: str
    rank: int
    score: float
    unlocks: List[str]
    reason: str
    changed: bool
    triggered_actions: List[str] = field(default_factory=list)


class AdaptivePosture:
    """Birikimli tehdit skorunu histerezisli bir durum makinesiyle savunma
    durusuna cevirir."""

    def __init__(self, hysteresis_ticks: int = 2):
        # Seviye degisimi icin skorun kac tik hedef bolgede kalmasi gerektigi.
        self.hysteresis_ticks = hysteresis_ticks
        self._level_rank = 0
        self._pending_rank: Optional[int] = None
        self._pending_count = 0
        self._last_score = 0.0

    @property
    def level(self) -> str:
        return _ORDERED[self._level_rank]["name"]

    def _target_rank(self, score: float) -> int:
        """Verilen skorun karsilik geldigi seviye sirasi (histerezissiz)."""
        rank = 0
        for lv in _ORDERED:
            if score >= lv["enter_score"]:
                rank = lv["rank"]
        return rank

    def update(self, score: float) -> PostureState:
        """Yeni birikimli tehdit skoruyla durusu gunceller.

        Histerezis: hedef seviye mevcuttan farkliysa, degisim ancak ayni hedef
        `hysteresis_ticks` kez ust uste gorulurse uygulanir. Boylece tek bir
        gurultu tepesi durusu savurmaz."""
        self._last_score = score
        target = self._target_rank(score)
        changed = False
        triggered: List[str] = []

        if target == self._level_rank:
            # Zaten dogru seviyedeyiz; bekleyen degisimi iptal et.
            self._pending_rank = None
            self._pending_count = 0
        else:
            if target == self._pending_rank:
                self._pending_count += 1
            else:
                self._pending_rank = target
                self._pending_count = 1

            if self._pending_count >= self.hysteresis_ticks:
                old_rank = self._level_rank
                # Bir seferde tek kademe hareket et (kademeli tirmanis/inis),
                # hedef uzaksa bir sonraki update yine ilerletir.
                self._level_rank += 1 if target > old_rank else -1
                changed = True
                self._pending_rank = None
                self._pending_count = 0
                if self._level_rank > old_rank:
                    triggered = list(_ORDERED[self._level_rank]["unlocks"])

        lv = _ORDERED[self._level_rank]
        if changed and triggered:
            reason = (
                f"Durus {lv['name']} seviyesine YUKSELDI (skor {score:.0f}). "
                f"Acilan savunmalar: {', '.join(triggered)}."
            )
        elif changed:
            reason = (
                f"Tehdit geriledi; durus {lv['name']} seviyesine DUSURULDU "
                f"(skor {score:.0f}). Maliyetli savunmalar kademeli kapatildi."
            )
        else:
            pend = ""
            if self._pending_rank is not None:
                pend = (f" (hedef {_ORDERED[self._pending_rank]['name']}, "
                        f"onay {self._pending_count}/{self.hysteresis_ticks})")
            reason = f"Durus {lv['name']} (skor {score:.0f}), stabil{pend}."

        return PostureState(
            level=lv["name"],
            rank=lv["rank"],
            score=round(score, 2),
            unlocks=list(lv["unlocks"]),
            reason=reason,
            changed=changed,
            triggered_actions=triggered,
        )

    def snapshot(self) -> dict:
        lv = _ORDERED[self._level_rank]
        return {
            "level": lv["name"],
            "rank": lv["rank"],
            "score": round(self._last_score, 2),
            "color": lv["color"],
            "unlocks": list(lv["unlocks"]),
            "description_tr": lv["description_tr"],
            "all_levels": [
                {"name": l["name"], "rank": l["rank"], "enter_score": l["enter_score"],
                 "color": l["color"], "active": l["rank"] <= lv["rank"]}
                for l in _ORDERED
            ],
        }


def score_from_signals(
    ensemble_threat: float = 0.0,
    critical_alerts: int = 0,
    blocked_ips: int = 0,
    honeytoken_triggers: int = 0,
    sybil_actors: int = 0,
    slow_burners: int = 0,
) -> float:
    """Farkli fazlarin sinyallerini tek bir birikimli durus skoruna (0..100+)
    cevirir. Her terim aciklanabilir ve sinirlidir; agirliklar dokumantedir."""
    score = 0.0
    score += min(40.0, ensemble_threat * 12.0)     # birlesik tehdit yogunlugu
    score += min(30.0, critical_alerts * 6.0)       # kritik alarm sayisi
    score += min(15.0, blocked_ips * 1.5)           # engellenen IP hacmi
    score += min(25.0, honeytoken_triggers * 12.0)  # honeytoken = yuksek guven
    score += min(15.0, sybil_actors * 5.0)          # kimlik rotasyonu
    score += min(15.0, slow_burners * 5.0)          # dusuk-ve-yavas
    return round(score, 2)
