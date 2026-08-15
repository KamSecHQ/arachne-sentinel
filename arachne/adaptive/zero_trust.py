"""
Faz 25 - Sifir Guven Politika Motoru (Zero Trust policy engine).

--- Ko-evrim fikri ---
Klasik cevre (perimeter) savunmasi "ic ag guvenli" varsayar: bir kez iceri
giren saldirgan yatayca (lateral) serbestce dolasir. Saldirgan tam olarak
bunu OGRENIR - bir ucu ele gecirip iceride gezinir. Sifir Guven bu varsayimi
yikar: "asla guvenme, her zaman dogrula" (never trust, always verify). Her
erisim istegi, OTURUM basina, bir Politika Karar Noktasi (PDP) tarafindan
sinyallere gore yeniden degerlendirilir; mikrosegmentasyon yatay hareketi
keser. Bizim yuzeyimize uyarlanmis hali: saldirganin HER eylemi bir istek
basina politika degerlendirmesidir - izin verilir, meydan okunur (challenge)
ya da bir decoy'a yonlendirilir; suphe arttikca guven butcesi daralir.

--- Model (NIST SP 800-207) ---
  * PDP (Policy Decision Point) = PolicyEngine.decide: sinyallerden bir guven
    skoru hesaplar ve karar verir.
  * PEP (Policy Enforcement Point) = 'enforcement' alani: kararin nasil
    uygulanacagi (izin ver / challenge / reddet / decoy'a yonlendir).
  * Mikrosegmentasyon = Segmentation: segmentler arasi gecis, hedef segmentin
    hassasiyetine ve guven skoruna baglidir; bagli olmayan segmentler her zaman
    reddedilir (yatay hareket engellenir).

--- DURUSTLUK NOTU ---
Bu, NIST SP 800-207'nin CEKIRDEK mantigini (PE/PA/PEP dongusu, 7 ilke,
per-request degerlendirme, mikrosegmentasyon) kucuk ve deterministik gosterir;
tam bir kurumsal ZTA urunu (Zscaler, Illumio, Morphisec) DEGILDIR. Guven skoru
belgelenmis agirliklarla basit bir dogrusal birlestirmedir - kalibre edilmis
bir risk motoru degildir. Esikler (>=0.7 allow, 0.4-0.7 challenge, <0.4 deny)
ayarlanabilir varsayilanlardir. Cikti aciklanabilir Turkce `reasons` ile gelir.

--- Gercek cerceve eslemesi ---
NIST SP 800-207 (Zero Trust Architecture; PDP/PEP, 7 tenet), mikrosegmentasyon
(Illumio/Guardicore), BeyondCorp, Morphisec/Zero-Trust, MITRE D3FEND erisim
politikalari.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Yalnizca KENDI izleme yuzeyimizdeki erisim isteklerini
degerlendirir; hicbir baska sisteme dokunmaz, hack-back yoktur. "Reddet" ya da
"decoy'a yonlendir" kendi yuzeyimizde kalir.

Harici bagimlilik yok - sadece stdlib.
"""
from dataclasses import dataclass, field


# --- Guven skoru esikleri (belgeli varsayilanlar) ---
_ALLOW_THRESHOLD = 0.7       # >= : izin
_DENY_THRESHOLD = 0.4        # <  : reddet ; arasi: challenge


# --- Sinyal agirliklari (trust_from_signals) ---
# Taban 0.5'ten baslar; her sinyal skoru asagi/yukari iter. Tehdit istihbarati
# ve onceki alarmlar GUCLU dusuruculerdir (Sifir Guven'de suphe agir basar).
_W_IDENTITY_KNOWN = 0.20     # bilinen/dogrulanmis kimlik (+)
_W_DEVICE_POSTURE = 0.15     # cihaz durusu 0..1 (yamali, uyumlu) (+)
_W_BEHAVIOR = 0.15           # davranis gecmisi 0..1 (normal) (+)
_W_PRIOR_ALERTS = 0.12       # onceki alarm basina (-)
_W_THREAT_INTEL = 0.45       # tehdit istihbarati eslesmesi (sert -)
_W_SENSITIVITY = 0.20        # kaynak hassasiyeti 0..1 (-)


def trust_from_signals(signals: dict) -> float:
    """Sinyallerden 0..1 arasi bir guven skoru hesaplar (belgeli agirliklar).

    Taban 0.5. Toplanan katkilar:
      + identity_known (bool)      -> +0.20  (dogrulanmis kimlik guveni artirir)
      + device_posture (0..1)      -> +0.15 * posture (yamali/uyumlu cihaz)
      + behavioral_history (0..1)  -> +0.15 * history (gecmis normal davranis)
      - prior_alerts (int)         -> -0.12 * alert (her onceki alarm suphe)
      - threat_intel_hit (bool)    -> -0.45  (bilinen kotu -> sert dusus)
      - sensitivity (0..1)         -> -0.20 * sensitivity (hassas kaynak daha
                                       yuksek guven ister -> taban dususu)

    Sonuc 0..1 arasina kirpilir. Eksik anahtarlar notr (0/False) sayilir.
    """
    score = 0.5
    if signals.get("identity_known"):
        score += _W_IDENTITY_KNOWN
    score += _W_DEVICE_POSTURE * float(signals.get("device_posture", 0.0) or 0.0)
    score += _W_BEHAVIOR * float(signals.get("behavioral_history", 0.0) or 0.0)
    score -= _W_PRIOR_ALERTS * int(signals.get("prior_alerts", 0) or 0)
    if signals.get("threat_intel_hit"):
        score -= _W_THREAT_INTEL
    score -= _W_SENSITIVITY * float(signals.get("sensitivity", 0.0) or 0.0)
    return max(0.0, min(1.0, score))


class PolicyEngine:
    """Politika Karar Noktasi (PDP) - istek basina Sifir Guven degerlendirmesi.

    Her `decide` cagrisi tek bir erisim istegini (subject, resource, context)
    sinyallere donusturur, bir guven skoru hesaplar ve karar + PEP uygulamasi
    dondurur. Durum tutmaz (stateless) - her istek bagimsiz dogrulanir, bu
    Sifir Guven'in 'her zaman dogrula' ilkesidir.
    """

    def __init__(self, base_trust=0.5):
        # base_trust yalnizca referans/dokumantasyon amaclidir; skor
        # trust_from_signals icindeki 0.5 tabanindan turer.
        self.base_trust = base_trust

    def _collect_signals(self, subject: dict, resource: dict,
                         context: dict) -> dict:
        """Uc girdiyi tek bir sinyal sozlugune indirir."""
        return {
            "identity_known": bool(subject.get("identity_known")),
            "device_posture": subject.get("device_posture", 0.0),
            "behavioral_history": subject.get("behavioral_history", 0.0),
            "prior_alerts": subject.get("prior_alerts", 0),
            "threat_intel_hit": bool(context.get("threat_intel_hit")),
            "sensitivity": resource.get("sensitivity", 0.0),
        }

    def decide(self, subject: dict, resource: dict, context: dict = None) -> dict:
        """Bir erisim istegini degerlendirir (PDP karari).

        Doner: {decision, trust_score, reasons (Turkce), enforcement}.
        decision: 'allow' (>=0.7) | 'challenge' (0.4-0.7) | 'deny' (<0.4).
        """
        context = context or {}
        signals = self._collect_signals(subject, resource, context)
        score = trust_from_signals(signals)
        reasons = []

        if signals["identity_known"]:
            reasons.append("Kimlik dogrulanmis (+guven)")
        else:
            reasons.append("Kimlik bilinmiyor/dogrulanmamis (notr taban)")
        if signals["threat_intel_hit"]:
            reasons.append("Tehdit istihbarati eslesmesi: bilinen kotu (sert -guven)")
        if signals["prior_alerts"]:
            reasons.append(
                f"{signals['prior_alerts']} onceki alarm (birikmis suphe, -guven)")
        if float(signals["sensitivity"] or 0) >= 0.7:
            reasons.append("Yuksek hassasiyetli kaynak: daha yuksek guven esigi ister")
        if float(signals["device_posture"] or 0) >= 0.7:
            reasons.append("Iyi cihaz durusu (yamali/uyumlu, +guven)")

        if score >= _ALLOW_THRESHOLD:
            decision = "allow"
            enforcement = "Erisime izin ver; oturumu izlemeye devam et"
            reasons.append(
                f"Guven {score:.2f} >= {_ALLOW_THRESHOLD} -> izin")
        elif score >= _DENY_THRESHOLD:
            decision = "challenge"
            enforcement = (
                "Ek dogrulama iste (MFA/adim-yukseltme) veya decoy'a yonlendir; "
                "guven butcesini dar tut")
            reasons.append(
                f"Guven {score:.2f}, {_DENY_THRESHOLD}-{_ALLOW_THRESHOLD} "
                f"araliginda -> challenge")
        else:
            decision = "deny"
            enforcement = (
                "Erisimi reddet; PEP baglantiyi kes veya decoy segmentine "
                "yonlendir")
            reasons.append(
                f"Guven {score:.2f} < {_DENY_THRESHOLD} -> reddet")

        return {
            "decision": decision,
            "trust_score": round(score, 3),
            "reasons": reasons,
            "enforcement": enforcement,
        }


@dataclass
class _Segment:
    """Bir mikrosegment: adi ve hassasiyeti (0..1)."""
    name: str
    sensitivity: float
    neighbors: set = field(default_factory=set)


class Segmentation:
    """Mikrosegmentasyon grafi - yatay hareket (lateral movement) kontrolu.

    Segmentler arasi gecis iki kosula baglidir:
      1. Segmentler BAGLI olmali (connect edilmis). Bagli olmayan segmentler
         arasi gecis HER ZAMAN reddedilir - yatay hareket boylece engellenir.
      2. Hedef segmentin hassasiyeti ne kadar yuksekse, gecis icin gereken
         guven skoru o kadar yuksektir (required = 0.4 + 0.5 * sensitivity).
    """

    def __init__(self):
        self._segments = {}  # name -> _Segment

    def add_segment(self, name: str, sensitivity: float) -> dict:
        """Bir segment ekler (hassasiyet 0..1'e kirpilir)."""
        s = max(0.0, min(1.0, float(sensitivity)))
        self._segments[name] = _Segment(name=name, sensitivity=s)
        return {"name": name, "sensitivity": s}

    def connect(self, a: str, b: str) -> None:
        """Iki segmenti (cift yonlu) baglar. Bilinmeyen segmentte hata verir."""
        if a not in self._segments or b not in self._segments:
            raise KeyError("Bilinmeyen segment: baglanti kurulamadi")
        self._segments[a].neighbors.add(b)
        self._segments[b].neighbors.add(a)

    def _required_trust(self, sensitivity: float) -> float:
        """Hedef hassasiyetine gore gerekli guven esigi."""
        return 0.4 + 0.5 * sensitivity

    def can_traverse(self, from_seg: str, to_seg: str,
                     trust_score: float) -> dict:
        """from_seg -> to_seg gecisine bu guven skoruyla izin var mi?"""
        if from_seg not in self._segments or to_seg not in self._segments:
            return {
                "allowed": False,
                "reason": "Bilinmeyen segment - gecis reddedildi",
            }
        if from_seg == to_seg:
            return {
                "allowed": True,
                "reason": "Ayni segment icinde hareket",
            }
        dst = self._segments[to_seg]
        if to_seg not in self._segments[from_seg].neighbors:
            return {
                "allowed": False,
                "reason": (
                    f"'{from_seg}' ile '{to_seg}' arasinda mikrosegment "
                    f"baglantisi yok - yatay hareket engellendi"),
            }
        required = self._required_trust(dst.sensitivity)
        if trust_score >= required:
            return {
                "allowed": True,
                "reason": (
                    f"Guven {trust_score:.2f} >= gerekli {required:.2f} "
                    f"(hedef hassasiyet {dst.sensitivity:.2f}) -> gecise izin"),
            }
        return {
            "allowed": False,
            "reason": (
                f"Guven {trust_score:.2f} < gerekli {required:.2f} "
                f"(hedef hassasiyet {dst.sensitivity:.2f}) -> gecis reddedildi"),
        }

    def posture_report(self) -> dict:
        """Segmentasyon durusunun genel ozeti."""
        segs = self._segments
        total_pairs = len(segs) * (len(segs) - 1) // 2
        connected_pairs = sum(len(s.neighbors) for s in segs.values()) // 2
        return {
            "segment_count": len(segs),
            "segments": [
                {"name": s.name, "sensitivity": s.sensitivity,
                 "neighbors": sorted(s.neighbors)}
                for s in sorted(segs.values(), key=lambda x: x.name)
            ],
            "connected_pairs": connected_pairs,
            "isolated_pairs": max(0, total_pairs - connected_pairs),
            "assessment_tr": (
                f"{len(segs)} segment, {connected_pairs} bagli cift; geri kalan "
                f"tum ciftler varsayilan olarak izole (yatay hareket kapali)."
            ),
        }
