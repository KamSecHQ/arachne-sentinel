"""
Faz 24 - Topluluk Tespit Motoru (Ensemble / Savunma-Derinligi Oylamasi).

--- Adaptif savunma fikri ---
Adapte olan bir saldirgan, TEK bir tespit kuralini tersine muhendislikle
cozup atlatabilir (orn. flood esigini ogrenip altinda kalir). Cozum yapisal:
BIRDEN COK bagimsiz dedektoru birlestir; birini atlatmak sistemi atlatmaz.
Dedektorler farkli fiziksel prensiplere dayandigi icin (hiz, istatistiksel
kayma, parmak-izi, aldatma-temasi, imza) hepsini ayni anda atlatmak cok daha
zordur. Ozellikle "aldatma-temasi" dedektoru yanlis-pozitifi ~sifir ve
digerlerinden BAGIMSIZDIR: istatistiksel dedektorleri atlatan sinsi bir
saldirgan bile bir tuzaga dokununca yakalanir.

--- Nasil birlestirir ---
1) Agirlikli skor: threat = Sigma(w_i * score_i); esik asilinca alarm.
2) k-of-N oylama: en az k bagimsiz dedektor ayni anda tetiklenmeli.
3) Dinamik agirlik: aktif tehdit sinifina gore bir dedektorun agirligi
   yukseltilebilir (Faz 26 durusu buna baglanir).

--- DURUSTLUK ---
Bu bir "meta-dedektor"dur; kendi basina ham sinyal uretmez, alt dedektorlerin
(Faz 15/21/22/23 + imza) verdigi skorlari birlestirir. Katkisi, tek nokta
atlatmasini yapisal olarak zorlastirmaktir - sihirli bir tespit degil,
dogru bir BIRLESTIRME mantigidir. Kurumsal literaturdeki weighted-voting
ensemble IDS yaklasiminin kucuk, aciklanabilir bir uygulamasidir.

--- ETIK ---
Tamamen savunma. Hicbir eylem baska sisteme dokunmaz.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Alt dedektorlerin varsayilan agirliklari. "deception" (aldatma-temasi)
# kasitli olarak en yuksek: yanlis-pozitifi ~sifir oldugu icin tek basina
# bile guclu bir kanittir.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "signature": 1.0,     # WAF/kural imza eslesmesi (Faz 2/14)
    "flood": 0.9,         # hiz/hacim anomalisi (Faz 15)
    "slow_burn": 1.0,     # dusuk-ve-yavas kayma (Faz 21)
    "fingerprint": 0.8,   # kimlik rotasyonu / Sybil (Faz 22)
    "deception": 1.6,     # aldatma yuzeyi/honeytoken temasi (Faz 12/23)
    "risk": 0.7,          # cok-faktorlu risk skoru (Faz 18)
}

# Bu dedektorler "bagimsiz kanit" sayilir; k-of-N oylamasi bunlar uzerinden
# yapilir (ayni prensibe dayanan iki sinyal cift sayilmasin diye).
INDEPENDENT_DETECTORS = ("signature", "flood", "slow_burn", "fingerprint", "deception")


@dataclass
class DetectorSignal:
    """Tek bir alt dedektorun ciktisi.

    score: 0..1 arasi normalize edilmis guven (1 = kesin kotu).
    fired: dedektor esigini asip 'tetiklendi' mi.
    """
    name: str
    score: float
    fired: bool
    detail: str = ""


@dataclass
class EnsembleResult:
    source_ip: str
    threat: float
    alert: bool
    votes: int
    voters: List[str]
    weighted_breakdown: Dict[str, float]
    reason: str
    severity: str


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


class EnsembleDetector:
    """Birden cok bagimsiz dedektoru agirlikli skor + k-of-N oylama ile
    birlestiren meta-dedektor."""

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        alert_threshold: float = 1.5,
        min_votes: int = 2,
    ):
        # Kopyalayarak sakla - disaridan degistirilirse bizimki bozulmasin.
        self.weights: Dict[str, float] = dict(weights or DEFAULT_WEIGHTS)
        self.alert_threshold = alert_threshold
        self.min_votes = min_votes
        # Faz 26 durusu buraya gecici agirlik carpani enjekte edebilir.
        self._dynamic_multipliers: Dict[str, float] = {}

    def set_dynamic_weight(self, detector: str, multiplier: float) -> None:
        """Faz 26 (adaptif durus) aktif tehdit sinifina gore bir dedektorun
        agirligini gecici olarak yukseltir/dusurur."""
        self._dynamic_multipliers[detector] = multiplier

    def clear_dynamic_weights(self) -> None:
        self._dynamic_multipliers = {}

    def combine(self, source_ip: str, signals: List[DetectorSignal]) -> EnsembleResult:
        """Alt dedektor sinyallerini tek bir karara birlestirir."""
        weighted: Dict[str, float] = {}
        threat = 0.0
        voters: List[str] = []

        for sig in signals:
            base_w = self.weights.get(sig.name, 0.5)
            mult = self._dynamic_multipliers.get(sig.name, 1.0)
            contribution = _clamp01(sig.score) * base_w * mult
            weighted[sig.name] = round(contribution, 4)
            threat += contribution
            # k-of-N oylamasi yalnizca bagimsiz dedektorlerin "fired" sinyalini sayar
            if sig.fired and sig.name in INDEPENDENT_DETECTORS:
                voters.append(sig.name)

        votes = len(set(voters))
        threat = round(threat, 4)

        # Aldatma-temasi tek basina yeter: yanlis-pozitif ~sifir bir kanittir.
        deception_hit = any(
            s.name == "deception" and s.fired for s in signals
        )

        alert = (threat >= self.alert_threshold and votes >= self.min_votes) or deception_hit

        # Aciklanabilir gerekce
        if deception_hit and not (threat >= self.alert_threshold and votes >= self.min_votes):
            reason = (
                "Alarm: aldatma yuzeyi/honeytoken temasi tespit edildi - tek "
                "basina yeterli kanit (yanlis-pozitif ~sifir), diger dedektorler "
                "esigi asmasa bile."
            )
        elif alert:
            reason = (
                f"Alarm: {votes} bagimsiz dedektor ayni anda tetiklendi "
                f"({', '.join(sorted(set(voters)))}); birlesik tehdit skoru "
                f"{threat:.2f} >= {self.alert_threshold}. Tek bir kurali "
                f"atlatmak sistemi atlatmaya yetmez."
            )
        else:
            reason = (
                f"Alarm yok: birlesik skor {threat:.2f} (esik {self.alert_threshold}), "
                f"{votes} bagimsiz oy (gerekli {self.min_votes}). Sinyaller "
                f"tek basina yeterli kanit olusturmuyor."
            )

        severity = self._severity(threat, votes, deception_hit)
        return EnsembleResult(
            source_ip=source_ip,
            threat=threat,
            alert=alert,
            votes=votes,
            voters=sorted(set(voters)),
            weighted_breakdown=weighted,
            reason=reason,
            severity=severity,
        )

    @staticmethod
    def _severity(threat: float, votes: int, deception_hit: bool) -> str:
        if deception_hit or (threat >= 3.0 and votes >= 3):
            return "kritik"
        if threat >= 2.0 and votes >= 2:
            return "yuksek"
        if threat >= 1.0:
            return "orta"
        return "dusuk"


def signals_from_analysis(analysis: dict) -> List[DetectorSignal]:
    """Mevcut analiz sozlugunden (Faz 5/15/18/... ciktilari) ensemble sinyalleri
    uretmek icin kolaylik donusturucusu. Eksik alanlar sessizce atlanir - boylece
    farkli cagri yollarindan gelen kismi veriyle de calisir."""
    signals: List[DetectorSignal] = []

    def add(name, score, fired, detail=""):
        signals.append(DetectorSignal(name=name, score=float(score),
                                      fired=bool(fired), detail=detail))

    if "signature_score" in analysis:
        s = _clamp01(analysis["signature_score"])
        add("signature", s, s >= 0.5, "imza eslesmesi")
    if "flood" in analysis:
        f = analysis["flood"]
        add("flood", 1.0 if f.get("flood") else min(1.0, f.get("zscore", 0) / 3.0),
            bool(f.get("flood")), f.get("reason", ""))
    if "slow_burn" in analysis:
        sb = analysis["slow_burn"]
        add("slow_burn", 1.0 if sb.get("slow_burn") else _clamp01(sb.get("regularity", 0)),
            bool(sb.get("slow_burn")), sb.get("reason", ""))
    if "sybil" in analysis:
        sy = analysis["sybil"]
        add("fingerprint", 1.0 if sy.get("is_sybil") else 0.3,
            bool(sy.get("is_sybil")), sy.get("verdict", ""))
    if "deception" in analysis:
        de = analysis["deception"]
        add("deception", 1.0 if de.get("is_breach") else 0.0,
            bool(de.get("is_breach")), de.get("verdict", ""))
    if "risk_score" in analysis:
        add("risk", _clamp01(analysis["risk_score"] / 100.0),
            analysis["risk_score"] >= 60, "risk skoru")

    return signals
