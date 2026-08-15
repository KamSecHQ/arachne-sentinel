"""
Faz 18 - Cok faktorlu risk skorlama ve tehdit derecelendirme.

Faz 1'in skoru "kac kural tetiklendi" idi - iyi ama tek boyutlu. Bu motor,
gercek risk degerlendirme cercevelerinin (CVSS, DREAD, kurumsal risk
matrisleri) mantigini takip ederek COK FAKTORLU, agirlikli ve
ACIKLANABILIR bir risk skoru uretir.

--- Risk = Olasilik x Etki ---
Klasik risk formulu. Biz bunu iki eksende hesaplariz:

  OLASILIK (likelihood): saldirinin basarili olma / devam etme olasiligi
    - saldirgan otomatik mi, hedefli mi?
    - kill chain'de ne kadar ilerledi?
    - tekrarlayan saldirgan mi?
    - kampanyanin parcasi mi?

  ETKI (impact): basarili olursa ne kaybederiz?
    - saldiri sinifi (RCE > SQLi > tarama)
    - ters kabuk / web shell var mi?
    - hedeflenen servis kritikligi

Her faktorun katkisi AYRI AYRI gosterilir - "risk 82 cunku: hedefli
saldirgan (+25), RCE denemesi (+30), kill chain %57 (+15)..." Bu, bir
juri/yonetici icin ham bir sayidan cok daha anlamlidir.

--- CVSS benzerligi ---
CVSS'in temel vektor mantigini (Attack Vector, Complexity, Impact
metrikleri) kucuk olcekte taklit eder ama CVSS DEGILDIR ve oyle iddia
etmez - CVSS zafiyetleri puanlar, biz saldirgan davranisini puanliyoruz.
"""

# Saldiri sinifi -> etki agirligi (0-100)
_IMPACT_WEIGHTS = {
    "Command Injection": 95,
    "Reverse Shell": 95,
    "Web Shell": 90,
    "SQL Injection": 75,
    "Path Traversal": 65,
    "XSS": 55,
    "Directory Brute Force": 40,
    "Brute Force": 45,
    "Service Discovery": 25,
    "Port Scan": 20,
    "Obfuscation": 30,
    "Reconnaissance": 20,
}

# Kill chain asamasi -> olasilik carpani. Ilerledikce risk artar.
_KILLCHAIN_MULTIPLIER = {
    "reconnaissance": 0.5,
    "weaponization": 0.6,
    "delivery": 0.7,
    "exploitation": 0.9,
    "installation": 1.0,
    "command-and-control": 1.0,
    "actions-on-objectives": 1.0,
}

RISK_BANDS = [
    (85, "kritik", "Acil mudahale gerekiyor - aktif ve yuksek etkili tehdit"),
    (65, "yuksek", "Oncelikli inceleme - ciddi saldirgan ilgisi"),
    (40, "orta", "Izlenmeli - suphesi olay"),
    (15, "dusuk", "Dusuk oncelik - rutin gurultu olabilir"),
    (0, "asgari", "Onemsiz - muhtemelen zararsiz"),
]


def _band(score: int) -> tuple:
    for threshold, label, desc in RISK_BANDS:
        if score >= threshold:
            return label, desc
    return "asgari", RISK_BANDS[-1][2]


def compute_risk(*, attack_classes=None, kill_chain_phase="reconnaissance",
                 automated=False, repeat_offender=False, in_campaign=False,
                 has_reverse_shell=False, obfuscation_layers=0,
                 tool_confidence=0, event_count=0, entropy=0.0) -> dict:
    """Cok faktorlu risk skoru hesaplar; her faktorun katkisini gosterir."""
    attack_classes = attack_classes or []
    factors = []

    # --- ETKI ekseni ---
    max_impact = max((_IMPACT_WEIGHTS.get(c, 15) for c in attack_classes), default=10)
    impact = max_impact
    if attack_classes:
        top_class = max(attack_classes, key=lambda c: _IMPACT_WEIGHTS.get(c, 0))
        factors.append({"factor": f"En yuksek etkili saldiri: {top_class}",
                        "contribution": max_impact, "axis": "etki"})
    if has_reverse_shell:
        impact = min(100, impact + 10)
        factors.append({"factor": "Ters kabuk kalibi tespit edildi",
                        "contribution": 10, "axis": "etki"})

    # --- OLASILIK ekseni ---
    likelihood = 30  # taban
    kc_mult = _KILLCHAIN_MULTIPLIER.get(kill_chain_phase, 0.5)
    kc_bonus = int((kc_mult - 0.5) * 60)  # 0.5 -> 0, 1.0 -> 30
    if kc_bonus:
        likelihood += kc_bonus
        factors.append({"factor": f"Kill chain asamasi: {kill_chain_phase}",
                        "contribution": kc_bonus, "axis": "olasilik"})

    if repeat_offender:
        likelihood += 15
        factors.append({"factor": "Tekrarlayan saldirgan",
                        "contribution": 15, "axis": "olasilik"})
    if in_campaign:
        likelihood += 12
        factors.append({"factor": "Korele kampanyanin parcasi",
                        "contribution": 12, "axis": "olasilik"})
    if tool_confidence >= 80:
        likelihood += 10
        factors.append({"factor": "Yuksek guvenli arac tespiti",
                        "contribution": 10, "axis": "olasilik"})

    # Hedefli mi otomatik mi? Hedefli saldirgan daha yuksek olasilik.
    if not automated and attack_classes:
        likelihood += 10
        factors.append({"factor": "Elle hazirlanmis (otomatik degil) saldiri",
                        "contribution": 10, "axis": "olasilik"})

    if obfuscation_layers >= 2:
        likelihood += 8
        factors.append({"factor": f"{obfuscation_layers} katman gizleme (kararlilik)",
                        "contribution": 8, "axis": "olasilik"})
    if entropy >= 6.5:
        likelihood += 5
        factors.append({"factor": "Cok yuksek entropi (sikistirilmis/sifreli)",
                        "contribution": 5, "axis": "olasilik"})

    impact = max(0, min(100, impact))
    likelihood = max(0, min(100, likelihood))

    # Risk = olasilik x etki (0-1 x 0-100 -> 0-100), hafif dogrusal olmayan
    risk = (likelihood / 100.0) * impact
    # Cok yuksek her iki eksende risk ustel yaklassin
    if likelihood >= 70 and impact >= 70:
        risk = min(100, risk * 1.15)
    risk = int(round(max(0, min(100, risk))))

    label, desc = _band(risk)

    return {
        "risk_score": risk,
        "risk_band": label,
        "risk_description_tr": desc,
        "impact_score": impact,
        "likelihood_score": likelihood,
        "factors": factors,
        "vector_tr": (
            f"Risk {risk}/100 ({label}) = Etki {impact} x Olasilik {likelihood}%. "
            f"Baslica etkenler: " +
            "; ".join(f"{f['factor']} (+{f['contribution']})" for f in factors[:4])
        ),
    }


def risk_from_analysis(analysis: dict, *, repeat_offender=False,
                       in_campaign=False) -> dict:
    """reverse.attack_analyzer ciktisindan dogrudan risk hesaplar."""
    iocs = analysis.get("iocs", {})
    return compute_risk(
        attack_classes=analysis.get("attack_classes", []),
        kill_chain_phase=analysis.get("kill_chain", {}).get("phase", "reconnaissance"),
        automated=analysis.get("automated", False),
        repeat_offender=repeat_offender,
        in_campaign=in_campaign,
        has_reverse_shell=bool(iocs.get("reverse_shells")),
        obfuscation_layers=analysis.get("deobfuscation", {}).get("layers", 0),
        tool_confidence=(analysis.get("tools") or [{}])[0].get("confidence", 0)
        if analysis.get("tools") else 0,
        event_count=analysis.get("event_count", 0),
        entropy=analysis.get("entropy", 0.0),
    )
