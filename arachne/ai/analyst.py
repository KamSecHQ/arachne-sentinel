"""
Yerel (cevrimdisi) guvenlik analisti - Faz 8'in her zaman calisan cekirdegi.

--- Neden "yerel analist"? ---
Bir dil modeli API'sine bagimli olmak, projeyi kirilgan yapar: internet
yoksa, anahtar yoksa, kota bittiyse "yapay zeka ozelligi" comer. Juri
karsisinda demo yaparken bu kabul edilemez.

Bu yuzden mimari su sekilde: YEREL ANALIST HER ZAMAN CALISIR. Dil modeli
varsa ciktiyi zenginlestirir, yoksa sistem hicbir sey kaybetmez.

--- Bu bir "yapay zeka" mi? ---
Durust cevap: bu bir dil modeli degil, kural ve istatistik tabanli bir
uzman sistemidir (expert system). Ama yaptigi is gercektir: yapisal
verilerden dogal dilde, baglama duyarli, oncelik siralamasi yapilmis bir
olay raporu uretir. 1970'lerden beri yapay zekanin mesru bir dali olan
"knowledge-based system" yaklasimidir.

Projede ML tabanli siniflandirici da var (Faz 2, TF-IDF + Logistic
Regression) - yani "yapay zeka" iddiasi bu dosyaya dayanmiyor. Burada
onemli olan, dil modeli olmadan da anlamli bir analist ciktisi
uretebilmek.
"""
from collections import Counter

from ..intel import attck

# Saldiri sinifi -> AI sema kategorisi eslemesi
_CLASS_TO_CATEGORY = {
    "SQL Injection": "sql-injection",
    "XSS": "xss",
    "Command Injection": "command-injection",
    "Path Traversal": "path-traversal",
    "Brute Force": "brute-force",
    "Port Scan": "port-scan",
    "Directory Brute Force": "directory-brute-force",
    "Web Shell": "web-shell",
    "Reverse Shell": "reverse-shell",
    "Obfuscation": "obfuscation",
    "Service Discovery": "reconnaissance",
}

# Saldiri sinifi -> saldirganin amaci (dogal dil)
_INTENT = {
    "SQL Injection": (
        "Veritabanina dogrudan erisim saglamak: kimlik dogrulamayi atlamak, "
        "kullanici tablosunu okumak ya da veri sizdirmak"
    ),
    "Command Injection": (
        "Sunucu uzerinde isletim sistemi komutu calistirmak - bu, tam sistem "
        "ele gecirmeye giden en kisa yoldur"
    ),
    "XSS": (
        "Baska kullanicilarin tarayicisinda kod calistirmak: oturum cerezi "
        "calmak ya da sahte arayuz gostermek"
    ),
    "Path Traversal": (
        "Web kokunun disina cikip yapilandirma dosyalarini, kimlik bilgilerini "
        "ya da kaynak kodu okumak"
    ),
    "Brute Force": (
        "Zayif bir parolayi deneme-yanilma ile bulup mesru kullanici olarak "
        "sisteme girmek"
    ),
    "Port Scan": (
        "Hangi servislerin calistigini haritalamak - saldirinin hazirlik "
        "asamasi, henuz zarar yok ama niyet net"
    ),
    "Directory Brute Force": (
        "Baglanti verilmemis yonetim panelleri, yedek dosyalari veya .git "
        "dizini gibi gizli varliklari bulmak"
    ),
    "Web Shell": (
        "Sunucuya kalici bir uzaktan kontrol arayuzu yerlestirmek - "
        "saldirinin 'kurulum' asamasi"
    ),
    "Reverse Shell": (
        "Kurbandan saldirgana geri baglanan bir kabuk acmak; guvenlik "
        "duvarinin giden trafige daha musamahakar olmasindan yararlanir"
    ),
    "Obfuscation": (
        "Imza tabanli savunmalari atlatmak icin yuku katman katman kodlamak - "
        "mesru trafik bunu yapmaz"
    ),
    "Service Discovery": (
        "Calisan servisleri ve surumlerini belirleyip bilinen zafiyetlerle "
        "eslestirmek"
    ),
}

# Saldiri sinifi -> analistin neye bakmasi gerektigi
_FOCUS = {
    "SQL Injection": "Uygulamada parametreli sorgu kullanilip kullanilmadigini dogrulayin",
    "Command Injection": "Kullanici girdisinin kabuga gecen tum yollarini acilen gozden gecirin",
    "XSS": "Cikti kacislama (output encoding) ve Content-Security-Policy basligini kontrol edin",
    "Path Traversal": "Dosya yolu birlestirme kodunda kanonikleştirme (canonicalization) var mi bakin",
    "Brute Force": "Hesap kilitleme ve hiz sinirlama politikalarini gozden gecirin",
    "Port Scan": "Disariya acik port envanterini dogrulayin - gereksiz servisleri kapatin",
    "Web Shell": "Yukleme dizinlerinde calistirilabilir dosya var mi kontrol edin",
    "Reverse Shell": "Giden (egress) trafik filtrelemesini gozden gecirin",
    "Obfuscation": "WAF kural setinin kodlama-normalizasyonu yapip yapmadigini dogrulayin",
}


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def analyze_payload_locally(payload: str, analysis: dict, sanitized: dict = None) -> dict:
    """Tek bir yuk icin yerel analist yorumu uretir.

    `analysis` : reverse.attack_analyzer.analyze_payload() ciktisi
    `sanitized`: ai.sanitizer.sanitize_for_ai() ciktisi (enjeksiyon tespiti icin)
    """
    sanitized = sanitized or {}
    classes = analysis.get("attack_classes", [])
    primary = classes[0] if classes else None

    category = _CLASS_TO_CATEGORY.get(primary, "unknown" if classes else "benign")
    score = analysis.get("threat_score", 0)
    severity = _severity_from_score(score)

    # Guven: kac bagimsiz kanit var?
    evidence_count = (
        len(classes)
        + (1 if analysis.get("primary_tool") else 0)
        + (1 if analysis.get("obfuscation_score", 0) > 0 else 0)
        + (1 if analysis.get("ioc_count", 0) > 0 else 0)
    )
    confidence = "high" if evidence_count >= 3 else ("medium" if evidence_count >= 2 else "low")

    summary = _build_payload_summary(analysis, primary)
    intent = _INTENT.get(primary, "Saldirganin amaci mevcut kanitlardan net belirlenemedi")
    technical = _build_technical_note(analysis)
    focus = _FOCUS.get(primary, "Ilgili servis loglarini manuel olarak inceleyin")

    result = {
        "attack_category": category,
        "severity_opinion": severity,
        "confidence": confidence,
        "summary": summary,
        "attacker_intent": intent,
        "technical_note": technical,
        "injection_attempt": bool(sanitized.get("injection_attempt")),
        "recommended_focus": focus,
        "_source": "yerel-analist",
    }
    if sanitized.get("injection_attempt"):
        indicators = sanitized.get("injection_indicators", [])
        descriptions = ", ".join(i["description"] for i in indicators[:3])
        result["injection_note"] = (
            f"Yuk, AI analiz katmanini manipule etmeye yonelik talimat iceriyor "
            f"({descriptions}). Bu, saldirganin sistemin ic mimarisini tahmin "
            f"ettigini gosterir - tehdit seviyesini yukseltir."
        )
    return result


def _build_payload_summary(analysis: dict, primary) -> str:
    parts = []
    if primary:
        mapping = attck.map_attack_class(primary)
        parts.append(f"{primary} girisimi tespit edildi ({mapping['description_tr']}).")
    else:
        parts.append("Bilinen bir saldiri imzasi eslesmedi.")

    deob = analysis.get("deobfuscation", {})
    if deob.get("was_obfuscated"):
        parts.append(
            f"Yuk {deob['layers']} katman kodlama ile gizlenmisti "
            f"({deob['method_chain']}); cozuldukten sonra icerik ortaya cikti."
        )

    hidden = analysis.get("hidden_attack_classes", [])
    if hidden:
        parts.append(
            f"Onemli: {', '.join(hidden)} imzasi SADECE kodlama cozuldukten "
            f"sonra gorunur hale geldi - klasik WAF atlatma tekniği."
        )

    tool = analysis.get("primary_tool")
    if tool:
        parts.append(f"Trafik {tool} aracinin parmak izini tasiyor.")

    iocs = analysis.get("iocs", {})
    if iocs.get("reverse_shells"):
        parts.append("KRITIK: Yuk icinde ters kabuk (reverse shell) kalibi bulundu.")
    elif iocs.get("shell_commands"):
        cmds = ", ".join(iocs["shell_commands"][:3])
        parts.append(f"Kabuk komutlari tespit edildi: {cmds}.")

    kc = analysis.get("kill_chain", {})
    if kc:
        parts.append(
            f"Saldirgan kill chain'in '{kc.get('phase_tr', '?')}' asamasinda "
            f"(%{kc.get('progress_pct', 0)} ilerleme)."
        )
    return " ".join(parts)[:400]


def _build_technical_note(analysis: dict) -> str:
    bits = []
    techniques = analysis.get("attck_techniques", [])
    if techniques:
        ids = ", ".join(f"{t['id']} ({t['name']})" for t in techniques[:3])
        bits.append(f"MITRE ATT&CK: {ids}.")
    mappings = analysis.get("framework_mappings", [])
    cwes = sorted({c for m in mappings for c in m.get("cwe", [])})
    if cwes:
        bits.append(f"Ilgili zafiyet siniflari: {', '.join(cwes)}.")
    if analysis.get("obfuscation_score"):
        bits.append(f"Gizleme skoru: {analysis['obfuscation_score']}/100.")
    return " ".join(bits)[:400] or "Ek teknik detay yok."


def analyze_ip_locally(ip_analysis: dict, profile: dict = None) -> dict:
    """Bir saldirganin TUM etkinligi icin yerel analist degerlendirmesi."""
    profile = profile or {}
    classes = ip_analysis.get("attack_classes", [])
    primary = classes[0] if classes else None
    score = ip_analysis.get("max_threat_score", 0)

    summary_parts = [
        f"{ip_analysis.get('source_ip', 'bilinmeyen IP')} adresinden "
        f"{ip_analysis.get('event_count', 0)} olay kaydedildi."
    ]

    if classes:
        summary_parts.append(f"Tespit edilen saldiri turleri: {', '.join(classes)}.")
    services = ip_analysis.get("services_touched", [])
    if len(services) > 1:
        summary_parts.append(
            f"{len(services)} farkli servise dokundu ({', '.join(services)}) - "
            f"bu, rastgele degil sistematik bir kesif gostergesidir."
        )

    timing = profile.get("timing", {})
    if timing.get("assessment_tr"):
        summary_parts.append(timing["assessment_tr"] + ".")

    tool = ip_analysis.get("primary_tool")
    if tool:
        summary_parts.append(f"Birincil arac: {tool}.")

    threat_class = profile.get("threat_class")
    if threat_class:
        summary_parts.append(
            f"Tehdit sinifi: {threat_class} - {profile.get('threat_class_reason', '')}"
        )

    kc = ip_analysis.get("kill_chain", {})

    return {
        "attack_category": _CLASS_TO_CATEGORY.get(primary, "reconnaissance"),
        "severity_opinion": _severity_from_score(score),
        "confidence": "high" if len(classes) >= 2 else "medium",
        "summary": " ".join(summary_parts)[:400],
        "attacker_intent": _INTENT.get(primary, "Kesif ve zafiyet arama"),
        "technical_note": (
            f"Kill chain: {kc.get('phase_tr', '?')} "
            f"({kc.get('stage_index', 0)}/{kc.get('total_stages', 7)} asama). "
            f"IOC sayisi: {ip_analysis.get('ioc_count', 0)}."
        )[:400],
        "injection_attempt": False,
        "recommended_focus": _FOCUS.get(primary, "Bu IP'nin gecmis etkinligini inceleyin"),
        "_source": "yerel-analist",
    }


def build_situation_report(stats: dict, profiles: list, campaigns: list,
                           recent_alerts: list, mtd_stats: dict = None,
                           soar_stats: dict = None) -> dict:
    """Tum sistemin durumu icin yonetici ozeti (situation report / SITREP).

    Bu, "yapay zekaya sistemin durumunu sor" istegine verilen cevaptir:
    tum katmanlardan (honeypot, WAF, tarama, MTD, SOAR, istihbarat) veri
    toplar ve oncelik siralamasi yapilmis, dogal dilde bir rapor uretir."""
    mtd_stats = mtd_stats or {}
    soar_stats = soar_stats or {}

    total_events = stats.get("total_events", 0)
    total_alerts = stats.get("total_alerts", 0)
    by_severity = stats.get("by_severity", {})
    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)

    # --- Genel tehdit duzeyi ---
    if critical >= 5:
        posture, posture_reason = "KRITIK", (
            f"{critical} kritik seviyeli alarm - aktif ve ciddi bir saldiri altindasiniz"
        )
    elif critical >= 1:
        posture, posture_reason = "YUKSEK", (
            f"{critical} kritik alarm tespit edildi - acil inceleme gerekiyor"
        )
    elif high >= 3:
        posture, posture_reason = "ORTA-YUKSEK", (
            f"{high} yuksek siddetli alarm - saldirgan ilgisi belirgin"
        )
    elif total_alerts > 0:
        posture, posture_reason = "ORTA", (
            f"{total_alerts} alarm var ama hicbiri kritik seviyede degil"
        )
    else:
        posture, posture_reason = "SAKIN", "Alarm uretilmedi - sistem gozlem modunda"

    # --- Bulgular (onceliklendirilmis) ---
    findings = []

    if campaigns:
        biggest = campaigns[0]
        findings.append({
            "priority": 1,
            "title": "Korele saldiri kampanyasi tespit edildi",
            "detail": (
                f"{biggest['member_count']} farkli IP ayni davranissal parmak izini "
                f"paylasiyor ({', '.join(biggest['member_ips'][:4])}"
                f"{'...' if biggest['member_count'] > 4 else ''}). "
                f"Bu, tek bir saldirganin birden fazla adres kullandigini gosterir - "
                f"IP bazli engelleme tek basina yetersiz kalir."
            ),
        })

    targeted = [p for p in profiles if p.get("threat_class") == "hedefli-saldirgan"]
    if targeted:
        ips = ", ".join(p["source_ip"] for p in targeted[:3])
        findings.append({
            "priority": 1,
            "title": "Hedefli saldirgan davranisi",
            "detail": (
                f"{len(targeted)} kaynak ({ips}) firsatci tarama degil, sistematik "
                f"kesif yapiyor: coklu servis + yuksek skor + surekli etkinlik. "
                f"Bu profil, otomatik botlardan farkli olarak insan yonlendirmeli "
                f"bir saldiriya isaret eder."
            ),
        })

    automated = [p for p in profiles if p.get("threat_class") == "otomatik-tarayici"]
    if automated:
        findings.append({
            "priority": 3,
            "title": "Otomatik tarama trafigi",
            "detail": (
                f"{len(automated)} kaynak makine ritminde tarama yapiyor. Bu tur "
                f"trafik internete acik her sistemde sureklidir; hedefli degildir "
                f"ama hacim olusturarak gercek saldiriyi maskeleyebilir."
            ),
        })

    tool_counter = Counter()
    for p in profiles:
        if p.get("primary_tool"):
            tool_counter[p["primary_tool"]] += 1
    if tool_counter:
        tools_txt = ", ".join(f"{t} ({n} kaynak)" for t, n in tool_counter.most_common(3))
        findings.append({
            "priority": 2,
            "title": "Bilinen saldiri araclari kullaniliyor",
            "detail": (
                f"{tools_txt}. Hazir arac kullanimi, saldirganin genellikle bilinen "
                f"zafiyetleri aradigini gosterir - yamalar guncelse risk sinirlidir."
            ),
        })

    if mtd_stats.get("total_rotations"):
        findings.append({
            "priority": 4,
            "title": "Moving Target Defense aktif",
            "detail": (
                f"{mtd_stats['total_rotations']} kimlik rotasyonu gerceklestirildi. "
                f"Saldirganin onceki taramalarinda topladigi port/banner bilgisi "
                f"artik gecersiz."
            ),
        })

    if soar_stats.get("total_actions"):
        findings.append({
            "priority": 2,
            "title": "Otonom mudahale calisti",
            "detail": (
                f"{soar_stats['total_actions']} otomatik eylem uygulandi, "
                f"{soar_stats.get('active_blocks', 0)} IP su an engelli. "
                f"{soar_stats.get('awaiting_approval', 0)} eylem analist onayi bekliyor."
            ),
        })

    findings.sort(key=lambda f: f["priority"])

    # --- Oneriler ---
    recommendations = []
    if critical:
        recommendations.append(
            "Kritik alarmlari tek tek inceleyin: hangi servise, hangi yuk ile "
            "saldirildigini 'Son Alarmlar' tablosundan dogrulayin."
        )
    if campaigns:
        recommendations.append(
            "Kampanya tespit edildigi icin IP bazli degil DAVRANIS bazli engelleme "
            "dusunun - saldirgan adres degistirdiginde kural hala calisir."
        )
    if targeted:
        recommendations.append(
            "Hedefli saldirgan profilleri icin honeypot disindaki gercek servislerin "
            "log kayitlarini da kontrol edin; ayni kaynak oralara da dokunmus olabilir."
        )
    if not recommendations:
        recommendations.append(
            "Acil bir aksiyon gerekmiyor. Sistem calisir durumda ve gozlem yapiyor."
        )

    return {
        "posture": posture,
        "posture_reason": posture_reason,
        "headline": (
            f"{total_events} olay, {total_alerts} alarm; tehdit duzeyi: {posture}"
        ),
        "findings": findings,
        "recommendations": recommendations,
        "stats_snapshot": {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical,
            "high_alerts": high,
            "unique_attackers": len(profiles),
            "campaigns": len(campaigns),
            "mtd_rotations": mtd_stats.get("total_rotations", 0),
            "soar_actions": soar_stats.get("total_actions", 0),
        },
        "_source": "yerel-analist",
    }
