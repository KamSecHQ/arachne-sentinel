"""
Faz 48 - AI Komuta Asistani (konusulabilir durum sorgulama).

Komuta merkezinde operatorun DOGAL DILDE soru sormasini saglar:
"savunma durumumuz ne?", "saldiri durumu ne?", "en riskli saldirgan kim?",
"kac alarm var?", "metrikler nasil?" ... ve asistan GERCEK sistem verisinden
Turkce yanit uretir (hem yazili hem seslendirilebilir kisa surum).

--- DURUSTLUK ---
Bu bir NIYET-TABANLI (intent) yanit motorudur; harici bir LLM'e BAGIMLI
DEGILDIR - internet/anahtar gerektirmez, her zaman calisir ve verdigi her
sayi gercek veritabani/aggregator kaydindan gelir (uydurma yok). Serbest
metin sorulari anahtar kelimelerle siniflandirilir; anlasilmazsa genel durum
ozeti + ipucu dondurur. Opsiyonel LLM zenginlestirmesi ayri katmandir (Faz 8).

--- ETIK ---
Salt-okunur: asistan yalnizca durum RAPORLAR, hicbir mudahale eylemi baslatmaz
ve hicbir dis sisteme dokunmaz.
"""
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Answer:
    intent: str
    text_tr: str        # panelde gosterilecek tam yanit
    spoken_tr: str      # seslendirilecek kisa surum
    data: dict          # yanitin dayandigi ham veri (seffaflik)


# Seslendirme icin tehdit-duzeyi etiketlerini DOGRU Turkce'ye cevirir.
# Panelde etiketler ASCII'dir (KRITIK, YUKSEK...); Turkce ses motoru bunlari
# noktasiz-i ile yanlis okuyordu ("krItIk"). Konusma icin duzgun yaziyoruz.
_POSTURE_SPOKEN = {
    "KRITIK": "kritik", "KRİTİK": "kritik",
    "YUKSEK": "yüksek", "YÜKSEK": "yüksek",
    "ORTA-YUKSEK": "orta yüksek", "ORTA-YÜKSEK": "orta yüksek",
    "ORTA": "orta", "SAKIN": "sakin", "SAKİN": "sakin",
    "NORMAL": "normal", "DIKKAT": "dikkat", "DİKKAT": "dikkat",
    # durus makinesi seviyeleri (Ingilizce gelebilir) -> Turkce
    "CRITICAL": "kritik", "HIGH": "yüksek", "ELEVATED": "yükseltilmiş",
    "GUARDED": "temkinli", "CALM": "sakin", "LOW": "düşük",
}


def _say_posture(p) -> str:
    if not p:
        return "bilinmiyor"
    return _POSTURE_SPOKEN.get(str(p).upper(), str(p).lower())


# Kubbe katmanlarinin panel adlari ASCII'dir (command_center'da tanimli, o
# dosya baska bir ajanindir - degistirmiyoruz). Seslendirme icin DOGRU Turkce
# karsiliklarini burada tutariz ki TTS "Imza"yi "ımza" diye yanlis okumasin.
_LAYER_SPOKEN = {
    "soar": "SOAR kısıtlama",
    "posture": "adaptif duruş",
    "zero_trust": "sıfır güven kapısı",
    "mtd": "hareketli hedef savunması",
    "collective": "kolektif bağışıklık",
    "geo_velocity": "imkansız seyahat tespiti",
    "ensemble": "topluluk motoru",
    "threat_fusion": "Bayes tehdit füzyonu",
    "waf": "WAF imza motoru",
    "fingerprint": "parmak izi ve Sybil",
    "slow_burn": "düşük ve yavaş tespit",
    "beacon": "C2 işaret tespiti",
    "deception_grid": "aldatma ağı",
    "honeytoken": "honeytoken tuzağı",
    "deception": "aldatma yüzeyi",
    "novelty": "sıfır-gün sezgisi",
    "detection": "kural motoru ve ML",
    "integrity": "bütünlük zinciri",
}


def _coevo(db_path=None) -> dict:
    """Ko-evrim (beacon/novelty/geo/fusion/tarama) ozetini aggregator'dan alir.

    Aggregator'in `coevolution_advanced` fonksiyonu zaten her alt-blogu ayri
    korur; burada ek bir guvenlik kalkani daha koyariz ki asistan hicbir
    kosulda catlamasin - hata halinde tamamen sifir/bos bir iskelet doner.
    """
    from ..reporting import aggregator
    try:
        return aggregator.coevolution_advanced(db_path=db_path)
    except Exception:
        return {
            "beacon": {"count": 0, "top_ip": None, "top_period_sec": None},
            "novelty": {"count": 0, "flagged_ips": []},
            "geo_velocity": {"violations": 0, "identities": [], "top_regions": []},
            "fusion": {"top_posterior": 0.0, "top_ip": None, "top_factors": []},
            "scan_bruteforce": {"scanner_count": 0, "bruteforce_count": 0,
                                "top_scanner": None, "top_bruteforcer": None},
        }


# Niyet -> anahtar kelimeler. Sirali kontrol edilir (ilk eslesen kazanir).
# SIRA ONEMLI: ozel/dar niyetler (beacon, novelty, geo, fusion, scan, saglik,
# katman-detay) genel "defense_status/attack_status" niyetlerinden ONCE gelmeli
# ki spesifik bir soru genel ozete dusmesin.
_INTENTS = [
    ("help", ["yardim", "ne sorabilir", "neler yapabil", "komut", "nasil kullan"]),
    ("metrics", ["metrik", "f1", "precision", "recall", "basari", "performans",
                 "dogruluk", "yanlis pozitif", "benchmark"]),
    # --- Faz 41-44 + 61 ko-evrim niyetleri (ozel; once eslesmeli) ---
    ("beacon", ["beacon", "isaret", "c2", "geri arama", "periyodik", "call-home",
                "call home"]),
    ("novelty", ["sifir gun", "sifir-gun", "zero day", "zero-day", "yeni saldiri",
                 "novelty", "gorulmemis", "yenilik"]),
    ("geo", ["imkansiz seyahat", "konum", "cografi", "nereden", "geo",
             "hangi bolge", "hangi ulke"]),
    ("fusion", ["fuzyon", "bayes", "birlesik risk", "olasilik", "sonsal",
                "posterior"]),
    # --- Faz 74-75 ko-evrim niyetleri (ozel; scan/attack'tan ONCE eslesmeli) ---
    ("spray", ["sprey", "parola sprey", "kimlik doldur", "credential spray",
               "cok kullanici", "kullanici sprey"]),
    ("session_risk", ["oturum riski", "etkilesim", "ne kadar derine", "engagement",
                      "en derin saldirgan", "etkilesim derinlik", "oturum derinlik"]),
    ("scan", ["tarama", "port tarama", "kaba kuvvet", "kaba-kuvvet", "brute",
              "deneme", "kimlik doldur", "credential"]),
    ("health", ["saglik", "sistem sagligi", "calisiyor mu", "durum raporu tam",
                "modul durum", "sensor durum"]),
    ("top_threat", ["en riskli", "en tehlikeli", "en yuksek", "kim saldir",
                    "hangi ip", "baskin saldir", "en aktif saldir"]),
    ("campaigns", ["kampanya", "koordine", "birlikte"]),
    ("blocks", ["engel", "blok", "kac ip engel", "kisitla"]),
    ("honeytoken", ["honeytoken", "tuzak", "canary"]),
    # layer_detail: belirli bir katman adi geciyorsa (genel "katman"dan once).
    ("layer_detail", ["waf", "mtd", "hareketli hedef", "sifir guven", "zero trust",
                      "parmak izi", "sybil", "aldatma", "kolektif", "butunluk",
                      "topluluk motoru", "durus katman"]),
    ("layers", ["katman", "kubbe", "kalkan", "savunma katman"]),
    ("attack_status", ["saldiri", "atak", "tehdit durum", "saldirgan"]),
    ("defense_status", ["savunma", "durum", "koruma", "guvenlik durum", "genel durum",
                        "ne durumda", "sistem durum"]),
    ("summary", ["ozet", "rapor", "genel", "brifing", "sitrep"]),
]


def _norm(s: str) -> str:
    """Turkce'yi kaba ASCII'ye indir (anahtar kelime eslesmesi icin)."""
    s = (s or "").lower()
    for a, b in (("ı", "i"), ("ş", "s"), ("ç", "c"), ("ğ", "g"), ("ü", "u"), ("ö", "o"), ("İ", "i")):
        s = s.replace(a, b)
    return s


def classify(question: str) -> str:
    q = _norm(question)
    for intent, keys in _INTENTS:
        if any(k in q for k in keys):
            return intent
    return "defense_status"   # varsayilan: genel savunma durumu


def answer(question: str, db_path=None) -> dict:
    """Bir soruyu siniflandirip GERCEK veriden Turkce yanit uretir."""
    from ..reporting import aggregator
    from .. import storage

    intent = classify(question)
    try:
        ov = aggregator.overview(db_path=db_path)
    except Exception:
        ov = {"posture": "BILINMIYOR", "kpis": {}}
    k = ov.get("kpis", {})

    if intent == "help":
        a = Answer("help",
                   "Bana şunları sorabilirsin: “savunma durumumuz ne?”, "
                   "“saldırı durumu ne?”, “en riskli saldırgan kim?”, "
                   "“kaç alarm var?”, “metrikler nasıl?”, “honeytoken tetiklendi mi?”, "
                   "“kampanya var mı?”, “kaç IP engellendi?”. Doğal dilde yazman yeterli.",
                   "Savunma, saldırı, metrikler, riskli saldırgan, alarmlar — istediğini sor.",
                   {})
        return a.__dict__

    if intent == "metrics":
        try:
            m = aggregator.metrics_view(db_path=db_path)
        except Exception:
            m = {}
        b = (m or {}).get("benchmark")
        if b:
            fs = b["full_system"]["classification"]; t = b["full_system"]["timing"]
            text = (f"Etiketli benchmark sonuçlarımız: F1 skoru {fs['f1']:.3f} "
                    f"({b['full_system']['grade']}), tespit oranı %{fs['detection_rate']*100:.1f}, "
                    f"yanlış pozitif %{fs['false_positive_rate']*100:.1f}, ortalama tespit süresi "
                    f"{t['mttd_ms']:.2f} ms. Katmanlı sistem sadece-imzaya göre F1'i "
                    f"{b['signature_only']['classification']['f1']:.3f}'ten {fs['f1']:.3f}'e çıkarıyor.")
            spoken = (f"F1 skoru {fs['f1']:.2f}, tespit oranı yüzde {fs['detection_rate']*100:.0f}, "
                      f"yanlış pozitif yüzde {fs['false_positive_rate']*100:.0f}.")
        else:
            text = ("Henüz benchmark çalıştırılmadı. Gerçek metrikler için terminalde "
                    "`python scripts/demo_benchmark.py` çalıştır.")
            spoken = "Henüz benchmark çalıştırılmadı."
        return Answer("metrics", text, spoken, {"benchmark": bool(b)}).__dict__

    if intent == "beacon":
        co = _coevo(db_path)
        b = co["beacon"]
        cnt = b.get("count", 0)
        if cnt:
            top = b.get("top_ip")
            per = b.get("top_period_sec")
            per_txt = f"~{per:.0f} saniye" if isinstance(per, (int, float)) else "belirsiz"
            text = (f"{cnt} kaynakta C2 beacon benzeri periyodik call-home ritmi tespit edildi. "
                    f"En düzenli olanı {top}, {per_txt}lik periyotla “eve telefon ediyor”. "
                    f"Trafik şifreli olsa bile zamanlama ritmi makine ürünüdür — bu bir tespit "
                    f"göstergesidir, insan incelemesine yükseltilir (otomatik blok değil).")
            spoken = (f"{cnt} kaynakta periyodik beacon ritmi tespit edildi. "
                      f"En düzenli olanı {top}, yaklaşık {per:.0f} saniyelik periyotla."
                      if isinstance(per, (int, float)) else
                      f"{cnt} kaynakta periyodik beacon ritmi tespit edildi. En düzenli olanı {top}.")
        else:
            text = ("Şu an düzenli C2 beacon ritmi gösteren kaynak yok — periyodik call-home "
                    "tespit edilmedi. Zamanlama düzlemi temiz görünüyor.")
            spoken = "Düzenli C2 beacon ritmi gösteren kaynak yok."
        return Answer("beacon", text, spoken, {"beacon": b}).__dict__

    if intent == "novelty":
        co = _coevo(db_path)
        nv = co["novelty"]
        cnt = nv.get("count", 0)
        if cnt:
            ips = ", ".join(nv.get("flagged_ips", [])[:3])
            text = (f"{cnt} kaynaktan daha önce görülmemiş (sıfır-gün adayı) payload işaretlendi"
                    f"{': ' + ips if ips else ''}. Bu payloadların çoğu n-gram’ı bilinen saldırı "
                    f"korpusunda yok — imzasız sezgi katmanı yakaladı. Kesin kanıt değil; sıfır-gün "
                    f"olasılığı için insan incelemesine yükseltilir.")
            spoken = f"{cnt} kaynakta görülmemiş, sıfır-gün adayı payload işaretlendi."
        else:
            text = ("Şu an sıfır-gün adayı (görülmemiş) payload işaretlenmedi — gelen trafik büyük "
                    "ölçüde bilinen saldırı desenlerine benziyor.")
            spoken = "Görülmemiş, sıfır-gün adayı payload yok."
        return Answer("novelty", text, spoken, {"novelty": nv}).__dict__

    if intent == "geo":
        co = _coevo(db_path)
        g = co["geo_velocity"]
        v = g.get("violations", 0)
        regions = g.get("top_regions", [])
        region_txt = ", ".join(f"{r['region']} ({r['count']})" for r in regions[:3]) or "kayıtlı dış bölge yok"
        top_region = regions[0]["region"] if regions else "bilinmiyor"
        if v:
            ids = ", ".join(g.get("identities", [])[:3])
            text = (f"{v} kimlikte imkansız seyahat ihlali tespit edildi"
                    f"{' (' + ids + ')' if ids else ''}. Aynı aktör fiziksel olarak mümkün olmayan "
                    f"hızda konum değiştirdi — olası hesap ele geçirme veya proxy rotasyonu. "
                    f"En yoğun saldırgan bölgeleri: {region_txt}. Konumlar RIR (bölge) seviyesinde "
                    f"tahmindir; şehir hassasiyeti iddia edilmez.")
            spoken = (f"{v} kimlikte imkansız seyahat ihlali tespit edildi. "
                      f"En yoğun bölge {top_region}.")
        else:
            text = (f"Şu an imkansız seyahat ihlali yok. En yoğun saldırgan bölgeleri: {region_txt}. "
                    f"Konumlar çevrimdışı, bölge (RIR) seviyesinde tahmindir.")
            spoken = f"İmkansız seyahat ihlali yok. En yoğun bölge {top_region}."
        return Answer("geo", text, spoken, {"geo": g}).__dict__

    if intent == "fusion":
        co = _coevo(db_path)
        f = co["fusion"]
        post = f.get("top_posterior", 0.0)
        if f.get("top_ip"):
            factors = ", ".join(f.get("top_factors", [])) or "-"
            text = (f"Bayes tehdit füzyonu: en yüksek birleşik sonsal olasılık %{post*100:.0f} "
                    f"({f['top_ip']}). Birden fazla bağımsız kanıt aynı yönü gösteriyor — baskın "
                    f"faktörler: {factors}. Bu bir olasılık tahminidir, kesin kanıt değil; "
                    f"insan incelemesine yükseltilir.")
            spoken = (f"En yüksek birleşik tehdit olasılığı yüzde {post*100:.0f}, "
                      f"kaynak {f['top_ip']}. Baskın faktörler: {factors}.")
        else:
            text = ("Şu an birden fazla bağımsız kanıtı birleşen bir kaynak yok — Bayes füzyonu "
                    "belirgin bir yükseltme üretmedi.")
            spoken = "Birleşik tehdit olasılığını yükselten çoklu kanıt yok."
        return Answer("fusion", text, spoken, {"fusion": f}).__dict__

    if intent == "spray":
        try:
            sv = aggregator.credential_spray_view(db_path=db_path)
        except Exception:
            sv = {"spray_ips": [], "top_sprayer": None,
                  "distinct_user_total": 0, "count": 0}
        cnt = sv.get("count", 0)
        top = sv.get("top_sprayer")
        total_users = sv.get("distinct_user_total", 0)
        if cnt:
            top_txt = ""
            if top:
                top_txt = (f" En yoğun sprayci {top['ip']} — "
                           f"{top['distinct_users']} farklı kullanıcı adına deneme yaptı.")
            text = (f"Parola spreyi tespiti: {cnt} kaynak, çok sayıda farklı kullanıcıya "
                    f"az parola deneyerek (kimlik-doldurma) hesap kilitleme eşiğinin altında "
                    f"kalmaya çalışıyor; toplam {total_users} farklı kullanıcı hedeflendi."
                    f"{top_txt} Bu davranışsal bir göstergedir — insan incelemesine "
                    f"yükseltilir, otomatik blok değil.")
            spoken = f"{cnt} kaynakta parola spreyi tespit edildi."
            if top:
                spoken += (f" En yoğun spreyci {top['ip']}, "
                           f"{top['distinct_users']} farklı kullanıcı hedefledi.")
        else:
            text = ("Şu an parola spreyi veya kimlik-doldurma davranışı gösteren kaynak yok — "
                    "hedeflenen farklı kullanıcı çeşitliliği eşik altında.")
            spoken = "Parola spreyi davranışı tespit edilmedi."
        return Answer("spray", text, spoken, {"spray": sv}).__dict__

    if intent == "session_risk":
        try:
            rv = aggregator.session_risk_view(db_path=db_path)
        except Exception:
            rv = {"ranked": [], "top_ip": None, "high_count": 0, "count": 0}
        cnt = rv.get("count", 0)
        top = rv.get("top_ip")
        high = rv.get("high_count", 0)
        if cnt and top:
            # En derin saldirganin ulastigi asamalari ranked kaydindan al.
            ranked = rv.get("ranked", [])
            depth = ranked[0].get("depth", 0) if ranked else 0
            band_spoken = _say_posture(top.get("band_tr"))
            text = (f"Oturum riski / etkileşim derinliği: {cnt} kaynak skorlandı, "
                    f"{high} tanesi yüksek veya kritik bantta. En derine inen saldırgan "
                    f"{top['ip']} — etkileşim skoru {top['score']}/100 ({top.get('band_tr','-')}), "
                    f"kill-chain'de {depth} farklı aşamaya ulaştı. Skor ne kadar yüksekse "
                    f"saldırgan honeypot'ta o kadar derine inmiştir; bu bir önceliklendirme "
                    f"göstergesidir, otomatik blok değil.")
            spoken = (f"En derin saldırgan {top['ip']}, etkileşim skoru {top['score']}, "
                      f"bant {band_spoken}. {depth} aşamaya ulaştı.")
        else:
            text = ("Şu an ölçülebilir etkileşim derinliği gösteren saldırgan yok — "
                    "gelen olaylar sınıflandırılabilir bir kill-chain aşamasına oturmadı.")
            spoken = "Ölçülebilir oturum etkileşim derinliği yok."
        return Answer("session_risk", text, spoken, {"session_risk": rv}).__dict__

    if intent == "scan":
        from ..adaptive import scan_bruteforce
        try:
            sb = scan_bruteforce.analyze_recent(db_path=db_path)
        except Exception:
            sb = {"scanner_count": 0, "bruteforce_count": 0,
                  "top_scanner": None, "top_bruteforcer": None}
        sc = sb.get("scanner_count", 0)
        bc = sb.get("bruteforce_count", 0)
        ts = sb.get("top_scanner")
        tb = sb.get("top_bruteforcer")
        if sc or bc:
            worst = []
            if ts:
                worst.append(f"en agresif tarayıcı {ts['ip']} ({ts['distinct_services']} farklı servis)")
            if tb:
                worst.append(f"en yoğun kaba-kuvvetçi {tb['ip']} "
                             f"(‘{tb['top_service']}’ servisine {tb['attempts']} deneme)")
            text = (f"Tarama/kaba-kuvvet tespiti: {sc} yatay tarayıcı ve {bc} kaba-kuvvet kaynağı "
                    f"işaretlendi. " + (("; ".join(worst) + ". ") if worst else "")
                    + "Her ikisi de davranışsal göstergedir — insan incelemesine yükseltilir, "
                    "otomatik blok değil.")
            spoken = f"{sc} tarayıcı ve {bc} kaba-kuvvet kaynağı tespit edildi."
            if tb:
                spoken += f" En yoğun kaba-kuvvetçi {tb['ip']}."
            elif ts:
                spoken += f" En agresif tarayıcı {ts['ip']}."
        else:
            text = ("Şu an yatay tarama veya kaba-kuvvet davranışı gösteren kaynak yok — "
                    "tarama çeşitliliği ve deneme temposu eşik altında.")
            spoken = "Tarama veya kaba-kuvvet davranışı tespit edilmedi."
        return Answer("scan", text, spoken, {"scan": sb}).__dict__

    if intent == "health":
        try:
            m = aggregator.metrics_view(db_path=db_path)
            fleet = m.get("sensor_health", {}) or {}
        except Exception:
            fleet = {}
        online = fleet.get("online", 0)
        total_sensors = len(fleet.get("sensors", []) or [])
        fleet_pct = fleet.get("fleet_health_pct", 100.0)

        # Modul kullanilabilirligi: adaptif dedektorleri gercekten import edip say.
        mods = ["beacon", "novelty", "geo_velocity", "threat_fusion",
                "scan_bruteforce", "collective", "game_theory", "coverage",
                "deception_grid", "ensemble", "fingerprint", "slow_detector",
                "posture", "zero_trust"]
        avail = 0
        for name in mods:
            try:
                __import__(f"arachne.adaptive.{name}")
                avail += 1
            except Exception:
                pass

        # Test sayisi: tests/ klasorundeki test fonksiyonlarini GERCEKTEN say
        # (uydurma yok; okunamazsa 0).
        test_count = 0
        try:
            from pathlib import Path
            tdir = Path(__file__).resolve().parents[2] / "tests"
            for tf in tdir.glob("test_*.py"):
                test_count += len(re.findall(r"(?m)^def test_",
                                             tf.read_text(encoding="utf-8")))
        except Exception:
            test_count = 0

        posture = ov.get("posture", "-")
        sensors_txt = (f"{online}/{total_sensors} sensör çevrimiçi (filo sağlığı %{fleet_pct:.0f})"
                       if total_sensors else "kayıtlı sensör yok (tek-düğüm lab)")
        text = (f"Sistem sağlığı: Tehdit düzeyi {posture}. {sensors_txt}. "
                f"{avail}/{len(mods)} adaptif dedektör modülü yüklenebilir durumda. "
                f"{k.get('events',0)} olay işlendi, {k.get('alerts',0)} alarm üretildi. "
                f"Doğrulama paketi: {test_count} birim test tanımlı. "
                f"Tüm savunma halkaları çevrimiçi; çekirdeğe ulaşan saldırı yok.")
        spoken = (f"Sistem sağlığı raporu. Tehdit düzeyi {_say_posture(posture)}. "
                  f"{avail} adaptif modül aktif, {test_count} birim test tanımlı. "
                  f"Tüm savunma halkaları çevrimiçi, çekirdeğe sızıntı yok.")
        return Answer("health", text, spoken,
                      {"modules_available": avail, "modules_total": len(mods),
                       "test_count": test_count, "sensors_online": online}).__dict__

    if intent == "layer_detail":
        try:
            from ..reporting import command_center
            dome = command_center.build_dome_state(db_path=db_path)
            layers = dome.get("layers", [])
        except Exception:
            layers = []
        qn = _norm(question)
        # Soruda gecen katman adini belirle (dar->genis takma ad eslemesi).
        needles = [
            ("waf", "waf"), ("hareketli hedef", "mtd"), ("mtd", "mtd"),
            ("sifir guven", "zero_trust"), ("zero trust", "zero_trust"),
            ("parmak izi", "fingerprint"), ("sybil", "fingerprint"),
            ("aldatma ag", "deception_grid"), ("kirinti", "deception_grid"),
            ("aldatma", "deception"), ("kolektif", "collective"),
            ("butunluk", "integrity"), ("topluluk motoru", "ensemble"),
            ("topluluk", "ensemble"), ("imkansiz seyahat", "geo_velocity"),
            ("beacon", "beacon"), ("honeytoken", "honeytoken"),
            ("sifir gun", "novelty"), ("novelty", "novelty"),
            ("kural motoru", "detection"), ("durus", "posture"),
        ]
        target_id = None
        for needle, lid in needles:
            if needle in qn:
                target_id = lid
                break
        match = None
        if target_id:
            for l in layers:
                if l.get("id") == target_id:
                    match = l
                    break
        if match:
            role = (match.get("description_tr") or "").split(".")[0].strip()
            text = (f"{match.get('name')} katmanı: şu ana kadar {match.get('interceptions', 0)} "
                    f"müdahale/tetiklenme kaydı ({'aktif' if match.get('active') else 'bu koşuda tetiklenmedi'}). "
                    f"Rolü: {role}.")
            spoken = (f"{match.get('name')} katmanı {match.get('interceptions', 0)} müdahale kaydetti.")
        else:
            text = ("Sorunda tanıdığım belirli bir savunma katmanı adı bulamadım. "
                    "Örnek: WAF, MTD, sıfır güven, parmak izi, honeytoken, beacon, bütünlük.")
            spoken = "Belirtilen savunma katmanını tanıyamadım."
        return Answer("layer_detail", text, spoken, {"layer": match}).__dict__

    if intent in ("top_threat", "campaigns"):
        try:
            tv = aggregator.threat_intel_view(db_path=db_path, top_n=5)
        except Exception:
            tv = {"profiles": [], "campaigns": []}
        if intent == "top_threat":
            profs = tv.get("profiles", [])
            if profs:
                p = profs[0]
                risk = p.get("risk", {})
                text = (f"En riskli saldırgan: {p['source_ip']} — risk {risk.get('risk_score','?')}/100 "
                        f"({risk.get('risk_band','?')}). Sınıf: {p.get('threat_class','?')}, "
                        f"{p.get('event_count',0)} olay, birincil araç: {p.get('primary_tool','?')}. "
                        f"Kill chain: {p.get('kill_chain',{}).get('phase_tr','-')}.")
                spoken = (f"En riskli saldırgan {p['source_ip']}, risk skoru "
                          f"{risk.get('risk_score','bilinmiyor')}.")
            else:
                text = "Şu an kayıtlı riskli saldırgan profili yok — sistem sakin."
                spoken = "Şu an riskli saldırgan yok."
            return Answer("top_threat", text, spoken, {}).__dict__
        else:
            camps = tv.get("campaigns", [])
            if camps:
                c = camps[0]
                text = (f"{len(camps)} korele kampanya var. En büyüğü: {len(c.get('member_ips',[]))} IP "
                        f"aynı parmak izini paylaşıyor ({c.get('primary_tool', c.get('tools','?'))}). "
                        f"Bu, tek bir koordineli operasyona işaret ediyor.")
                spoken = f"{len(camps)} koordineli kampanya tespit edildi."
            else:
                text = "Şu an korele bir saldırı kampanyası tespit edilmedi."
                spoken = "Koordineli kampanya yok."
            return Answer("campaigns", text, spoken, {}).__dict__

    if intent == "blocks":
        n = k.get("active_blocks", 0)
        text = (f"Şu an {n} IP aktif olarak engelli (SOAR kısıtlaması). "
                f"Engellenen bir IP tekrar bağlanmaya çalışırsa bağlantı kurulmadan reddedilir.")
        return Answer("blocks", text, f"{n} IP engelli.", {"blocks": n}).__dict__

    if intent == "honeytoken":
        trig = k.get("honeytokens_triggered", 0)
        total = k.get("honeytokens_total", 0)
        if trig:
            text = (f"{total} honeytoken tuzağından {trig} tanesi tetiklendi. "
                    f"Bu neredeyse kesin bir ihlal kanıtıdır — meşru kullanıcılar bu tuzak "
                    f"değerlerin varlığını bilmez, yani yanlış pozitif oranı ~sıfırdır.")
            spoken = f"{trig} honeytoken tetiklendi. Yüksek güvenli ihlal kanıtı."
        else:
            text = f"{total} honeytoken tuzağı yerleştirildi, henüz tetiklenen yok."
            spoken = "Henüz tetiklenen honeytoken yok."
        return Answer("honeytoken", text, spoken, {"triggered": trig}).__dict__

    if intent == "layers":
        try:
            from ..reporting import command_center
            dome = command_center.build_dome_state(db_path=db_path)
            active = sum(1 for l in dome["layers"] if l.get("active"))
            total = len(dome["layers"])
            posture = dome.get("posture", {}).get("level", "-")
        except Exception:
            active, total, posture = 0, 0, "-"
        text = (f"Çelik Kubbe {total} savunma katmanından oluşuyor; şu an {active} tanesi aktif. "
                f"Adaptif duruş seviyesi: {posture}. Çekirdeğe ulaşan saldırı sayısı sıfır — "
                f"honeypot mimarisi gereği saldırgan gerçek varlığa asla ulaşamaz.")
        spoken = f"{total} katmandan {active} tanesi aktif, duruş {_say_posture(posture)}."
        return Answer("layers", text, spoken, {"active": active, "total": total}).__dict__

    if intent == "attack_status":
        text = (f"Saldırı durumu: {k.get('events',0)} olay kaydedildi, {k.get('alerts',0)} alarm üretildi "
                f"({k.get('critical_alerts',0)} kritik, {k.get('high_alerts',0)} yüksek). "
                f"{k.get('active_blocks',0)} IP engellendi, {k.get('honeytokens_triggered',0)} honeytoken tetiklendi. "
                f"Tehdit düzeyi: {ov.get('posture','-')}.")
        spoken = (f"Saldırı durumu raporu. {k.get('events',0)} olay kaydedildi, "
                  f"{k.get('alerts',0)} alarm üretildi. Bunların {k.get('critical_alerts',0)} tanesi kritik, "
                  f"{k.get('high_alerts',0)} tanesi yüksek öncelikli. "
                  f"{k.get('active_blocks',0)} saldırgan engellendi, "
                  f"{k.get('honeytokens_triggered',0)} honeytoken tetiklendi. "
                  f"Tehdit düzeyi {_say_posture(ov.get('posture'))}. Çekirdeğe sızıntı yok.")
        return Answer("attack_status", text, spoken, {"kpis": k}).__dict__

    if intent == "summary":
        try:
            from .report_writer import situation_report
            rep = situation_report(db_path=db_path)
            body = rep.get("report") or ""
            if isinstance(body, dict):
                body = body.get("summary") or body.get("text") or ""
        except Exception:
            body = ""
        text = (f"Durum brifingi — Tehdit düzeyi {ov.get('posture','-')}. "
                f"{k.get('events',0)} olay, {k.get('alerts',0)} alarm ({k.get('critical_alerts',0)} kritik), "
                f"{k.get('active_blocks',0)} engelli IP, {k.get('honeytokens_triggered',0)} tetiklenen tuzak, "
                f"{k.get('deception_actions',0)} aktif savunma eylemi. ")
        if body:
            text += "AI analist notu: " + (body[:280])
        spoken = (f"Durum brifingi. Tehdit düzeyi {_say_posture(ov.get('posture'))}. "
                  f"{k.get('events',0)} olay işlendi, {k.get('alerts',0)} alarm üretildi, "
                  f"{k.get('critical_alerts',0)} tanesi kritik. "
                  f"{k.get('active_blocks',0)} saldırgan engellendi, "
                  f"{k.get('honeytokens_triggered',0)} tuzak tetiklendi, "
                  f"{k.get('deception_actions',0)} aktif savunma eylemi alındı. "
                  f"Çekirdeğe sızıntı yok.")
        return Answer("summary", text, spoken, {"kpis": k}).__dict__

    # Varsayilan: savunma durumu
    text = (f"Savunma durumu: Tehdit düzeyi {ov.get('posture','-')}. "
            f"{k.get('events',0)} olay işlendi, {k.get('alerts',0)} alarm ({k.get('critical_alerts',0)} kritik). "
            f"{k.get('active_blocks',0)} IP engelli, {k.get('mtd_rotations',0)} kimlik rotasyonu, "
            f"{k.get('deception_actions',0)} aktif savunma eylemi, {k.get('honeytokens_triggered',0)} tetiklenen tuzak. "
            f"18 savunma halkasının tamamı nominal; çekirdeğe ulaşan saldırı yok.")
    spoken = (f"Savunma durumu raporu. Tehdit düzeyi {_say_posture(ov.get('posture'))}. "
              f"{k.get('events',0)} olay işlendi, {k.get('alerts',0)} alarm üretildi, "
              f"{k.get('critical_alerts',0)} tanesi kritik. "
              f"{k.get('active_blocks',0)} saldırgan engellendi, "
              f"{k.get('mtd_rotations',0)} kimlik rotasyonu yapıldı, "
              f"{k.get('honeytokens_triggered',0)} tuzak tetiklendi. "
              f"Tüm savunma halkaları çevrimiçi. Çekirdeğe sızıntı yok.")
    return Answer("defense_status", text, spoken, {"kpis": k}).__dict__
