"""
Faz 39 - Metrik ve Degerlendirme Motoru.

Bir tespit sistemi "iyi calisiyor" iddiasi tek basina hicbir sey ifade
etmez. Bu modul, sistemin gercek kalitesini ETIKETLI benchmark verisi
uzerinden - yani her olayin gercekte kotu mu iyi mi oldugu ONCEDEN bilinen
kontrollu bir kume uzerinden - sayisal olarak olcer.

--- Neyi modelliyor ---
  * Karisiklik matrisi + precision / recall / F1 / accuracy:
    standart bilgi-getirimi (IR) ve makine ogrenmesi degerlendirmesi.
  * FPR (yanlis pozitif orani) / FNR (yanlis negatif orani): bir tespit
    sisteminin gercek maliyet eksenleri - cok alarm mi, kacan saldiri mi?
  * MTTD (Mean Time To Detect), MTTR (Mean Time To Respond), P95 gecikme,
    olay/sn (throughput): klasik SOC / SRE operasyonel metrikleri.

--- DURUSTLUK NOTU ---
Buradaki tum sayilar SADECE verilen etiketli benchmark kumesi uzerinde
gecerlidir. Bunlar sistemin gercek dunyadaki mutlak performansini GARANTI
ETMEZ - yalnizca "bu kontrollu senaryolarda su kadar isabet etti" der.
Benchmark ne kadar dar/temsili degilse, gercek dunya o kadar farkli olur.
Metrik, iddianin yerine gecen bir kanittir; ama kanitin kapsami kadar
gecerlidir. Ayrica hicbir sayi 0 bolen durumunda patlamaz -> 0.0 doner.

--- ETIK ---
Savunma amaclidir: yalnizca kendi honeypot/WAF yuzeyimizin tespit
kalitesini olceriz. Saldirgana geri saldiri (hack-back) yoktur; disariya
hicbir istek gitmez. Saf fonksiyonlar: veri arguman olarak gelir, sozluk
doner. Ag yok, dosya yok, storage.py'ye dokunulmaz. Sadece stdlib.
"""
import math


def _safe_div(numerator: float, denominator: float) -> float:
    """Sifira bolmeyi 0.0 ile guvene alan bolme."""
    if not denominator:
        return 0.0
    return numerator / denominator


def confusion_matrix(results: list) -> dict:
    """Etiketli sonuclardan karisiklik matrisi (TP/FP/FN/TN) sayilarini uretir.

    Her sonuc: {"is_malicious": bool (gercek), "detected": bool (tahmin)}.
      * TP: gercekten kotu, tespit edildi.
      * FP: aslinda iyi, yanlislikla alarm verildi.
      * FN: gercekten kotu, KACIRILDI.
      * TN: iyi, dogru sekilde temiz gecti.
    """
    tp = fp = fn = tn = 0
    for r in results:
        truth = bool(r.get("is_malicious"))
        pred = bool(r.get("detected"))
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif truth and not pred:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def classification_metrics(results: list) -> dict:
    """Siniflandirma kalitesini (precision/recall/F1/accuracy vb.) hesaplar.

    Tum oranlar 0..1 araligindadir ve 4 ondalik basamaga yuvarlanir. Her
    bolme sifira karsi korunur (payda 0 -> 0.0).
    """
    cm = confusion_matrix(results)
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    total = tp + fp + fn + tn

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)                 # detection_rate ile ayni
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, total)
    false_positive_rate = _safe_div(fp, fp + tn)
    false_negative_rate = _safe_div(fn, fn + tp)

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "detection_rate": round(recall, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def percentile(values: list, p: float) -> float:
    """Elle hesaplanan yuzdelik dilim (p: 0..100), dogrusal interpolasyon.

    Bos liste -> 0.0. numpy/statistics.quantiles gibi bir bagimlilik
    kullanmadan, siralanmis dizide (p/100)*(n-1) konumundaki degeri iki komsu
    arasinda dogrusal interpolasyonla bulur.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    if n == 1:
        return float(ordered[0])
    p = max(0.0, min(100.0, float(p)))
    rank = (p / 100.0) * (n - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(ordered[low])
    frac = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def timing_metrics(results: list) -> dict:
    """SOC zamanlama metrikleri: MTTD, MTTR ve tespit gecikmesi dagilimi.

    Sonuclar {"detected", "detect_latency_ms", "respond_latency_ms"} tasiyabilir.
      * mttd_ms: tespit edilen (detected=True) olaylarda ortalama tespit
        gecikmesi (Mean Time To Detect).
      * mttr_ms: respond_latency_ms bulunan olaylarda ortalama yanit gecikmesi
        (Mean Time To Respond).
      * p95 / medyan / maksimum: tespit gecikmelerinin dagilimi (kuyruk
        gecikmesi operasyonel olarak ortalamadan daha onemlidir).
    """
    detect_latencies = []
    respond_latencies = []
    for r in results:
        if r.get("detected") and r.get("detect_latency_ms") is not None:
            detect_latencies.append(float(r["detect_latency_ms"]))
        if r.get("respond_latency_ms") is not None:
            respond_latencies.append(float(r["respond_latency_ms"]))

    mttd = _safe_div(sum(detect_latencies), len(detect_latencies))
    mttr = _safe_div(sum(respond_latencies), len(respond_latencies))
    max_detection = max(detect_latencies) if detect_latencies else 0.0

    return {
        "mttd_ms": round(mttd, 2),
        "mttr_ms": round(mttr, 2),
        "p95_detection_latency_ms": round(percentile(detect_latencies, 95), 2),
        "median_detection_latency_ms": round(percentile(detect_latencies, 50), 2),
        "max_detection_latency_ms": round(float(max_detection), 2),
    }


def throughput(event_count: int, elapsed_sec: float) -> dict:
    """Isleme kapasitesi: saniyede kac olay islendi (olay/sn)."""
    return {"events_per_sec": round(_safe_div(event_count or 0, elapsed_sec or 0), 2)}


def response_success_rate(responses: list) -> dict:
    """Otomatik yanit basari orani.

    Her yanit {"applied": bool}: aksiyon gercekten uygulanabildi mi? Bir
    playbook tetiklenip de blocklist/tarpit aksiyonu uygulanamadiysa bu, yanit
    zincirinin zayif halkasidir.
    """
    total = len(responses)
    applied = sum(1 for r in responses if r.get("applied"))
    return {
        "rate": round(_safe_div(applied, total), 4),
        "applied": applied,
        "total": total,
    }


def _grade_from_f1(f1: float) -> str:
    """F1 skorundan Turkce harf/etiket notu."""
    if f1 >= 0.90:
        return "A - Mukemmel"
    if f1 >= 0.80:
        return "B - Iyi"
    if f1 >= 0.70:
        return "C - Orta"
    if f1 >= 0.60:
        return "D - Zayif"
    return "F - Yetersiz"


def evaluation_report(results: list, elapsed_sec: float = None,
                      responses: list = None, sensor_health: dict = None,
                      event_count: int = None) -> dict:
    """Tum metrikleri tek bir degerlendirme raporunda birlestirir.

    Siniflandirma + zamanlama + throughput + yanit basarisi + sensor sagligini
    bir araya getirir, F1'den bir not (grade) cikarir ve Turkce bir ozet uretir.

    DURUSTLUK: rapor, sayilarin ETIKETLI benchmark verisi uzerinde olculdugunu
    ve mutlak bir garanti OLMADIGINI acikca belirtir.
    """
    classification = classification_metrics(results)
    timing = timing_metrics(results)

    ev_count = event_count if event_count is not None else len(results)
    tput = throughput(ev_count, elapsed_sec) if elapsed_sec is not None else {
        "events_per_sec": 0.0
    }
    response = response_success_rate(responses) if responses else {
        "rate": 0.0, "applied": 0, "total": 0
    }

    f1 = classification["f1"]
    grade = _grade_from_f1(f1)

    summary_tr = (
        f"Etiketli benchmark: {len(results)} senaryo, "
        f"F1={f1} (not: {grade}), "
        f"tespit orani={classification['detection_rate']}, "
        f"yanlis pozitif orani={classification['false_positive_rate']}, "
        f"MTTD={timing['mttd_ms']}ms, MTTR={timing['mttr_ms']}ms, "
        f"P95 tespit={timing['p95_detection_latency_ms']}ms, "
        f"throughput={tput['events_per_sec']} olay/sn. "
        f"DURUSTLUK: bu sayilar yalnizca bu etiketli benchmark kumesinde "
        f"olculmustur; gercek dunya performansini GARANTI ETMEZ."
    )

    return {
        "classification": classification,
        "timing": timing,
        "throughput": tput,
        "response": response,
        "sensor_health": sensor_health or {},
        "grade": grade,
        "summary_tr": summary_tr,
    }
