"""
Faz 106 - Isolation Forest icin "normal" davranis ornekleri.

--- DURUSTLUK NOTU (onemli) ---
Bu, gercek uretim trafiginden ogrenilmis bir taban cizgisi (baseline)
DEGILDIR - `training_data.py`'nin (Faz 2) 38 zararli/40 zararsiz metin
ornegiyle AYNI olcekte, elle yazilmis, ILLUSTRATIF bir sentetik veri
kumesidir. Amac, Isolation Forest'in "az ama gercekten calisan" bir
ornekle nasil calistigini gostermektir - kesin kalibre edilmis bir
uretim modeli iddia edilmez.

Her satir `arachne.detection.anomaly_ml.FEATURE_NAMES` sirasiyla:
  [event_count, distinct_services, distinct_ports, avg_payload_length,
   avg_entropy]

Degerler, "birkac servise, birkac kisa istekle, dusuk entropili yukle
baglanan sıradan/mesru bir istemci" profilini temsil eder."""

NORMAL_FEATURE_SAMPLES = [
    [1, 1, 1, 20, 3.0],
    [2, 1, 1, 15, 2.8],
    [3, 2, 2, 30, 3.5],
    [1, 1, 1, 10, 2.5],
    [4, 2, 2, 25, 3.2],
    [2, 1, 1, 18, 3.0],
    [5, 2, 3, 22, 3.4],
    [1, 1, 1, 12, 2.6],
    [3, 1, 2, 28, 3.1],
    [2, 2, 2, 16, 2.9],
    [1, 1, 1, 8, 2.2],
    [4, 3, 3, 35, 3.6],
    [2, 1, 1, 14, 2.7],
    [3, 2, 1, 20, 3.0],
    [1, 1, 1, 5, 2.0],
]
