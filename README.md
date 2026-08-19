# 🕸 Arachne Sentinel

Honeypot tabanlı, **70 fazlı** bir **erken uyarı, saldırı tespit, otonom
müdahale, aktif savunma, adaptif (ko-evrim) savunma ve ölçülebilir SOC
platformu**. Faz 1-70 tam — motor + test + sinematik komuta merkezi + AI
komuta asistanı. **18 halkalı** Çelik Kubbe. Sahte servisler açar, gelen her etkileşimi kaydeder,
saldırgan davranışını **açıklanabilir** şekilde puanlar, saldırıyı tersine
mühendislikle çözer, saldırgan profili çıkarır, otomatik müdahale eder ve
tüm bunları canlı bir komuta merkezinde gösterir.

> ⚠️ **Sadece kendi sahip olduğunuz veya test izniniz olan, izole/lab
> ortamlarında çalıştırın.** Detaylar için [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md)
> dosyasına bakın.

## Neden bu proje?

Bu, gerçek dünyadaki savunma amaçlı güvenlik ürünlerinin (honeypot/deception
teknolojisi, IDS, WAF, SOAR, tehdit istihbaratı platformları) küçük ölçekli ama
**gerçekten çalışan** bir versiyonu olarak tasarlandı. Amaç büyük iddialarla
değil, ölçülebilir ve savunulabilir sonuçlarla dikkat çekmek — her alarmın,
her otomatik kararın *neden* verildiği açıkça görülebilir.

**Sabit ilke:** Az ama gerçekten çalışan, test edilmiş, savunulabilir.
Hiçbir yerde sahte veri, süs animasyonu ya da "yapay zeka ekledik" pazarlaması
yoktur — panelde gördüğünüz her sayı gerçek bir veritabanı kaydından gelir.

## Özellikler

**Faz 1 — Honeypot ve tespit motoru:**
- **4 sahte servis**: SSH, FTP, MySQL, HTTP "admin panel" (`arachne/honeypot/`)
- **SQLite tabanlı olay/alarm günlüğü** (`arachne/storage.py`)
- **Açıklanabilir kural motoru** (`arachne/detection/`): port taraması,
  brute-force, bilinen saldırı imzaları, çoklu servis keşfi, tekrarlayan saldırgan

**Faz 2 — WAF, otonom tarayıcı ve ML sınıflandırıcı:**
- **WAF katmanı** (`arachne/waf/`): herhangi bir WSGI uygulamasının önüne
  konabilen, regex tabanlı imza motoru + rate-limiting middleware
- **Otonom zafiyet tarayıcı** (`arachne/scanner/`): bağımsız port tarama +
  banner grabbing + bilinen zafiyet eşleştirme
- **ML tabanlı saldırı sınıflandırıcısı** (`arachne/detection/ml_classifier.py`):
  TF-IDF + Logistic Regression, kural motoruna *ek* bir sinyal olarak

**Faz 3 — Native ARM64 assembly imza tarama çekirdeği:**
- İmza taramasının çekirdeği elle yazılmış **ARM64 assembly** ile
  (`arachne/native/arm64/fast_scan.s`) — Apple Silicon'da native çalışır,
  diğer platformlarda birebir aynı sonucu üreten Python yedeğine düşer
- Bağımsız native CLI aracı (`arachne/native/tools/byte_inspector.s`)
- Detaylar ve dürüst kıyaslama: [arachne/native/README.md](arachne/native/README.md)

**Faz 4 — Moving Target Defense ("hayalet" savunma katmanı):**
- **Banner/sürüm rotasyonu** (`arachne/mtd/identity_rotator.py`)
- **Gerçekten port değiştiren "hayalet admin" servisi** (`arachne/mtd/port_hopper.py`)
- **Lab-içi "hayalet DNS" yanıtlayıcısı** (`arachne/mtd/dns_ghost.py`) — DNS paket
  formatı elle ayrıştırılıp üretilir
- ⚠️ Bu bir VPN/anonimlik ürünü değildir — sadece kendi izole lab ortamınızdaki
  sahte servislerin kimliğini değiştirir

**Faz 5 — Saldırı tersine mühendisliği** (`arachne/reverse/`):
- **Çok katmanlı kodlama çözücü**: URL, çift-URL, base64, hex, HTML entity,
  unicode escape — sabit noktaya kadar katman katman açar ve hangi adımlardan
  geçtiğini kaydeder
- **Gizlenmiş saldırı tespiti**: kodlama altına saklanmış imzaları bulur
  (klasik WAF atlatma tekniği)
- **IOC çıkarımı**: IP, domain, URL, dosya yolu, hash, kabuk komutu, ters kabuk
- **Saldırı aracı parmak izi**: sqlmap, nikto, nmap, hydra, gobuster, ffuf,
  metasploit, wpscan — her tespit *gerekçesiyle* birlikte
- **MITRE ATT&CK / CWE / CAPEC eşlemesi** + Lockheed Martin Kill Chain konumu

**Faz 6 — Tehdit istihbaratı ve saldırgan profilleme** (`arachne/intel/`):
- **Davranışsal parmak izi**: servis tercihi, zamanlama ritmi (makine/insan
  ayrımı standart sapmayla), yük karakteri — IP adresi bilinçli olarak dışlanır
- **Kampanya korelasyonu**: aynı parmak izine sahip farklı IP'leri tek bir
  kampanya altında birleştirir
- **STIX 2.1 dışa aktarım**: bulgular MISP/OpenCTI/SIEM'lere aktarılabilir
  (çift kill-chain eşlemesi, resmi OASIS TLP marking ID'leri, ATT&CK/CWE bağlantıları)
- **Çevrimdışı IP kapsam sınıflandırması** — konum tahmini dürüstçe "tahmin"
  olarak etiketlenir, lab trafiği sahte bir ülkeye yerleştirilmez

**Faz 7 — SOAR otonom savunma orkestrasyonu** (`arachne/soar/`):
- **5 playbook**: TETİKLEYİCİ → ZENGİNLEŞTİRME → KARAR → EYLEM → KAPANIŞ
- **Gerçek yaptırım**: TTL'li engelleme listesi; engellenen IP'nin bağlantısı
  honeypot tarafından gerçekten reddedilir (veritabanı destekli, süreçler arası)
- **İnsan onay kapısı**: geri alınabilir eylemler otomatik, yıkıcı eylemler
  analist onayına yükseltilir
- **Lab güvenliği**: loopback ve özel ağ adresleri asla engellenemez
- Her otomatik karar gerekçesiyle denetim kaydına yazılır

**Faz 8 — Güvenli yapay zeka analist katmanı** (`arachne/ai/`):
- **Yerel analist**: ağ/API anahtarı gerektirmeden, yapısal veriden doğal dilde
  önceliklendirilmiş durum raporu (SITREP) üretir — her zaman çalışır
- **Karantina LLM** (opsiyonel): API anahtarı yalnızca ortam değişkeninden okunur
- **Prompt enjeksiyonu savunması**: Microsoft Research "Spotlighting" datamarking
  tekniği (arXiv 2403.14720) — ölçülmüş saldırı başarı oranını %50'den %3'ün
  altına indiren yöntem
- **Enjeksiyon denemesini tespite çevirme**: AI'ı manipüle etmeye çalışan
  saldırgan, bu davranışıyla yakalanır ve tehdit skoru yükselir
- **Katı çıktı şeması + HTML kaçışlama**: LLM çıktısı üzerinden XSS imkânsız
- Ele alınan OWASP LLM riskleri: LLM01, LLM05, LLM06, LLM07, LLM10
- **Taşıyıcı ilke: yapay zeka zenginleştirir, KARAR VERMEZ**

**Faz 9 — Dağıtık sensör ağı** (`arachne/mesh/`):
- Birden fazla sensör düğümü, merkezi toplayıcıya **HMAC-SHA256 imzalı** rapor gönderir
- **Tekrar oynatma koruması**: zaman damgası penceresi + nonce
- Sabit süreli imza karşılaştırması (timing attack'e karşı)
- Doğrulanmamış raporlar reddedilir *ve kaydedilir* — başarısız kimlik doğrulama
  denemesi bir güvenlik sinyalidir

**Faz 10 — Çelik Kubbe komuta merkezi** (`arachne/reporting/`):
- **Katmanlı savunma simülasyonu**: gelen her saldırı bir mermi, her savunma
  katmanı bir halka — çarptığı halka o kaydı *gerçekten işleyen* katmandır
- **Küresel saldırı haritası**: saldırgan kaynakları ve saldırı yayları
- **Canlı analiz laboratuvarı**: yükü yapıştır, tersine mühendislik sonucunu gör
- Canlı tehdit radarı, saldırı akışı terminali, alarm zaman çizelgesi,
  kritik alarmda ses + toast bildirimi

**Faz 11 — Aktif savunma & aldatma** (`arachne/active_defense/`):
- **Tarpit**: saldırganı kasıtlı yavaşlatarak zamanını harcar (uyarlanabilir)
- **Aldatma**: yüksek tehditli saldırgana sahte /etc/passwd, sahte kimlik,
  sahte "giriş başarılı" döner — gerçek hiçbir bilgi içermez
- ⚠️ "Misilleme" değil aktif savunma: başka sisteme saldırmaz, tüm eylemler
  kendi honeypot yüzeyimizde kalır (hack-back yoktur)

**Faz 12 — Honeytoken & canary tuzakları**:
- İzlenebilir sahte kimlikler (AWS/API/JWT/DB/canary URL); kullanıldığı an
  neredeyse kesin bir ihlal kanıtı (yanlış pozitif ~sıfır)

**Faz 13 — Gelişmiş kodlama çözücü**: ROT13, SQL CHAR(), JS fromCharCode,
gzip+base64, entropi analizi, polyglot tespiti

**Faz 14 — İmza kural motoru (YARA-benzeri)**: derlenen, açıklanabilir,
kendi kural dilimiz (`arachne/detection/rule_engine.py`)

**Faz 15 — İstatistiksel anomali & flood tespiti**: z-score tabanlı hacim
anomalisi + dağılım anomalisi (`arachne/detection/anomaly.py`)

**Faz 16 — Otomatik imza üretimi**: yakalanan saldırılardan yanlış-pozitif
kontrollü aday imzalar (`arachne/intel/signature_synth.py`)

**Faz 17 — Kurcalama-kanıtı denetim zinciri**: hash zinciri + Merkle kökü
(`arachne/integrity/`)

**Faz 18 — Çok faktörlü risk skorlama**: Risk = Olasılık × Etki, açıklanabilir
vektörle (`arachne/intel/risk_engine.py`)

**Faz 19 — Saldırı grafiği & kill chain modelleme**: yönlü graf, sonraki adım
tahmini, yatay hareket, doğal dilde anlatı (`arachne/intel/attack_graph.py`)

**Faz 20 — Yeniden tasarlanan komuta merkezi**: 8 temiz görünümlü tek-sayfa
uygulama (SPA), iki hızlı poll döngüsü, birleşik toplayıcı

### Faz 21-30 — Adaptif (ko-evrim) savunma (`arachne/adaptive/`)

> Saldırgan savunmayı gözleyip taktik değiştirirse, savunma da ona göre
> yeniden yapılanır. Statik duvar değil, saldırganla birlikte evrilen savunma.
> Tamamen savunma; hiçbir modül başka sisteme dokunmaz (hack-back yok).

- **Faz 21 — Düşük-ve-Yavaş tespiti** (`slow_detector.py`): CUSUM/EWMA + ritim
  düzenliliği; flood eşiğinin altında kalan sabırlı saldırganı yakalar
- **Faz 22 — Parmak izi & Sybil** (`fingerprint.py`): JA3/JA4 mantığı; tek
  aktörün çok kimlik gibi görünmesini altındaki parmak izinden yakalar
- **Faz 23 — Aldatma ağı & kırıntı yolu** (`deception_grid.py`): kademeli sahte
  düğümler; belirgin tuzaklardan kaçanı kırıntı yoluyla derine çeker
- **Faz 24 — Topluluk motoru** (`ensemble.py`): çok dedektör + k-of-N oylama;
  tek kuralı atlatmak sistemi atlatmaz
- **Faz 25 — Sıfır Güven politika motoru** (`zero_trust.py`): NIST SP 800-207
  PDP/PEP + mikrosegmentasyon
- **Faz 26 — Adaptif savunma duruşu** (`posture.py`): NORMAL→KRİTİK histerezisli
  durum makinesi; tehdide göre savunmaları açar/kapar
- **Faz 27 — Oyun-teorik savunma** (`game_theory.py`): Stackelberg oyunu +
  ko-evrim; MTD'nin biçimsel gerekçesi
- **Faz 28 — D3FEND & NIST CSF 2.0 kapsam haritası** (`coverage.py`): dört
  sütunlu eşleme (Faz → D3FEND → CSF → ATT&CK)
- **Faz 29 — Kolektif savunma** (`collective.py`): STIX/TAXII gösterge paylaşımı;
  bir sensör yakalar, tüm ağ bağışıklanır
- **Faz 30 — Genişletilmiş kubbe**: gök kubbe 5→14 halka (~2.8x) + "Adaptif
  Savunma" paneli

### Faz 31-40 — Yarışma sertleştirmesi (ölçülebilir SOC hattı)

> Katmanlı hat: Sensör → SIEM → Tehdit İstihbaratı → Signature/Behavior →
> AI Correlation → Risk → SOAR → Olay Sonrası. Başarı **gerçek benchmark
> verisiyle** kanıtlanır. Tamamen savunma.
>
> Tümü CANLI: motor + test + panel görünümü.

- **Faz 31 — Sensör sağlığı** (`mesh/health.py`): heartbeat, packet-loss, bütünlük
- **Faz 32-33 — SIEM + IOC grafiği** (`siem/normalizer.py`, `intel/correlation_graph.py`):
  varlık çıkarımı (ECS) + IOC→saldırgan→ATT&CK→kampanya→hedef, tıklanabilir grafik
- **Faz 34-35 — AI korelasyon + 9-aşama** (`intel/correlator.py`, `attack_stages.py`) + **Attack Replay oynatıcı**
- **Faz 36 — Açıklanabilir tersine mühendislik** (`reverse/explainer.py`): panelde neden+pattern+confidence+MITRE
- **Faz 37 — SOAR genişletme**: 9 playbook, 12 eylem (oturum sonlandırma, izolasyon, bildirim)
- **Faz 39 — Metrik motoru** (`metrics/evaluation.py`): Genel Bakış'ta Precision/Recall/F1/FPR/MTTD/MTTR/P95/events-sec
- **Faz 40 — Benchmark + uçtan-uca** (`benchmark/harness.py`, `demo_benchmark.py`, `demo_e2e.py`):
  ölçülen **F1 0.834 (sadece imza) → 0.976 (tam sistem), yanlış pozitif %0**
- **Canlı Akış**: gerçek varlık ilişki grafiği (her düğüm gerçek IP/servis/sensör, tıkla→ilişkiler)

### Faz 41-50 — İleri savunma + sinematik komuta merkezi + AI asistan

> Faz 41-44 gerçek, test edilmiş tespit motorlarıdır ve Çelik Kubbe'de kendi
> halkalarıyla temsil edilir (kubbe artık **18 halka**). Faz 45-50 komuta
> merkezinin görsel/işitsel/etkileşim katmanıdır. Tamamen savunma.

- **Faz 41 — C2 İşaret (Beacon) tespiti** (`adaptive/beacon.py`): periyodik
  geri-arama ritmini jitter/düzenlilikle yakalar
- **Faz 42 — Sıfır-gün sezgisi** (`adaptive/novelty.py`): karakter n-gram
  nadirliğiyle daha önce görülmemiş yükleri işaretler (leave-one-out)
- **Faz 43 — Bayes tehdit füzyonu** (`adaptive/threat_fusion.py`): bağımsız
  sinyalleri log-odds ile tek olasılığa birleştirir + faktör açıklaması
- **Faz 44 — İmkânsız seyahat** (`adaptive/geo_velocity.py`): aynı aktörün
  bölgeler arası fiziksel imkânsız hızını haversine ile yakalar
- **Faz 45-46 — Sinematik kubbe + harita** (`command_center.js`): atmosferik
  gökkubbe, dönen radar huzmesi, akan enerji, şok dalgaları, sonar darbeleri
- **Faz 47 — Ortak telsiz/SFX motoru** (`ArachneSFX`): nav/hover/onay/klakson
  sesleri, girişle aynı prosedürel Web Audio motoru
- **Faz 48 — AI Komuta Asistanı** (`ai/assistant.py`, `/api/assistant`):
  Türkçe doğal dil ile sorulur ("savunma durumu ne?"), GERÇEK veriden sesli
  yanıt; salt-okunur, harici LLM yok, deterministik
- **Faz 49 — Proaktif saldırı anonsu**: yeni saldırıda asistan otomatik
  profesyonel durum raporu verir (görsel kart + sesli anons + klakson)
- **Faz 50 — Sinematik yoğunluk katmanı** (`fx.js`): HUD çerçeve, telemetri
  şeridi, arka plan parçacık/ızgara/veri-yağmuru

**Ortak:**
- **Otomatik HTML raporu**, **AI Markdown raporu**, **STIX 2.1 bundle** ve
  **sinematik canlı komuta merkezi** (gerçek performans metrikleriyle)
- **546 birim testi** (`tests/`) ve kendi kendini test eden demo saldırı scriptleri

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Hızlı başlangıç (jüri/demo için önerilen)

Üç terminal açın (her terminalde önce `source .venv/bin/activate`):

```bash
# Terminal 1 — tüm katmanları başlat (Faz 1-20)
python main.py full-demo

# Terminal 2 — komuta merkezi
python main.py dashboard --port 5001    # -> http://127.0.0.1:5001
# (macOS'ta port 5000 AirPlay Receiver ile çakışır — bu yüzden 5001)

# Terminal 3 — küresel saldırı senaryosunu çalıştır
python scripts/demo_global_attack.py
python scripts/demo_mesh.py --collector http://127.0.0.1:5001/mesh/ingest
```

Sonra tarayıcıda paneli açın ve Çelik Kubbe'de mermilerin katmanlarda
durdurulmasını, haritada saldırı yaylarını, AI analistinin ürettiği durum
raporunu ve SOAR'ın otomatik engellemelerini izleyin.

## Tüm komutlar

```bash
# --- Faz 1: honeypot ---
python main.py run                     # sahte servisleri başlat
python scripts/demo_attack.py          # yerel saldırı simülasyonu
python main.py report                  # statik HTML rapor -> data/report.html
python main.py dashboard               # canlı komuta merkezi

# --- Faz 2: WAF, tarayıcı, ML ---
python main.py waf-demo                # WAF-korumalı demo uygulaması (:8090)
python main.py waf-demo --unprotected  # karşılaştırma için WAF'sız
python scripts/demo_waf_attack.py      # WAF'ı gerçek saldırılarla test et
python main.py scan --host 127.0.0.1   # otonom port/zafiyet taraması
python main.py train-ml                # ML sınıflandırıcısını yeniden eğit

# --- Faz 3: native ARM64 (Apple Silicon) ---
cd arachne/native/arm64 && make && cd ../../..
python3 scripts/benchmark_native_scan.py   # dürüst kıyaslama

# --- Faz 4: Moving Target Defense ---
python main.py mtd-demo

# --- Faz 5: saldırı tersine mühendisliği ---
python main.py analyze --payload "id=1' OR 1=1--"
python main.py analyze --payload "JyBPUiAnMSc9JzE%3D"   # gizlenmiş SQLi

# --- Faz 6: tehdit istihbaratı ---
python main.py stix-export             # -> data/stix_bundle.json

# --- Faz 7: SOAR otonom müdahale ---
python main.py soar-demo               # honeypot + gerçek otomatik engelleme

# --- Faz 8: AI analist ---
python main.py ai-report               # -> data/ai_report.md

# --- Faz 9: dağıtık sensör ağı ---
python main.py mesh-demo               # (panel çalışırken)

# --- Faz 10: tam sistem ---
python main.py full-demo
python scripts/demo_global_attack.py
```

## Yapay zeka katmanını yapılandırma (opsiyonel)

Sistem dil modeli **olmadan da tam çalışır** — yerel analist her zaman devrededir.
Karantina LLM'i etkinleştirmek isterseniz:

```bash
export ARACHNE_LLM_ENABLED=1
export ARACHNE_LLM_API_KEY="anahtarınız"        # asla koda/dosyaya yazılmaz
export ARACHNE_LLM_MODEL="gpt-4o-mini"          # opsiyonel
export ARACHNE_LLM_ENDPOINT="https://..."       # opsiyonel (yerel model de olur)
```

Sensör ağı için paylaşılan sırrı değiştirin (üretimde zorunlu):

```bash
export ARACHNE_MESH_SECRET="uzun-rastgele-bir-sir"
```

## Testler

```bash
pip install pytest
pytest tests/ -v      # 387 test
```

## Mimari ve yol haritası

- Mimari detayları ve tasarım kararları: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Faz faz gelişim planı: [docs/ROADMAP.md](docs/ROADMAP.md)
- Etik/yasal kullanım notu: [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md)

## Proje ekibi

Bu proje, Topkapı Üniversitesi Bilgi Güvenliği Teknolojisi öğrencileri
tarafından ortak bir portföy/yarışma projesi olarak geliştirilmektedir.

## Lisans

MIT — bkz. [LICENSE](LICENSE)
