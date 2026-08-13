# 🕸 Arachne Sentinel

Honeypot tabanlı, kural motoruyla çalışan bir **erken uyarı ve saldırı tespit
sistemi**. Sahte servisler (SSH, FTP, MySQL, bir "yönetici paneli") açar,
bunlara yapılan her bağlantı ve etkileşimi kaydeder, saldırgan davranış
kalıplarını (port taraması, brute-force, bilinen saldırı imzaları, çoklu
servis keşfi) tespit edip **açıklanabilir** (explainable) bir tehdit skoru
üretir ve otomatik bir saldırı raporu / canlı panel sunar.

> ⚠️ **Sadece kendi sahip olduğunuz veya test izniniz olan, izole/lab
> ortamlarında çalıştırın.** Detaylar için [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md)
> dosyasına bakın.

## Neden bu proje?

Bu, gerçek dünyadaki savunma amaçlı güvenlik ürünlerinin (honeypot/deception
teknolojisi, IDS, WAF) küçük ölçekli ama **gerçekten çalışan** bir versiyonu
olarak tasarlandı. Amaç büyük iddialarla değil, ölçülebilir ve savunulabilir
sonuçlarla dikkat çekmek — her alarmın *neden* verildiği açıkça görülebilir.

## Özellikler

**Faz 1 — Honeypot ve tespit motoru:**
- **4 sahte servis**: SSH, FTP, MySQL, HTTP "admin panel" (`arachne/honeypot/`)
- **SQLite tabanlı olay/alarm günlüğü** (`arachne/storage.py`)
- **Açıklanabilir kural motoru** (`arachne/detection/`): port taraması,
  brute-force, bilinen SQLi/XSS/command-injection/path-traversal imzaları,
  çoklu servis keşfi, tekrarlayan saldırgan tespiti

**Faz 2 — WAF, otonom tarayıcı ve ML sınıflandırıcı:**
- **WAF katmanı** (`arachne/waf/`): herhangi bir WSGI uygulamasının önüne
  konabilen, regex tabanlı imza motoru + rate-limiting içeren middleware;
  bilinçli olarak zafiyetli, tamamen yerel bir demo uygulaması ile birlikte
  gelir (`arachne/waf/demo_app.py`)
- **Otonom zafiyet tarayıcı** (`arachne/scanner/`): bağımsız port tarama +
  banner grabbing + bilinen zafiyet eşleştirme
- **ML tabanlı saldırı sınıflandırıcısı** (`arachne/detection/ml_classifier.py`):
  TF-IDF + Logistic Regression ile, kural motoruna ek bir sinyal olarak
  çalışan, hafif obfuske edilmiş varyasyonları da yakalayabilen bir model

**Faz 3 — Native ARM64 assembly imza tarama çekirdeği:**
- Honeypot kural motorunun kullandığı imza taramasının çekirdeği, elle
  yazılmış **ARM64 assembly** ile (`arachne/native/arm64/fast_scan.s`) —
  Apple Silicon (M-serisi) Mac'lerde native çalışır, diğer platformlarda
  otomatik olarak birebir aynı sonucu üreten bir Python yedeğine düşer
- Projeden bağımsız, tek başına çalışan bir native CLI aracı
  (`arachne/native/tools/byte_inspector.s`)
- Detaylar ve dürüst kıyaslama: [arachne/native/README.md](arachne/native/README.md)

**Ortak:**
- **Otomatik HTML raporu** (honeypot + WAF + tarama bulgularını tek sayfada
  birleştirir) ve **canlı web paneli** (`arachne/reporting/`)
- **39 birim testi** (`tests/`) ve kendi kendini test eden demo saldırı
  scriptleri (`scripts/`)

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Kullanım

```bash
# 1) Honeypot servislerini başlat (ayrı bir terminalde açık bırakın)
python main.py run

# 2) Sistemi test etmek için sahte bir saldırı simülasyonu çalıştırın
python scripts/demo_attack.py

# 3) Statik bir HTML rapor üretin
python main.py report          # -> data/report.html

# 4) Ya da canlı paneli açın
python main.py dashboard        # -> http://127.0.0.1:5000

# 5) WAF-korumalı demo web uygulamasını başlatın (ayrı bir terminalde)
python main.py waf-demo         # -> http://127.0.0.1:8090
# Karşılaştırma için WAF'sız versiyonu deneyin:
python main.py waf-demo --unprotected

# 6) WAF'ı gerçek saldırılarla test edin
python scripts/demo_waf_attack.py

# 7) Otonom port/zafiyet taraması yapın
python main.py scan --host 127.0.0.1

# 8) ML sınıflandırıcısını yeniden eğitin (opsiyonel, ilk kullanımda otomatik eğitilir)
python main.py train-ml

# 9) (Apple Silicon Mac) Native ARM64 assembly imza tarama çekirdeğini derleyin
cd arachne/native/arm64 && make && cd ../../..
python3 -c "from arachne.native import signature_engine as s; print(s.engine_status())"

# 10) Native vs Python dürüst kıyaslaması
python3 scripts/benchmark_native_scan.py
```

## Testler

```bash
pip install pytest
pytest tests/ -v
```

## Mimari ve yol haritası

- Mimari detayları ve tasarım kararları: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 1 yıllık ve 4 yıllık genişleme planı: [docs/ROADMAP.md](docs/ROADMAP.md)
- Etik/yasal kullanım notu: [docs/ETHICS_AND_LEGAL.md](docs/ETHICS_AND_LEGAL.md)

## Proje ekibi

Bu proje, Topkapı Üniversitesi Bilgi Güvenliği Teknolojisi öğrencileri
tarafından ortak bir portföy/yarışma projesi olarak geliştirilmektedir.

## Lisans

MIT — bkz. [LICENSE](LICENSE)
