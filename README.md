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

## Özellikler (v0.1)

- **4 sahte servis**: SSH, FTP, MySQL, HTTP "admin panel" (`arachne/honeypot/`)
- **SQLite tabanlı olay/alarm günlüğü** (`arachne/storage.py`)
- **Açıklanabilir kural motoru** (`arachne/detection/`): port taraması,
  brute-force, bilinen SQLi/XSS/command-injection/path-traversal imzaları,
  çoklu servis keşfi, tekrarlayan saldırgan tespiti
- **Otomatik HTML raporu** ve **canlı web paneli** (`arachne/reporting/`)
- **13 birim testi** (`tests/`) ve kendi kendini test eden bir demo saldırı
  scripti (`scripts/demo_attack.py`)

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
