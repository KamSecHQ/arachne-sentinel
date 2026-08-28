# Container Dağıtımı (Faz 105)

> ⚠️ **Bu belge [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md)'nin bir uzantısıdır,
> yerine geçmez.** Container'lar honeypot portlarını gerçek bir ağa (host
> makinenin ağına) açar. **Sadece kendi sahip olduğunuz veya izole bir
> lab/VM ağında** çalıştırın — hiçbir zaman genel internete veya başkasına
> ait bir ağa doğrudan maruz bırakmayın.

## Neden container?

Faz 1-103 boyunca proje bilinçli olarak "iki-üç terminal aç, `source
.venv/bin/activate`, `python main.py ...`" akışını kullandı — bu, geliştirme
ve jüri sunumu için yeterliydi. Faz 105, aynı sistemi **tek komutla,
tekrarlanabilir** şekilde ayağa kaldırmayı ekliyor (TÜBİTAK/Teknopark
değerlendiricilerinin kendi makinelerinde hızlıca deneyebilmesi için) —
kod tabanına **hiçbir yeni pip bağımlılığı eklemeden** (bkz. `Dockerfile`,
`requirements.txt` değişmedi).

## Docker kurulu değilse (macOS)

Docker Desktop yerine hafif, ücretsiz bir alternatif olan
[Colima](https://github.com/abiosoft/colima) kullanılabilir — bu proje
Faz 105'te tam olarak bu şekilde uçtan uca test edildi:

```bash
brew install colima docker docker-compose
mkdir -p ~/.docker && echo '{"cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins"]}' > ~/.docker/config.json
colima start --cpu 2 --memory 4 --disk 20
```

Durdurmak için: `colima stop` (veriler `docker volume` içinde kalıcı kalır).

## Hızlı başlangıç

```bash
docker compose build

# (Opsiyonel ama önerilir) Müşteri kimlik/iletişim profilinizi girin -
# bkz. docs/INTEGRATION.md. Konteynerler henüz ayakta olmasa da çalışır,
# çünkü profil paylaşılan `arachne_data` volume'una yazılır.
docker compose run --rm dashboard onboard

docker compose up -d
```

Ardından:

```bash
curl http://localhost:5001/api/state   # canli durum JSON'i
```

Tarayıcıda: `http://localhost:5001`

Durdurmak için:

```bash
docker compose down
```

## Mimari

İki servis, aynı `data/` named volume'unu (SQLite veritabanı) paylaşır —
bu, projenin var olan çok-süreçli mimarisinin (`storage.py`'nin
`db_path=None` → `config.DB_PATH` fallback'i, Faz 7'nin "honeypot ve panel
ayrı süreçlerde çalışır" notu) doğal bir uzantısıdır:

- **`honeypot`** — `python main.py full-demo` (Faz 1-102 tüm sahte
  servisler + MTD + SOAR + honeytoken).
- **`dashboard`** — `python main.py dashboard --port 5001 --no-open`
  (canlı komuta merkezi; `--no-open` çünkü container içinde tarayıcı yok).

## Port haritası

| Host portu | Servis | Faz |
|---|---|---|
| 5001 | Komuta merkezi (HTTP) | 20 |
| 2222 | Sahte SSH | 1 |
| 2121 | Sahte FTP | 1 |
| 3307 | Sahte MySQL | 1 |
| 8081 | Sahte HTTP admin paneli | 1 |
| 2323 | Sahte Telnet | 103 |
| 6380 | Sahte Redis | 103 |
| 2375 | Sahte Docker API | 103 |
| 9200 | Sahte Elasticsearch | 103 |
| 3389 | Sahte RDP (minimal — bkz. ROADMAP dürüstlük notu) | 103 |
| 4450 | Sahte SMB (minimal — bkz. ROADMAP dürüstlük notu) | 103 |
| 5300/udp | Hayalet DNS (**gerçek sistem DNS'i DEĞİL**) | 4 |

## Opsiyonel dış kaynaklar

Faz 102/104/107'nin tüm dış-kaynak özellikleri (tehdit istihbaratı, NVD CVE
zenginleştirmesi, karantina LLM, canlı syslog iletimi) **varsayılan olarak
kapalıdır**. Açmak isterseniz, repo kökünde bir `.env` dosyası oluşturup
`docker-compose.yml`'in zaten geçtiği değişkenleri doldurun:

```bash
# .env (repo kökünde, git'e eklemeyin)
ARACHNE_THREAT_INTEL_ENABLED=1
ARACHNE_ABUSEIPDB_API_KEY=sizin-anahtariniz
ARACHNE_NVD_ENABLED=1
```

Doldurulmadıkları sürece sistem hiçbir şey kaybetmeden, tamamen kendi
deterministik motoruyla çalışır (bkz. `arachne/ai/llm_backend.py` ve
`arachne/intel/threat_intel.py`'deki "güvenli varsayılan" ilkesi).

## Veri kalıcılığı

`arachne_data` named volume'u, konteynerler yeniden başlatılsa/güncellense
bile SQLite veritabanını (`data/arachne.db`), ML modelini ve kurcalama-kanıtı
denetim zincirini korur. Tamamen sıfırdan başlamak için:

```bash
docker compose down -v   # DIKKAT: named volume'u da siler, veri kaybolur
```

## Container içinde testleri çalıştırma

```bash
docker compose run --rm dashboard sh -c "pip install pytest && pytest tests/ -v"
```

## Bilinen sınırlama

Faz 3'ün elle yazılmış ARM64 assembly imza tarama çekirdeği (`arachne/native/`)
bu imajda **derlenmez** — konteyner platformu (genelde x86-64 Linux) Apple
Silicon değildir. Sistem bunu otomatik algılar ve sessizce Python yedeğine
düşer; davranış hiçbir zaman değişmez, sadece hız (bkz.
`arachne/native/README.md`).
