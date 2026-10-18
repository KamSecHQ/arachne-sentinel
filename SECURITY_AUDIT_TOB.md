# Güvenlik Denetimi — Arachne Sentinel (Trail of Bits skill'leri)

**Tarih:** 2026-10-18
**Kapsam:** `arachne/`, `website/` ve dağıtım dosyaları (`docker-compose.yml`, `requirements.txt`) — salt denetim, hiçbir kod değiştirilmedi.
**Metodoloji:** Trail of Bits `insecure-defaults`, `sharp-edges` ve `supply-chain-risk-auditor` plugin'lerinin referans korpusu (desen kataloğu) koda `grep` + manuel izleme ile uygulandı.

## Metodoloji ve sınırlar (dürüst kapsam beyanı)

Trail of Bits marketplace'i (`trailofbits/skills`) diske klonlanmış ve 11 plugin `settings.json` içinde etkin. Ancak plugin'ler bu oturumda çağrılabilir slash-komut/skill olarak **yüklenmedi**; ayrıca:

- `insecure-defaults:audit` komutu, bu oturumda bulunmayan bir `Workflow` aracına bağlıdır.
- `supply-chain-risk-auditor` sürüm-eşleşmeli CVE taraması için `collect.py`/`render.py` + ağ erişimi ister; bu snapshot'ta `scripts/` yok ve ağ taraması yapılmadı.

Bu nedenle denetim, her plugin'in **referans desen kataloğunu** (ör. `fallback-secrets.md`, `weak-crypto.md`, `lang-python.md`) okuyup kodda birebir uygulayarak yürütüldü. Bu, insecure-defaults ve sharp-edges için denetimin asıl özüdür. **Supply-chain tarafında**, bağımlılıkların sürüm-eşleşmeli advisory/CVE taraması YAPILMADI; aşağıdaki supply-chain bulguları yalnızca manifest yapısına (sabitleme, lockfile, kaynak) dayanır — "bulgu yok" ifadesi advisory yokluğu anlamına gelmez.

---

## Özet tablo

| # | Önem | Başlık | Konum |
|---|------|--------|-------|
| 1 | **Yüksek** | Mesh paylaşılan sırrı herkese açık varsayılana (`DEFAULT_LAB_SECRET`) düşüyor; `/mesh/ingest` panel-auth'tan muaf ve Docker'da 0.0.0.0:5001'de erişilebilir | `arachne/mesh/crypto.py:49`, `docker-compose.yml` |
| 2 | **Orta** | Kontrol düzlemi (dashboard 5001) Docker'da host'ta 0.0.0.0'a açık; website 127.0.0.1'e sabitlenmişken dashboard değil | `docker-compose.yml` (dashboard servisi) |
| 3 | **Orta** | ML/anomali modelleri `joblib.load` (pickle) ile yükleniyor — `data/` yazılabilirse kod çalıştırma | `arachne/detection/ml_classifier.py:77`, `arachne/detection/anomaly_ml.py:98` |
| 4 | **Orta** | Bağımlılıklar sabitlenmemiş (`>=` aralıkları), lockfile yok — tekrarlanabilir olmayan/otomatik yükseltilen tedarik zinciri | `requirements.txt` |
| 5 | **Düşük** | `/mesh/ingest` üzerinde IP başına hız sınırı yok; başarısız doğrulama her istekte DB'ye yazıyor — kimlik doğrulamasız disk-dolum/log-taşma DoS | `arachne/mesh/collector.py:82` |
| 6 | **Düşük** | Auth muafiyeti `path.startswith("/mesh/ingest")` önek eşleşmesi — `/mesh/ingestXYZ` gibi yollar da muaf | `arachne/reporting/panel_auth.py:40` |

**Doğrulanan iyi uygulamalar (bulgu değil):** panel anahtarı `hmac.compare_digest` ile sabit-süreli; panel-auth varsayılan AÇIK; token dosyası `0600` + `O_EXCL`; oturum çerezi HttpOnly + SameSite=Strict; güvenlik başlıkları; Flask `debug=False` (her yerde); `secrets` modülü (nonce/token); SQL tamamen parametreli (`?`), enjeksiyon yok; `eval/exec/shell=True/yaml.load` kullanımı yok; Iyzico ödeme varsayılan KAPALI + varsayılan SANDBOX + anahtarlar sızdırılmıyor + callback sunucu tarafında yeniden doğrulanıyor; HOTP'te SHA-1 RFC 4226 gereği HMAC-SHA1'dir (zafiyet değil).

---

## Bulgular

### 1 — [Yüksek] Mesh paylaşılan sırrı açık-kaynak varsayılana düşüyor; imzasız SOAR silahlandırma riski

**Konum:** `arachne/mesh/crypto.py:44-49`, `docker-compose.yml` (dashboard + ortak ortam), `arachne/reporting/panel_auth.py:40`, `arachne/reporting/dashboard.py:57-58`, `arachne/mesh/collector.py:82`

**Ne:**
```python
# arachne/mesh/crypto.py
DEFAULT_LAB_SECRET = "arachne-lab-shared-secret-degistirin"   # depoda açık
def get_shared_secret() -> str:
    return os.environ.get(ENV_SHARED_SECRET) or DEFAULT_LAB_SECRET
```
`ARACHNE_MESH_SECRET` ayarlı değilse (veya `docker-compose.yml`'deki `${ARACHNE_MESH_SECRET:-}` ile boş string ise), mesh mesaj kimlik doğrulaması herkese açık, depoda yazılı bir sırla yapılır. Üç koşul birleşiyor:

1. `/mesh/ingest` blueprint'i dashboard uygulamasına kayıtlı (`dashboard.py:58`).
2. `/mesh/ingest`, panel kimlik doğrulamasından **muaf** (`panel_auth.py:40`, "kendi HMAC'i var" gerekçesiyle) — tek koruması mesh HMAC'i.
3. Docker'da dashboard `0.0.0.0:5001`'de host'a açık (bkz. Bulgu 2).

**Neden önemli:** `crypto.py` modül başlığının kendisinin uyardığı senaryo gerçekleşebilir hale geliyor: varsayılan sırrı bilen (depoyu okuyan) herkes geçerli imzalı sahte sensör raporları üretip `/mesh/ingest`'e gönderebilir. Bu raporlar `storage.log_event` ile gerçek olaylar gibi kaydedilir; aşağı akıştaki SOAR/istihbarat katmanı bunları gerçek saldırı sayıp masum IP'leri otomatik engelleyebilir — "kimlik doğrulamasız SOAR saldırganın elinde silaha dönüşür". `using_default_secret()` yalnızca `/mesh/status` içinde bilgi amaçlı gösterilir (`collector.py:194`); uç nokta yine de varsayılan sırla imzalanmış mesajları **kabul etmeye devam eder**.

**Düzeltme önerisi:**
- Varsayılan sırrı tamamen kaldırıp, sır yoksa `/mesh/ingest`'i devre dışı bırakın (fail-secure): `get_shared_secret()` sır yoksa `None` döndürsün; `verify_message` sır `None` ise her mesajı reddetsin ve collector açılışta "mesh devre dışı: ARACHNE_MESH_SECRET ayarlı değil" uyarısı versin. Panel anahtarı dosyası (`panel_auth.panel_token`) için zaten kullanılan "yoksa `0600` ile rastgele üret" deseni mesh sırrı için de uygulanabilir (`data/mesh_secret`).
- En azından: `using_default_secret()` doğruysa `/mesh/ingest` 403 dönsün; bilgi amaçlı bayrak yeterli değil.

---

### 2 — [Orta] Dashboard kontrol düzlemi Docker'da 0.0.0.0'a açık

**Konum:** `docker-compose.yml` — `dashboard` servisi

**Ne:**
```yaml
dashboard:
  command: ["dashboard", "--host", "0.0.0.0", "--port", "5001", "--no-open"]
  ports:
    - "5001:5001"        # host'ta 0.0.0.0'a bağlanır
website:
  ports:
    - "127.0.0.1:8088:8088"   # bilinçli olarak localhost'a sabit
```
Website servisinin yorumu, Docker'ın UFW/iptables kurallarını kendi DOCKER zinciriyle atlayabildiğini doğru biçimde açıklayıp portu `127.0.0.1`'e sabitliyor. Dashboard servisi aynı önlemi **almıyor** — `5001:5001` host'un tüm arayüzlerine açılır.

**Neden önemli:** Dashboard, komuta merkezidir (tüm istihbarat, Son Hat tatbikat/bekleme, analiz, asistan uç noktaları). Panel-auth varsayılan açık olduğu için kimlik doğrulama vardır; ancak (a) kontrol düzleminin ağa bakması derinlemesine savunma ilkesine aykırı, (b) auth'tan muaf `/mesh/ingest` dışarı bakar hale gelir (bkz. Bulgu 1). Docker+UFW atlaması nedeniyle host'taki güvenlik duvarı bunu beklendiği gibi engellemeyebilir.

**Düzeltme önerisi:** Dashboard portunu website gibi localhost'a sabitleyin — `ports: ["127.0.0.1:5001:5001"]` — ve erişimi TLS sonlandıran bir reverse proxy (Caddy/Nginx) + kimlik doğrulama arkasına alın. `--host 0.0.0.0` container içinde kalabilir; host yayını `127.0.0.1`'e sınırlanmalı.

---

### 3 — [Orta] ML modelleri pickle (`joblib.load`) ile yükleniyor

**Konum:** `arachne/detection/ml_classifier.py:77`, `arachne/detection/anomaly_ml.py:98`

**Ne:**
```python
candidate = joblib.load(config.ML_MODEL_PATH)   # data/*.joblib
```
`joblib.load` özünde `pickle` kullanır; pickle çözümleme güvenilmeyen veride rastgele kod çalıştırır (`sharp-edges/lang-python.md`: "pickle.loads — deserialization RCE").

**Neden önemli — ve neden Kritik DEĞİL:** Model dosyaları `data/` içinde yereldir ve `.gitignore`'da (`data/*.joblib`) — yani depoda dağıtılmaz, `_fit_pipeline()` ile yerel olarak üretilir. Dolayısıyla ağ üzerinden saldırgan-kontrollü değiller. Gerçek risk: `data/` dizinine yazabilen bir aktör (Docker'daki paylaşılan `arachne_data` volume, düşük yetkili yerel kullanıcı veya `data/`'ya ulaşan bir yol-geçişi) zararlı bir `.joblib` bırakırsa, bir sonraki yükleme kod çalıştırır. Bu bir honeypot platformu olduğundan, `data/` yazımına ulaşan herhangi bir yol doğrudan RCE'ye yükselir.

**Düzeltme önerisi:**
- Model dosyalarının bütünlüğünü yükleme öncesi doğrulayın: dosyayı bilinen bir SHA-256 ile (ayrı, yazılamaz bir konumda tutulan) karşılaştırın; uyuşmazsa yüklemeyi reddedip yeniden eğitin.
- `data/` model dizinini mümkün olan en dar izinle (`0700`/`0600`) ve uygulama kullanıcısına ait tutun; Docker volume'ünü dashboard için salt-okunur bağlamayı değerlendirin.
- Uzun vadede pickle'dan kaçının: modeli pickle olmayan bir formatta (ör. `skops`, veya özniteliklerin JSON serisi) saklayın; bu sınıf kod ekibin kontrolünde olduğundan `_model_is_usable` zaten yeniden-eğitim yedeğine sahip.

---

### 4 — [Orta] Bağımlılıklar sabitlenmemiş, lockfile yok

**Konum:** `requirements.txt`

**Ne:** Tüm doğrudan bağımlılıklar kayan alt-sınır aralıklarıyla belirtilmiş: `flask>=3.0`, `scikit-learn>=1.4`, `joblib>=1.3`, `iyzipay>=1.0.46`, `pywebview>=5.0`, `pyobjc-*>=10.0`. `uv.lock`/`pyproject.toml`/hash-sabitleme yok.

**Neden önemli:** `>=` aralıkları, her kurulumda farklı (ve o an mevcut en yeni) sürümleri — geçişli bağımlılıklar dahil — çeker. Bu (a) kurulumları tekrarlanamaz kılar, (b) ele geçirilmiş veya kırıcı bir upstream sürümünü hiçbir onay olmadan otomatik getirir. `scikit-learn`/`joblib` büyük geçişli ağaçlar (numpy, scipy, threadpoolctl) getirir; `iyzipay` gerçek-para yoluna dokunan üçüncü-taraf bir SDK'dır.

**Düzeltme önerisi:**
- Tam sürüm sabitleyin ve bir lockfile üretin (`uv lock` / `pip-compile`); mümkünse hash-sabitleme (`--require-hashes`) kullanın.
- Üretim imajında `pip install --require-hashes -r requirements.lock` benzeri doğrulanmış kurulum kullanın.
- Ayrı bir çalışmada bağımlılıkların sürüm-eşleşmeli advisory taraması yapın (bu denetimde YAPILMADI): `pip-audit` veya ToB supply-chain `collect.py` (ağ erişimiyle).

---

### 5 — [Düşük] `/mesh/ingest`'te hız sınırı yok; başarısız doğrulama DB'ye yazıyor

**Konum:** `arachne/mesh/collector.py:82-108`

**Ne:** `ingest()` her isteği işler; rapor başına olay sayısı 200 ile sınırlı (`MAX_EVENTS_PER_REPORT`) ancak **istek frekansı** için IP başına sınır yok. Her başarısız doğrulama `storage.log_mesh_event(..., status="reddedildi", ...)` ile bir DB satırı yazar (bilinçli: "başarısız kimlik doğrulama bir sinyaldir").

**Neden önemli:** Kimlik doğrulamasız bir istemci, geçersiz zarflarla `/mesh/ingest`'i sel edebilir; her istek bir DB yazımı tetikler → ortak SQLite veritabanında disk-dolum / yazma amplifikasyonu ve panel yavaşlaması (DoS). Panel giriş yolundaki (`panel_auth._locked_out`) IP-başına hız sınırının muadili burada yok.

**Düzeltme önerisi:** `/mesh/ingest`'e IP başına hız sınırı ekleyin (panel-auth'taki `_locked_out`/`_record_failure` deseni yeniden kullanılabilir). Başarısız doğrulama kayıtlarını pencere başına toparlayıp (rate-limited/aggregated) yazın; her reddi ayrı satır yapmaktan kaçının.

---

### 6 — [Düşük] Auth muafiyeti önek eşleşmesi çok geniş

**Konum:** `arachne/reporting/panel_auth.py:40,168`

**Ne:**
```python
EXEMPT_PREFIXES = ("/static/", "/mesh/ingest")
...
if path in EXEMPT_PATHS or path.startswith(EXEMPT_PREFIXES):
    return None
```
`startswith` önek eşleşmesi olduğundan `/mesh/ingest` yalnızca tam yolu değil, `/mesh/ingestentele`, `/mesh/ingest-x` gibi onunla başlayan her yolu da panel-auth'tan muaf tutar.

**Neden önemli:** Bugün böyle bir rota kayıtlı değil (`collector.py` yalnızca tam `/mesh/ingest` tanımlar), dolayısıyla şu an sömürülebilir bir yol yok. Ancak gelecekte `/mesh/ingest-config` gibi bir rota eklenirse, sessizce kimlik-doğrulamasız açılır — tipik bir "sharp edge" (yanlış kullanıma davetkâr tasarım). `/static/` için werkzeug yolu normalize ettiğinden pratik risk düşüktür.

**Düzeltme önerisi:** `/mesh/ingest` için tam-yol eşleşmesi kullanın (`EXEMPT_PATHS`'e taşıyın) ya da önek gerekiyorsa sonuna `/` koyun ve rota adlandırmasını buna göre sabitleyin. Muafiyetleri önek yerine açık rota-adı listesiyle yönetmek daha güvenlidir.

---

## Sonuç

Kod tabanı, güvenlik duyarlılığı yüksek bir ekip işi izlenimi veriyor: sabit-süreli karşılaştırma, güvenli çerezler, `secrets` kullanımı, parametreli SQL, `debug=False`, ödeme yolunda güvenli varsayılanlar ve sunucu-tarafı doğrulama. `eval/exec/shell=True/yaml.load` gibi klasik footgun'lar yok.

Öncelik sırası:
1. **Bulgu 1'i** (varsayılan mesh sırrı + auth-muaf, dışa bakan `/mesh/ingest`) kapatın — tek gerçek "Yüksek" ve projenin kendi tehdit modelinin (SOAR silahlandırma) tam karşılığı. Bulgu 2 ile birlikte ele alın.
2. **Bulgu 2 ve 3** — dağıtım sertleştirmesi (dashboard'u localhost'a sabitle, model bütünlüğü/izinler).
3. **Bulgu 4** — bağımlılık sabitleme + ayrı bir advisory taraması (bu denetimde çalıştırılmadı).
4. **Bulgu 5–6** — sağlamlaştırma.

**Hatırlatma:** Supply-chain tarafında sürüm-eşleşmeli CVE/advisory taraması yapılmadı; "advisory bulgusu yok" denememesi bu yüzden. Bulgu 4'teki `pip-audit`/ToB collector adımı ayrı çalıştırılmalı.
