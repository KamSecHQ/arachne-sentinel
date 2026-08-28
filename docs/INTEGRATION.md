# Entegrasyon Kılavuzu (Faz 110)

> Bu kılavuz, Arachne Sentinel'i **kendi web sitenize/altyapınıza** entegre
> etmek isteyen bir müşteri için yazılmıştır. Sadece izole/kendi
> sahip olduğunuz bir ortamda kullanın — bkz.
> [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md).

## Mimari: neden self-hosted?

Arachne Sentinel'i entegre ettiğinizde, **sistem tamamen kendi
altyapınızda çalışır** — bize (ya da başka bir üçüncü tarafa) hiçbir veri
gitmez. Bu bilinçli bir tercih:

- Saldırgan verileri, honeypot yakalamaları, WAF logları sizin
  kontrolünüzdeki veritabanında kalır.
- Opsiyonel dış-kaynak özellikler (tehdit istihbaratı, NVD, karantina LLM —
  bkz. [ETHICS_AND_LEGAL.md](ETHICS_AND_LEGAL.md)) varsayılan olarak
  kapalıdır; siz açmadıkça hiçbir dış çağrı yapılmaz.
- Tek dışa giden bağlantı (varsa) **sizin yapılandırdığınız alarm
  webhook'unuzdur** — bkz. Adım 4.

## Adım 1 — Kurulum sihirbazı

```bash
python main.py onboard
```

Sizden **sadece kimlik/iletişim bilgisi** ister: şirket adı, korunan
varlığın adı, alarm için e-posta/webhook. **Gerçek şifre, API anahtarı ya
da veritabanı bağlantı dizesi girmeyin** — bu bir honeypot/aldatma
sistemidir, gerçek sır saklamak için tasarlanmamıştır (bkz.
`arachne/customer/profile.py` docstring'i). Sihirbaz, yanlışlıkla gerçek
bir sır girerseniz bunu tespit edip reddeder.

Bilgiler `data/customer_profile.json` dosyasına yazılır. Bu dosyayı elle de
düzenleyebilir ya da `ARACHNE_CUSTOMER_PROFILE` ortam değişkeniyle farklı
bir konuma yönlendirebilirsiniz (örn. bir Docker volume'u).

## Adım 2 — Platformu ayağa kaldırma

```bash
docker compose up -d
```

Detaylar: [DEPLOYMENT.md](DEPLOYMENT.md). Docker istemiyorsanız
`python main.py full-demo` + `python main.py dashboard --port 5001` ile
aynı şeyi çıplak Python ile de yapabilirsiniz.

## Adım 3 — WAF'ı kendi web uygulamanızın önüne koyma

`arachne/waf/middleware.py`'deki `WAFMiddleware`, **herhangi bir WSGI
uygulamasının** önüne konabilen, framework'ten bağımsız bir istek
filtresidir. Kendi uygulama kodunuzu değiştirmeniz gerekmez — tek satır.

**Flask:**
```python
from arachne.waf.middleware import WAFMiddleware

app = Flask(__name__)
app.wsgi_app = WAFMiddleware(app.wsgi_app, db_path="data/arachne.db")
```

**Django** (`wsgi.py`):
```python
from arachne.waf.middleware import WAFMiddleware

application = get_wsgi_application()
application = WAFMiddleware(application, db_path="data/arachne.db")
```

**Herhangi bir WSGI uygulaması (FastAPI/Starlette dahil, ASGI için bir
WSGI-uyumluluk katmanı gerekir):**
```python
application = WAFMiddleware(application)
```

`block_threshold` (varsayılan 50) parametresiyle hassasiyeti
ayarlayabilirsiniz — düşürmek daha agresif engeller (yanlış-pozitif riski
artar), yükseltmek daha toleranslıdır.

## Adım 4 — Sahte servisleri (honeypot) yerleştirme (opsiyonel ama önerilir)

Gerçek servislerinizin **kullanılmayan** portlarında honeypot'ları
çalıştırmak, saldırganları gerçek sisteminize ulaşmadan yakalamanın en
etkili yoludur. `arachne/config.py`'deki `FAKE_SERVICES` sözlüğünü kendi
ortamınıza göre düzenleyip `python main.py run` (ya da `full-demo`) ile
başlatın. Hangi servisleri taklit edeceğinizi seçerken **gerçekten
kullanmadığınız** portları/servisleri tercih edin (port çakışması olmasın).

## Adım 5 — Kritik olay bildirimlerini bağlama

Kurulum sihirbazında bir `alert_webhook_url` girdiyseniz, aşağıdaki
olaylarda **otomatik olarak** dışarı bir POST isteği gider (Faz 110,
`arachne/soar/notifications.py`):

- Yüksek/kritik şiddetli her alarm (`SOAR & Aktif Savunma` katmanı)
- Son Hat'in devreye girmesi (kubbe delindi / çekirdek yemi tetiklendi)

Webhook, Slack/Discord/Microsoft Teams/genel bir "Incoming Webhook"
alıcısıyla uyumlu düz JSON gönderir:

```json
{
  "product": "Arachne Sentinel",
  "asset_name": "Ana Web Sitesi",
  "event_type": "alert",
  "source_ip": "203.0.113.9",
  "severity": "critical",
  "score": 95,
  "detail": "SQL Injection - skor 95",
  "timestamp": "2026-08-28T10:15:00Z"
}
```

**Veri minimizasyonu:** webhook'a sadece bu metadata gider — honeypot'a
gelen ham yük, veritabanı içeriği ya da kendi profil bilgileriniz (e-posta
adresiniz, webhook URL'nizin kendisi) asla gönderilmez. Saatlik 30
bildirim kotası vardır (webhook'unuzun spam'lenmemesi için); aşılırsa
sistem sessizce bekler, hiçbir savunma kararı etkilenmez.

Slack'te hızlı kurulum: workspace ayarlarından "Incoming Webhooks"
ekleyin, verilen URL'yi `python main.py onboard` sırasında (ya da
`data/customer_profile.json`'da `alert_webhook_url` alanına) yapıştırın.

## Adım 6 — Doğrulama

```bash
# Kendi honeypot'unuza sahte bir saldırı gönderin
python scripts/demo_attack.py

# Paneli açın, Genel Bakış'ta alarm sayısının arttığını görün
python main.py dashboard --port 5001

# Webhook yapılandırdıysanız Slack/Discord kanalınızda bildirimi görün
```

## Sıkça sorulan sorular

**S: Gerçek müşteri verilerimi/şifrelerimi bu sisteme koyabilir miyim?**
Hayır — kesinlikle önerilmez. Bu bir honeypot/aldatma sistemidir; amacı
saldırganı sahte veriyle oyalamaktır. Gerçek sırlarınız kendi güvenli
şifre yöneticinizde/secret store'unuzda kalmalı.

**S: Sistem internete kapalıyken de çalışır mı?**
Evet — çekirdek savunma (honeypot, WAF, kural motoru, SOAR, Son Hat) hiçbir
internet bağlantısı gerektirmez. Sadece açıkça yapılandırdığınız opsiyonel
özellikler (tehdit istihbaratı, NVD, webhook) dış bağlantı kullanır.

**S: Birden fazla varlığı/siteyi tek kurulumda koruyabilir miyim?**
Şu an bir kurulum = bir müşteri profili modeli var. Birden fazla varlık
için ayrı `docker compose` projeleri (farklı `ARACHNE_CUSTOMER_PROFILE`
yollarıyla) çalıştırmanız gerekir.
