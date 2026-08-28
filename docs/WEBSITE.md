# Arachne Sentinel'in Kendi Tanıtım Sitesi (Faz 112)

`website/` paketi, Arachne Sentinel'in **kendi ürünüyle korunan** gerçek
pazarlama sitesidir — sunumluk bir mockup değil, `python main.py website`
ile gerçekten çalışan bir Flask uygulaması.

## Dogfooding: site kendi WAF'ıyla korunuyor

`website/app.py`, tam da müşterilere önerdiğimiz entegrasyon adımını
([INTEGRATION.md](INTEGRATION.md) Adım 2) kendi üzerinde uyguluyor:

```python
app.wsgi_app = WAFMiddleware(app.wsgi_app, db_path=db_path)
```

Bu iddia değil, `tests/test_website.py::test_dogfooding_waf_actually_blocks_sql_injection`
ile doğrulanan bir gerçek — siteye bir SQLi denemesi gönderirseniz gerçek
bir HTTP 403 alırsınız (sayfanın kendisi de bunu söylüyor).

## Yerel çalıştırma

```bash
python main.py website                    # http://127.0.0.1:8088, WAF aktif
python main.py website --host 0.0.0.0      # dışarıdan erişim (container/sunucu)
python main.py website --unprotected       # SADECE karşılaştırma - gerçek dağıtımda kullanmayın
```

## İletişim adresini ayarlama

Sayfadaki tüm CTA'lar (`Pilot talep et`, `Profesyonel'e geç`, vb.)
`mailto:` bağlantılarıdır — ayrı bir form/e-posta altyapısı gerekmez.
Varsayılan adres bir yer tutucudur; gerçek adresinizi ortam değişkeniyle
ayarlayın:

```bash
export ARACHNE_WEBSITE_CONTACT_EMAIL="iletisim@sizin-alan-adiniz.com"
```

Docker Compose kullanıyorsanız `.env` dosyasına aynı değişkeni ekleyin
(`docker-compose.yml`'in `website` servisi zaten bunu geçiyor).

## Docker ile çalıştırma

```bash
docker compose up -d website
curl http://localhost:8088/health
```

Detaylar: [DEPLOYMENT.md](DEPLOYMENT.md).

## Gerçek bir alan adına bağlama (domain aldığınızda)

1. **DNS**: Alan adınızın kayıt sağlayıcısında bir **A kaydı** oluşturup
   sunucunuzun genel IP adresine yönlendirin (örn. `arachne-sentinel.com` →
   sunucu IP'niz). Yayılması birkaç dakika-birkaç saat sürebilir.
2. **TLS/ters vekil sunucu**: `website` servisi düz HTTP (8088) konuşur —
   gerçek trafik için önüne bir ters vekil sunucu (reverse proxy) koyup
   HTTPS sonlandırması yapmanız gerekir. En basit yol
   [Caddy](https://caddyserver.com/)'dir (otomatik Let's Encrypt sertifikası
   alır):
   ```
   # Caddyfile
   arachne-sentinel.com {
       reverse_proxy localhost:8088
   }
   ```
   `caddy run` ile başlatmanız yeterli — ayrı bir sertifika yönetimi
   gerekmez. Nginx + certbot da eşdeğer bir alternatiftir.
3. **Doğrulama**: `https://arachne-sentinel.com/health` gerçek alan
   adınızdan `{"status":"ok"}` döndüğünde site canlıdır.

**Not:** Bu proje bir hosting/DNS sağlayıcısı önermez — sunucunuzu
(VPS, kendi donanımınız vb.) ve alan adı kayıt sağlayıcınızı siz seçersiniz.
`docker compose up -d` çalıştığı her yerde (herhangi bir Linux sunucusunda)
bu site de çalışır.

## İçeriği güncelleme

- Metin/fiyatlandırma: `website/templates/index.html`
- Görsel tasarım/renkler: `website/static/css/site.css`
- Hero animasyonu (Çelik Kubbe canvas'ı): `website/static/js/site.js`

Fiyatlandırma rakamlarının gerekçesi için [PRICING.md](PRICING.md)'ye bakın.
