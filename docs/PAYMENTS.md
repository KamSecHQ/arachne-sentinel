# Ödeme Sistemi — İyzico Entegrasyonu (Faz 113)

Arachne Sentinel'in tanıtım sitesi (`website/`), Topluluk ve Profesyonel
paketler için **İyzico Checkout Form** üzerinden ödeme alabilir. Bu
entegrasyon, projenin geri kalanıyla aynı "karantina" ilkesini takip eder:
**açıkça yapılandırılmadan hiçbir ödeme çağrısı yapılmaz**, kart bilgisi
hiçbir zaman bizim sunucumuza dokunmaz.

## Neden İyzico?

Türkiye merchant hesabı açabilen, TL ile çalışan, kurulumu görece basit ve
yaygın kullanılan bir ödeme altyapısı. Kart bilgisini doğrudan İyzico'nun
kendi güvenli formu topladığı için (Checkout Form modeli) PCI-DSS kapsamımız
minimumda kalıyor — biz asla bir kart numarası görmüyoruz.

## Bu NE DEĞİL — dürüstlük notu

Bu entegrasyon **tek seferlik ödeme** akışıdır (İyzico Checkout Form API).
**Otomatik aylık yenileme yapmaz.** Bir müşteri "Profesyonel'e geç" dediğinde
o ayın ücretini öder; bir sonraki ay tekrar ödeme sayfasına yönlendirilmesi
(veya elle faturalandırılması) gerekir.

Gerçek otomatik tekrarlayan faturalandırma için İyzico'nun ayrı
**Subscription API**'si kullanılabilir (Product/PricingPlan ön-kurulumu
gerektirir, daha karmaşık bir kurulum). Bu, doğal bir sonraki geliştirme
adımıdır — şu an "otomatik yenileme" diye sunulmuyor, çünkü değil.

## Kurulum adımları

### 1. İyzico sandbox (test) hesabı açın

1. https://sandbox-merchant.iyzipay.com adresinden ücretsiz bir sandbox
   hesabı oluşturun (gerçek şirket bilgisi gerekmez, test amaçlıdır).
2. Panelden **API Anahtarları** bölümüne gidin, `API Key` ve `Secret Key`
   değerlerini kopyalayın.

> Not: İyzico herkese açık/paylaşılan bir demo API anahtarı sağlamaz — her
> geliştirici kendi sandbox hesabını açmak zorundadır. Bu yüzden gerçek bir
> ödeme testi için bu adım sizin tarafınızdan tamamlanmalı.

### 2. Ortam değişkenlerini ayarlayın

```bash
export ARACHNE_IYZICO_ENABLED=1
export ARACHNE_IYZICO_API_KEY="sandbox-xxxxxxxx"
export ARACHNE_IYZICO_SECRET_KEY="sandbox-yyyyyyyy"
export ARACHNE_IYZICO_SANDBOX=1   # varsayılan zaten budur, açıkça yazmak isteğe bağlı
```

Docker Compose kullanıyorsanız aynı değişkenleri proje kökündeki `.env`
dosyasına ekleyin — `docker-compose.yml`'nin `website` servisi bunları
otomatik olarak container'a geçirir.

### 3. Siteyi başlatın

```bash
python main.py website
```

veya Docker ile:

```bash
docker compose up -d website
```

Ana sayfadaki **Topluluk** ve **Profesyonel** kartlarındaki butonlar artık
`/checkout/<plan>` adresine, oradan da gerçek İyzico ödeme formuna
yönlendirir (sandbox modundaysa ekranda "SANDBOX MODU" uyarı şeridi
görünür — gerçek kartla denerseniz bile hiçbir para çekilmez, sandbox test
kartları için İyzico dokümantasyonuna bakın).

### 4. Canlıya geçiş (gerçek para)

Sandbox'ta test ettikten ve gerçek bir üretim (production) İyzico hesabı
açtıktan sonra:

```bash
export ARACHNE_IYZICO_API_KEY="<gercek-production-anahtari>"
export ARACHNE_IYZICO_SECRET_KEY="<gercek-production-gizli-anahtari>"
export ARACHNE_IYZICO_SANDBOX=0    # ACIKCA "0" yapilmadan sistem sandbox'ta kalir
```

`ARACHNE_IYZICO_SANDBOX` değişkeni **bilinçli bir çift kilittir**: anahtarlar
girilmiş olsa bile bu değişken açıkça `0` yapılmadan sistem sandbox'a
bağlanmaya devam eder. Kazara canlı para çekmeye karşı bu tasarım tercih
edildi (bkz. `website/payments.py` docstring'i).

## Güvenlik notları

- Kart numarası, CVV, son kullanma tarihi **hiçbir zaman** bizim
  sunucumuza ulaşmaz — bunlar doğrudan İyzico'nun kendi formuna girilir.
- `/checkout/callback` adresine gelen İyzico yönlendirmesindeki hiçbir alana
  doğrudan güvenilmez; gerçek ödeme durumu her zaman İyzico'ya ayrıca
  sorularak (`verify_payment_result()`, sunucu-sunucu API çağrısı) doğrulanır.
- `ARACHNE_IYZICO_API_KEY`/`ARACHNE_IYZICO_SECRET_KEY` değerleri hiçbir log
  satırında, panelde veya `/health` gibi bir uç noktada görünmez
  (`payments.status()` sadece anahtarın *var olup olmadığını* döner, değerini
  değil).
- Tüm ortam değişkenleri boşsa (varsayılan durum) ödeme sayfası çökmez —
  "ödeme henüz aktif değil, bizimle iletişime geçin" mesajı gösterilir ve
  `mailto:` linkiyle iletişim adresine yönlendirir.

## İlgili dosyalar

- [`website/payments.py`](../website/payments.py) — karantina modülü (İyzico SDK sarmalayıcı).
- [`website/app.py`](../website/app.py) — `/checkout/<plan_id>` ve `/checkout/callback` route'ları.
- [`website/templates/checkout.html`](../website/templates/checkout.html), `checkout_form.html`, `checkout_result.html`, `checkout_unavailable.html`, `checkout_error.html`.
- [`tests/test_payments.py`](../tests/test_payments.py) — İyzico'ya hiçbir gerçek ağ çağrısı yapmadan (mock ile) tüm akışın test edildiği dosya.
- [`docs/PRICING.md`](PRICING.md) — paket fiyatları (Topluluk 10 ₺/ay, Profesyonel 49 ₺/ay).
