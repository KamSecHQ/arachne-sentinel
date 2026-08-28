# Fiyatlandırma (Faz 111)

> Bu belge dahili bir referanstır — güncel/nihai ticari şartlar için
> [tanıtım sayfasına](https://claude.ai/code/artifact/6e4b641a-552f-451b-bd2a-f87d31ed3bfb)
> bakın. Fiyatlar `python main.py onboard`/entegrasyon desteğine ilişkindir;
> yazılımın kendisi MIT lisanslı ve açık kaynaktır (bkz. [LICENSE](../LICENSE)).

## Neden bu fiyatlar?

Karşılaştırılabilir kategorilerdeki gerçek piyasa fiyatları (2026, kamuya
açık kaynaklardan):

| Kategori | Referans ürün | Fiyat |
|---|---|---|
| Deception/honeypot | Thinkst Canary | 5 cihaz için $7.500–10.000/**yıl**'dan başlıyor |
| Yönetilen SIEM | Wazuh Cloud | 100 ajana kadar $571/**ay** (~$5.71/ajan) |
| Bulut WAF (KOBİ) | Cloudflare Business | $200–250/**ay** |
| SOC-as-a-Service (KOBİ) | Genel piyasa | $1.500–5.000/**ay** |
| MDR (uç nokta başına) | Genel piyasa | $8–35/uç nokta/**ay** |

Arachne Sentinel bu dört kategorinin (deception + WAF + SIEM-lite + SOAR)
işlevini **tek pakette, müşterinin kendi sunucusunda** sağlıyor — bizim
tarafımızda barındırma/24×7 SOC personeli maliyeti yok. Bu yapısal fark,
fiyatı piyasa ortalamasının çok altında tutmamızı sağlıyor.

**Durustluk notu:** Bu bir kesin rakip analizi değildir — kamuya açık
kaynaklardan derlenmiş kaba bir karşılaştırmadır (bkz. altta linkler).
Nihai fiyat kararı ticari ekibe aittir; buradaki sayılar öneri niteliğindedir.

## Paketler

### Topluluk — $10/ay

Kendi sunucunuza kurun, sınırsız süre kullanın.

- 110 fazın tamamı: honeypot, WAF, kural motoru, SOAR, Son Hat
- Docker Compose ile kendi kendine kurulum (bkz. [DEPLOYMENT.md](DEPLOYMENT.md))
- Topluluk desteği (GitHub Issues)
- Hedef kitle: değerlendirme, akademik kullanım, tek geliştiriciler

**Neden $0 değil:** Tamamen ücretsiz bir kademe, üründe gerçek bir değer
algısı oluşturmuyor — sembolik de olsa bir fiyat, "bu ciddi bir üründür"
mesajını verir ve destek altyapısının asgari maliyetini karşılar.

### Profesyonel — $49/ay ($39/ay yıllık faturalandırmada) — *önerilen varsayılan*

- Topluluk'un tüm özellikleri
- `python main.py onboard` kurulumunda birebir yardım
- Webhook/Slack/Discord entegrasyon desteği (bkz. [INTEGRATION.md](INTEGRATION.md))
- Öncelikli e-posta desteği (2 iş günü SLA)
- Güvenlik yaması önceliği
- Hedef kitle: tek bir gerçek site/uygulaması olan küçük-orta işletme

**Konumlama gerekçesi:** Cloudflare Business'ın ($200-250/ay) beşte
birinden az, ama tek başına bir WAF'tan çok daha fazlasını (deception +
SOAR + Son Hat) içeriyor.

### Kurumsal — Özel teklif

- Profesyonel'in tüm özellikleri
- Çoklu varlık/site profili desteği
- Özel SLA + doğrudan destek hattı
- Entegrasyon danışmanlığı (mevcut altyapıya özel)
- Hedef kitle: birden fazla sitesi/servisi olan şirketler, ajanslar

Fiyat kapsam görüşmesiyle belirlenir — SOC-as-a-Service piyasa ortalaması
($1.500-5.000/ay) referans alınarak, ama self-hosted olduğu için
altında konumlandırılması önerilir.

## Kaynaklar

Piyasa verisi için: [Vendr — Thinkst Canary](https://www.vendr.com/marketplace/thinkst-canary),
[SIEMCostCalculator — Wazuh](https://siemcostcalculator.com/wazuh-pricing),
[WAFPlanet — WAF fiyat karşılaştırması](https://wafplanet.com/blog/waf-pricing-comparison-2026/),
[BD Emerson — SOC-as-a-Service fiyatlandırması](https://www.bdemerson.com/article/soc-as-a-service-pricing).
