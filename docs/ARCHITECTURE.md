# Mimari

## Genel akış

```
saldırgan/tarayıcı
        │  TCP bağlantısı
        ▼
┌───────────────────┐        ┌──────────────────┐
│ honeypot/listeners │──────▶│  storage (SQLite) │
│  (sahte servisler) │  log  │  events / alerts  │
└───────────────────┘        └────────┬─────────┘
                                       │ okuma
                                       ▼
                              ┌──────────────────┐
                              │ detection/scorer  │
                              │  + rules (kurallar)│
                              └────────┬─────────┘
                                       │ alarm (skor >= eşik)
                                       ▼
                              ┌──────────────────┐
                              │ storage.log_alert │
                              └────────┬─────────┘
                                       │ okuma
                                       ▼
                        ┌───────────────────────────┐
                        │ reporting/report_generator │
                        │ reporting/dashboard (Flask)│
                        └───────────────────────────┘
```

## Tasarım kararları ve nedenleri

**Neden "düşük etkileşimli" (low-interaction) honeypot?** Sahte servisler
gerçek bir kabuk (shell) ya da dosya sistemi sunmaz; sadece bir banner
gönderir ve gelen veriyi loglar. Bu hem güvenlidir (saldırgan gerçek bir
şeyi ele geçiremez) hem de MVP için yeterlidir — asıl değer davranış
kalıplarını tespit etmekte, sahte bir Linux kabuğu simüle etmekte değil.

**Neden kural tabanlı bir motorla başladık, doğrudan ML değil?** Kural
tabanlı bir sistem *açıklanabilir*: her alarmın yanında "neden" tetiklendiği
açıkça yazar (`reasons` listesi). Bu hem hata ayıklamayı kolaylaştırır hem de
bir yarışma jürisi ya da mülakatta savunulması kolay bir sistem ortaya
çıkarır. Etiketli saldırı verisi biriktikçe (`events` tablosu büyüdükçe) bu
kurallara ek olarak bir ML sınıflandırıcı eklenebilir — bkz. ROADMAP.md.

**Neden SQLite?** Kurulum gerektirmez, tek dosyadır, taşınabilir demo/test
için idealdir. Sistem büyüdükçe PostgreSQL gibi bir veritabanına geçmek
`storage.py` içindeki fonksiyonları değiştirerek kolayca yapılabilir —
geri kalan kod (`honeypot`, `detection`, `reporting`) `storage` modülünün
arayüzüne bağımlı, SQLite'a değil.

**Skorlama nasıl çalışır?** Her kural bir "ağırlık" (weight) döndürür,
tetiklenen kuralların ağırlıkları toplanır, toplam skor `config.py`
içindeki eşiklerle karşılaştırılıp bir şiddet seviyesine (`low` / `medium`
/ `high` / `critical`) dönüştürülür. `ALERT_MIN_SCORE` eşiğinin altındaki
skorlar alarma dönüşmez (gürültüyü azaltmak için).

## Modül sorumlulukları

| Modül | Sorumluluk |
|---|---|
| `arachne/config.py` | Tüm ayarlar (portlar, eşikler, pencereler) tek yerde |
| `arachne/storage.py` | SQLite okuma/yazma, tüm sorgular burada toplanır |
| `arachne/honeypot/listeners.py` | Sahte servisler, bağlantı/veri loglama |
| `arachne/detection/rules.py` | Bağımsız, test edilebilir tespit kuralları |
| `arachne/detection/scorer.py` | Kuralları çalıştırıp toplam skor/alarm üretir |
| `arachne/reporting/report_generator.py` | Statik HTML rapor |
| `arachne/reporting/dashboard.py` | Canlı Flask paneli |
| `main.py` | CLI giriş noktası (`run` / `report` / `dashboard`) |
| `scripts/demo_attack.py` | Kendi kendini test eden saldırı simülasyonu |
