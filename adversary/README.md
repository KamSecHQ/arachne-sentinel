# 🕷 Arachne Adversary — Kırmızı Takım (Red Team) Test Motoru

Arachne Sentinel savunma platformunun **saldırı tarafı ikizi**. Amacı tek: kendi
savunmamızı test etmek ve **kırmızı–mavi ko-evrimi** kurmak. Saldırıda ne kadar
gelişirsek, savunmanın zayıf noktalarını o kadar erken bulur ve onu yukarı
çekeriz.

> Bu, Arachne Sentinel'in savunma sisteminden **ayrı bir projedir**
> (`adversary/`), ama onu hedefleyerek çalışır.

## ⚠️ Etik Sınır — Kod Seviyesinde Zorlanır

- **Yalnızca yerel/izole hedef.** Motor `localhost` / `127.0.0.0/8` / `::1`
  dışına **çıkamaz**. Bu bir ayar değil, `safety.py` içinde sabit bir kısıttır;
  loopback dışı her hedef `RedTeamSafetyError` ile **reddedilir**.
- **Silahlaştırma yok.** Dışarı bağlanan reverse shell, veri sızdırma, gerçek
  RCE, kalıcılık **yoktur**. Hedef, kendi bilinçli-zafiyetli lab uygulamamızdır
  (`arachne/waf/labtarget`); komut enjeksiyonu tarafında **sahte kabuk** vardır,
  yani gerçek komut asla çalışmaz.
- **Amaç savunma.** Üretilen yükler, sadece kendi WAF/savunmamızın onları
  yakalayıp yakalamadığını ölçmek için kullanılan test dizeleridir.

## Nasıl Çalışır

1. **Payload kütüphanesi** (`payloads.py`) — 5 sınıf temel saldırı (SQLi, XSS,
   path traversal, komut enjeksiyonu, SSTI).
2. **Mutasyon motoru** (`mutators.py`) — her yükü deterministik olarak dönüştürür
   (büyük/küçük harf, yorum ekleme, kodlama, boşluk hilesi) → WAF'ı atlatmayı zorlar.
3. **Kampanya motoru** (`engine.py`) — yükleri yerel lab hedefine gönderir;
   *engellendi / çalıştı / atlattı* ölçer. Her istek güvenlik kapısından geçer.
4. **Adaptif savunma** (`defense.py`) — atlatan varyantlara karşı normalleştirici
   (yorum sil, boşluk daralt, URL çöz…) öğrenen mavi takım.
5. **Ko-evrim döngüsü** (`coevolution.py`) — tur tur yarış: kırmızı atlatır, mavi
   öğrenir, atlatma oranı düşer.
6. **Rapor** (`report.py`) — tek-dosya HTML kırmızı-vs-mavi raporu.

## Kullanım

```bash
# CANLI DÜELLO ARENASI (komuta merkezi) — kırmızı vs mavi, tarayıcıda
python -m adversary.cli panel          # http://127.0.0.1:8099  (arena: / · sade panel: /panel)

# tek saldırı kampanyası (yerel lab hedefine)
python -m adversary.cli campaign

# kırmızı-mavi ko-evrim döngüsü (terminal)
python -m adversary.cli coevolve --rounds 5

# ko-evrim + HTML rapor
python -m adversary.cli report
```

### Komuta Merkezleri

Artık iki panel var, karşılıklı:

- **Mavi (savunma):** `python main.py dashboard --port 5001` — Arachne Sentinel komuta merkezi.
- **Kırmızı + Arena (saldırı/düello):** `python -m adversary.cli panel` — saldırı komuta merkezi ve **canlı düello arenası**: saldırılar ekranda uçar, kalkana çarpar (engel) ya da geçer (atlatma); tug-of-war saldırgan↔savunma dengesini gösterir; savunma öğrendikçe kalkan güçlenir.

## Örnek Sonuç (yerel lab)

| Tur | Saldırgan atlatma | Savunma öğrendi |
|----:|:-----------------:|-----------------|
| 1 | %28,9 (13/45) | collapse_ws, strip_comments |
| 2 | **%0,0** (0/45) | — (yakınsadı) |

Saldırgan 13 atlatma buldu; savunma iki normalleştirici öğrenip **yanlış pozitif
üretmeden** yakaladı. Daha zengin bir saldırı korpusu yarışı yeniden açar —
sistemin amacı tam da budur.
