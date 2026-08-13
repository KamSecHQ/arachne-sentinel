# Yol Haritası

Bu belge, Arachne Sentinel'i tek seferde "her şeyi yapan" bir sisteme
dönüştürmeye çalışmak yerine, her aşaması gerçekten çalışan ve savunulabilir
bir ürüne kademeli olarak büyütme planını içerir.

## Faz 1 — v0.1 (tamamlandı)

- Honeypot: SSH, FTP, MySQL, HTTP-admin sahte servisleri
- SQLite tabanlı olay/alarm günlüğü
- Açıklanabilir kural motoru: port taraması, brute-force, bilinen saldırı
  imzaları (SQLi/XSS/command injection/path traversal), çoklu servis
  keşfi, tekrarlayan saldırgan tespiti
- Statik HTML raporu + canlı Flask paneli
- 13 birim testi, kendi kendini test eden demo saldırı scripti

## Faz 2 — WAF katmanı + otonom zafiyet tarayıcı + ilk ML modeli (tamamlandı)

- [x] Ayrı bir modül olarak SQLi/XSS/command-injection/path-traversal için
  regex tabanlı bir "web application firewall" (WAF) middleware'i — gerçek
  bir test uygulamasının (`arachne/waf/demo_app.py`) önüne konup istekleri
  gerçekten engelliyor (403), rate-limiting de dahil
- [x] Bağımsız (nmap gerektirmeyen) port tarama + banner grabbing + bilinen
  zafiyet eşleştirme yapan otonom bir zafiyet tarayıcı (`arachne/scanner/`)
- [x] İlk **denetimli öğrenme tabanlı** saldırı sınıflandırıcısı (TF-IDF +
  Logistic Regression) — kural motorunun *yanında*, onun yerine değil
- [x] Honeypot + WAF + tarama bulgularını tek bir sayfada birleştiren
  güncellenmiş rapor
- [x] 16 yeni birim testi (toplam 29), uçtan uca demo scriptleriyle
  doğrulandı

**Sıradaki hedef:** TEKNOFEST / TÜBİTAK 2209-A başvurusu için yeterli
olgunlukta bir "araştırma projesi" paketi (rapor + demo + kod) hazırlamak —
elimizdeki sistem artık bunun icin teknik olarak yeterli olgunlukta.

## Faz 3 — Yıl 2: Düşük seviye bileşenler

- C ve Assembly bilgisi olgunlaştıkça: basit bir imza/pattern tabanlı
  tespit modülünün düşük seviye (C/asm) bir versiyonu, ya da küçük bir
  ikili analiz (binary analysis) yardımcı aracı
- Bu fazın hedefi "100 katman" değil — **az ama gerçekten sizin yazdığınız,
  savunabileceğiniz** bir düşük seviye bileşen eklemek
- Uluslararası CTF'lere (Google CTF, DEF CON quals gibi) katılım

## Faz 4 — Yıl 3-4: Moving Target Defense ve stretch-goal'lar

- Yalnızca izole lab/VM ortamında: dinamik port/servis rotasyonu (moving
  target defense) simülasyonu
- DDoS tespiti için basit trafik-anomali analizi (yine izole ortamda,
  gerçek internet trafiğine karşı değil)
- Trafik gizleme / anonimlik kavramını kanıtlayan küçük ölçekli bir
  prototip (tam bir VPN ürünü değil — bu ölçek tek başına ayrı bir şirketin
  işi, bkz. Tor Project)

## Sabit ilkeler (her fazda geçerli)

1. **Önce çalışan, test edilmiş, dokümante edilmiş bir MVP** — sonra kapsam
   genişletme.
2. **Mütevazı ve ölçülebilir iddialar.** "Sıfır risk" ya da "kırılamaz" gibi
   ifadeler yerine ölçülen sonuçlar: tespit oranı, yanlış pozitif oranı,
   tepki süresi.
3. Her faz sonunda: README/ARCHITECTURE güncellenir, testler yeşil kalır,
   bir demo/rapor üretilir.
