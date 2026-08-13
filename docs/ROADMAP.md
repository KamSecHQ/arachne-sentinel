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

## Faz 2 — Ay 3-8: WAF katmanı + otonom zafiyet tarayıcı + ilk ML modeli

- Ayrı bir modül olarak SQLi/XSS için imza tabanlı bir "web application
  firewall" (WAF) katmanı — honeypot dışında gerçek bir test uygulamasının
  önüne konabilir
- Açık kaynak araçları (ör. `python-nmap` sarmalayıcı) kullanarak basit,
  otomatik bir zafiyet tarama + raporlama modülü
- `events` tablosunda biriken veriyle (gerekirse halka açık honeypot veri
  setleriyle desteklenerek) ilk **denetimli öğrenme tabanlı** saldırı
  sınıflandırıcısı — kural motorunun *yanında*, onun yerine değil (kural
  motoru açıklanabilirlik sağlamaya devam eder)
- Hedef çıktı: TEKNOFEST / TÜBİTAK 2209-A başvurusu için yeterli olgunlukta
  bir "araştırma projesi" paketi (rapor + demo + kod)

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
