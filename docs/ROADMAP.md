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

## Faz 3 — düşük seviye bileşen: ARM64 assembly imza tarama çekirdeği (tamamlandı)

- [x] Honeypot kural motorunun (`rule_known_signature`) merkezinde yer alan
  "bu payload'da bilinen bir saldırı imzası var mı?" sorusunu cevaplayan
  gerçek bir işlevsel çekirdek, elle yazılmış **ARM64 assembly** ile
  (`arachne/native/arm64/fast_scan.s`) — Apple Silicon (M-serisi) Mac'lerde
  native olarak derlenip çalışır
- [x] `az_find` (tek imza arama) ve `az_scan_multi` (32'ye kadar imzayı tek
  taramada bitmask olarak döndüren toplu tarama) fonksiyonları, AAPCS64
  (standart ARM64 çağırma kuralı) ile C/Python'dan doğrudan çağrılabilir
- [x] Python tarafında `ctypes` köprüsü (`arachne/native/signature_engine.py`)
  — native kütüphane yoksa (Intel Mac, Linux, CI, henüz derlenmemiş kurulum)
  **otomatik ve sessizce** birebir aynı sonucu üreten bir Python yedeğine
  düşer; davranış hiçbir zaman platforma bağlı değişmez, sadece hız değişir
- [x] Bağımsız bir CLI aracı (`arachne/native/tools/byte_inspector.s`) —
  projeden tamamen ayrı, tek başına çalışan bir ikili; gerçek dosya G/Ç'si
  (`fopen`/`fread`/`fclose`) ve `printf` çağrılarını doğrudan assembly'den
  yapar
- [x] Doğrulama: mantık önce Linux ARM64 üzerinde (`qemu-aarch64` ile gerçek
  CPU emülasyonu) 20.000+ rastgele (fuzz) test + el ile yazılmış kenar durum
  testleriyle kanıtlandı, ardından Mach-O/Apple clang'e özgü farklarla
  (`_` sembol öneki, `@PAGE`/`@PAGEOFF` adresleme) Mac'e taşındı
- [x] Dürüst kıyaslama scripti (`scripts/benchmark_native_scan.py`): "el
  yazımı Python döngüsü vs el yazımı assembly" ve "Python'un kendi
  `str.find()`'ı vs assembly" ayrı ayrı ölçülür — abartılı "assembly her
  zaman kazanır" iddiası yerine farkın nereden geldiği gösterilir
- [x] 39 birim testi (29 + 10 yeni), hepsi native motor pasifken de (Python
  yedeği üzerinden) geçiyor — CI/sandbox gibi Apple Silicon olmayan
  ortamlarda proje bozulmuyor

**Bilinçli kapsam sınırlaması:** WAF katmanının regex tabanlı imza motoru
(`arachne/waf/rules.py`) bu fazın kapsamı DIŞINDA tutuldu — elle yazılmış bir
regex motoru, doğruluğu kanıtlanması çok daha zor bir güvenlik riski olurdu.
Assembly çekirdeği, honeypot'un daha basit alt-string eşleşmesine
odaklandı; bu "az ama gerçekten sizin yazdığınız, savunabileceğiniz" ilkesine
uygun bir seçimdir.

**Sıradaki hedef (Faz 3 devamı, isteğe bağlı):** İkinci bilgisayar (Windows/
x86-64) edinildiğinde aynı fonksiyonların x86-64 (NASM/GAS) versiyonu
eklenerek iki mimari arasında bir performans/taşınabilirlik karşılaştırması
yapılabilir; uluslararası CTF'lere (Google CTF, DEF CON quals gibi) katılım.

## Faz 4 — Moving Target Defense: "hayalet" savunma katmanı (tamamlandı)

- [x] **Banner/sürüm rotasyonu** (`arachne/mtd/identity_rotator.py`):
  honeypot servisleri zaman içinde farklı bir sürüm banner'ı gösterir; bir
  saldırgan iki farklı taramada iki farklı "sürüm" görür, güvenilir bir
  parmak izi (fingerprint) çıkaramaz. Saat enjekte edilebilir, deterministik
  test edildi.
- [x] **Gerçekten port değiştiren "hayalet admin" servisi**
  (`arachne/mtd/port_hopper.py`): bir port havuzu içinde periyodik olarak
  kapanıp başka bir portta yeniden açılır; saldırgan önceki taramada
  bulduğu portu tekrar denerse artık orada kimse yoktur. Her sıçrama
  `mtd_rotations` tablosuna kaydedilir.
- [x] **Lab-içi "hayalet DNS" yanıtlayıcısı** (`arachne/mtd/dns_ghost.py`):
  DNS paket formatının minimal bir alt kümesini elle ayrıştırıp üreten,
  aynı isim sorgulandığında rotasyonlu farklı bir (yerel) IP döndüren bir
  UDP yanıtlayıcı — "DNS tabanlı moving target defense" kavramının somut,
  çalışan bir kanıtı. Gerçek sistem DNS'ini değiştirmez, port 53
  kullanmaz (bkz. docs/ETHICS_AND_LEGAL.md).
- [x] `python main.py mtd-demo` ile üçü birden başlatılabilir; canlı
  panelde ve statik raporda ayrı bir "Faz 4" bölümü, tüm rotasyonları
  zaman çizelgesi olarak gösterir.
- [x] 10 yeni birim testi (toplam 49) — banner rotasyonunun zamanlaması,
  DNS paket ayrıştırma/üretme round-trip'i, port hopper'ın gerçek
  soket bağlama/kapatma davranışı dahil.

**Bilinçli kapsam sınırlaması ve netlik:** Bu faz **gerçek internete karşı
bir VPN/anonimlik ürünü değildir** — böyle bir ürün, tek başına ayrı bir
şirketin işi (bkz. Tor Project, ticari VPN sağlayıcıları). Burada
kurduğumuz şey, akademik güvenlik literatüründe tanınan "moving target
defense" kavramının küçük ama gerçek, test edilmiş bir uygulaması: kendi
korunan (sahte) yüzeyinizin kimliği zamanla değişir, böylece saldırganın
harita çıkarma/hedef sabitleme süreci zorlaşır. Bu, "sizi görünmez
yaparız" gibi abartılı bir pazarlama iddiası yerine, ölçülebilir ve
savunulabilir bir mühendislik iddiasıdır — tam da bu projenin baştan beri
takip ettiği ilkeye uygun (bkz. "Sabit ilkeler" bölümü).

**Sıradaki hedef (stretch-goal, isteğe bağlı):** DDoS tespiti için basit
trafik-anomali analizi (yine izole ortamda, gerçek internet trafiğine
karşı değil); ikinci bilgisayar edinildiğinde x86-64 assembly versiyonu
(bkz. Faz 3 notu); uluslararası CTF'lere (Google CTF, DEF CON quals gibi)
katılım.

## Sabit ilkeler (her fazda geçerli)

1. **Önce çalışan, test edilmiş, dokümante edilmiş bir MVP** — sonra kapsam
   genişletme.
2. **Mütevazı ve ölçülebilir iddialar.** "Sıfır risk" ya da "kırılamaz" gibi
   ifadeler yerine ölçülen sonuçlar: tespit oranı, yanlış pozitif oranı,
   tepki süresi.
3. Her faz sonunda: README/ARCHITECTURE güncellenir, testler yeşil kalır,
   bir demo/rapor üretilir.
