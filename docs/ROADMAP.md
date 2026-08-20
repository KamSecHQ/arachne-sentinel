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

## Faz 5 — Saldırı Tersine Mühendisliği (tamamlandı)

- [x] **Çok katmanlı kodlama çözücü** (`arachne/reverse/deobfuscator.py`):
  URL, çift-URL, base64, hex, HTML entity ve unicode escape katmanlarını
  sabit noktaya ulaşana kadar açar; geçilen her adımı kaydeder. Sonsuz
  döngüye karşı iki koruma (derinlik sınırı + değişiklik kontrolü).
- [x] **Gizlenmiş saldırı tespiti**: bir imza SADECE kodlama çözüldükten
  sonra görülüyorsa ayrıca işaretlenir — klasik WAF atlatma tekniği.
- [x] **IOC çıkarıcı** (`ioc_extractor.py`): IP, alan adı, URL, dosya yolu,
  hash, kripto cüzdanı, kabuk komutu ve ters kabuk kalıpları.
- [x] **Saldırı aracı parmak izi** (`tool_fingerprint.py`): sqlmap, nikto,
  nmap, hydra, gobuster, dirb, ffuf, metasploit, wpscan tespiti — her
  eşleşme GEREKÇESİYLE birlikte, güven skoruyla.
- [x] **MITRE ATT&CK / CWE / CAPEC eşlemesi** ve Lockheed Martin Kill Chain
  konumlandırması (`arachne/intel/attck.py`).
- [x] **Saldırı zinciri yeniden kurulumu**: bir IP'nin tüm olaylarını
  birleştirip "önce tarama, sonra brute-force, sonra SQLi" şeklinde
  sıralı bir anlatı çıkarır.
- [x] 32 birim testi.

**Teknik doğruluk notları (bilinçli tercihler):**
- ATT&CK v19 (Nisan 2026) ile TA0005 "Defense Evasion" → **"Stealth"**
  olarak değişti; TA0112 "Defense Impairment" eklendi. Güncel isimleri
  kullanıyoruz — internetteki çoğu öğretici hâlâ eski ismi kullanıyor.
- Dizin brute-force'u **T1595.003 (Wordlist Scanning)** olarak eşliyoruz,
  T1110 (Brute Force) olarak DEĞİL. MITRE'nin kendi tanımı: "amaç geçerli
  kimlik bilgisi keşfi değil, içerik/altyapı keşfidir".
- SQLi için ATT&CK'te ayrı teknik YOKTUR; doğru yaklaşım T1190'ı **CWE-89
  ve CAPEC-66 ile birlikte** taşımaktır — biz de öyle yapıyoruz.
- **CAPEC-213 kullanmıyoruz** — o ID kullanımdan kaldırıldı (deprecated).

**Bu fazda bulunan ve düzeltilen gerçek açık:** İmza setinde yalnızca
tırnaklı `' or '1'='1` varyantı vardı; en yaygın kalıplardan biri olan
tırnaksız `' OR 1=1--` hiç yakalanmıyordu. İmza seti genişletildi ve
yanlış pozitif üretmediğini doğrulayan testler eklendi.

## Faz 6 — Tehdit İstihbaratı ve Saldırgan Profilleme (tamamlandı)

- [x] **Davranışsal parmak izi** (`arachne/intel/profiler.py`): servis
  tercihi, zamanlama ritmi, araç imzası ve yük karakterinden türetilen
  bir imza. **IP adresi bilinçli olarak DIŞLANDI** — değişen şey tam da odur.
- [x] **Makine/insan ayrımı**: istekler arası aralıkların standart sapması.
  Otomatik araçlar makine hassasiyetinde düzenli, insanlar düzensizdir —
  şaşırtıcı derecede güçlü ve ucuz bir ölçüt.
- [x] **Kampanya korelasyonu**: aynı parmak izine sahip farklı IP'ler tek
  bir kampanya altında birleştirilir. "3 ayrı alarm" yerine "tek saldırgan,
  3 IP" diyebilmek.
- [x] **STIX 2.1 dışa aktarım** (`stix_export.py`): spec'e uygun ID formatı,
  RFC 3339 zaman damgaları, **çift kill-chain eşlemesi** (Lockheed Martin +
  ATT&CK), gerçek OASIS TLP marking ID'leri, ATT&CK/CWE dış referansları.
  MISP/OpenCTI/SIEM'ler bunu doğrudan okuyabilir.
- [x] **Çevrimdışı IP kapsam sınıflandırması** (`geo.py`): loopback /
  private / documentation / reserved / public ayrımı %100 kesin;
  bölge tahmini açıkça "tahmin" olarak etiketlenir.
- [x] 32 birim testi.

**Dürüstlük notu:** Bu bir GeoIP veritabanı DEĞİLDİR. Şehir seviyesi
doğruluk iddia edilmez. Lab trafiği (127.0.0.1) sahte bir ülkeye
yerleştirilmez, açıkça "LAB" olarak gösterilir.

## Faz 7 — SOAR: Otonom Savunma Orkestrasyonu (tamamlandı)

- [x] **5 playbook** (`arachne/soar/playbooks.py`): keşif, brute-force,
  web sömürü, gizlenmiş yük, hedefli saldırgan. Yapı ticari ürünlerin
  ortak sözlüğünü takip eder: TETİKLEYİCİ → ZENGİNLEŞTİRME → KARAR →
  EYLEM → KAPANIŞ.
- [x] **Playbook'lar saf VERİdir**, çalıştırılabilir kod değil — test etmesi
  önemsiz derecede kolay, ileride yapılandırma dosyasından okunabilir.
- [x] **Gerçek yaptırım** (`blocklist.py`): TTL'li engelleme listesi;
  honeypot her bağlantıda sorar ve engelli IP'yi gerçekten reddeder.
- [x] **İnsan onay kapısı**: geri alınabilir eylemler otomatik, yıkıcı
  eylemler analist onayına yükseltilir. Otomasyon olgunluğu "her şeyi
  otomatikleştirmek" değil, insan kapısının nereye konulacağını bilmektir.
- [x] **Lab güvenliği**: loopback ve özel ağ adresleri ASLA engellenemez —
  aksi hâlde sistem ilk demo saldırısında kendi kendini kilitlerdi.
- [x] **Katmanlar arası tetikleme**: SOAR, Faz 4'ün MTD rotasyonunu
  tetikleyebilir — saldırgan haritalama yaparken tam o anda kimliği
  değiştirmek, topladığı bilgiyi geçersiz kılar.
- [x] Her otomatik karar gerekçesiyle denetim kaydına yazılır.
- [x] 28 birim testi.

**Bu fazda bulunan ve düzeltilen gerçek hata:** Engellemeler ilk tasarımda
yalnızca bellekte tutuluyordu. Uçtan uca canlı testte, honeypot ve panelin
AYRI SÜREÇLERDE çalıştığı ve bellekteki listenin diğer süreçten görünmediği
ortaya çıktı — yaptırım sessizce işe yaramıyordu. Engellemeler SQLite'a
taşındı; bellek yalnızca 1 saniyelik sıcak yol önbelleği olarak kaldı.

## Faz 8 — Güvenli Yapay Zekâ Analist Katmanı (tamamlandı)

- [x] **Yerel analist** (`arachne/ai/analyst.py`): ağ/API anahtarı
  gerektirmeden, yapısal veriden doğal dilde önceliklendirilmiş durum
  raporu (SITREP) üretir. **HER ZAMAN çalışır** — dil modeli olmasa da
  sistem hiçbir şey kaybetmez.
- [x] **Karantina LLM** (`llm_backend.py`): opsiyonel; API anahtarı
  YALNIZCA ortam değişkeninden okunur, koda/dosyaya/veritabanına asla
  yazılmaz. Yalnızca stdlib (urllib) kullanır — hangi verinin nereye
  gittiği tek bakışta görülür.
- [x] **Prompt enjeksiyonu savunması** (`sanitizer.py`): Microsoft Research
  "Spotlighting" datamarking tekniği (arXiv 2403.14720). Ölçülmüş etkisi:
  saldırı başarı oranı ~%50'den **%3'ün altına** düşer. Delimiting tek
  başına yetersizdir (%30'da kalır) — bu yüzden datamarking seçtik.
- [x] **Enjeksiyon denemesini TESPİTE çevirme**: AI'ı manipüle etmeye
  çalışan saldırgan, bu davranışıyla yakalanır ve tehdit skoru yükselir.
  Sistemin iç mimarisini tahmin edecek kadar bilgili bir saldırgan,
  sıradan bir tarayıcıdan daha tehlikelidir.
- [x] **Katı çıktı şeması** (`schema.py`): enum kısıtlamaları, uzunluk
  sınırları, **HTML kaçışlama** (LLM çıktısı üzerinden XSS imkânsız),
  whitelist yaklaşımı (model veri yapısını genişletemez).
- [x] 36 birim testi.

**Ele alınan OWASP LLM Top 10 riskleri:**

| Risk | Azaltma |
|---|---|
| LLM01 Prompt Injection | datamarking + rol kısıtlama + enjeksiyon raporlama |
| LLM05 Improper Output Handling | katı şema + enum + HTML kaçışlama |
| LLM06 Excessive Agency | modelin araç/DB/ağ yetkisi YOK |
| LLM07 System Prompt Leakage | sızdırma denemesi tespit edilip raporlanır |
| LLM10 Unbounded Consumption | önbellek + saatlik kota + uzunluk sınırı |

**Taşıyıcı ilke: yapay zekâ ZENGİNLEŞTİRİR, KARAR VERMEZ.** Engelleme
kararları tamamen deterministik kural motorundadır. Başarılı bir prompt
enjeksiyonunun en kötü sonucu, bir rapor alanındaki yanıltıcı bir
cümledir — atlatılmış bir engelleme ya da yanlış banlanmış bir IP değil.

**"Ölümcül üçlü" (lethal trifecta) karşısındaki konum:** Bir ajan (1) özel
veriye erişim, (2) güvenilmeyen içeriğe maruz kalma ve (3) dışarıyla
iletişim yeteneklerinin üçüne birden sahipse tehlikelidir. Bizim analist
modelimizde (2) tanım gereği vardır; (1) ve (3) **bilinçli olarak
reddedilmiştir**.

## Faz 9 — Dağıtık Sensör Ağı (tamamlandı)

- [x] **HMAC-SHA256 imzalı mesajlaşma** (`arachne/mesh/crypto.py`):
  zaman damgası penceresi + nonce ile tekrar oynatma koruması.
- [x] **Sabit sürede imza karşılaştırma** (`hmac.compare_digest`): düz `==`
  ilk farklı byte'ta durur ve saldırganın imzayı byte byte tahmin
  etmesine izin verir (timing attack) — kriptografide klasik bir tuzak.
- [x] **Belirlenimci JSON serileştirme**: anahtar sırası farklı olduğunda
  imza doğrulamasının rastgele başarısız olmasını engeller.
- [x] **Sensör istemcisi** (`sensor.py`): kuyruk + toplu gönderim; ağ
  hatasında olaylar geri kuyruğa konur (at-least-once teslimat).
- [x] **Merkezi toplayıcı** (`collector.py`): doğrulama sırası ucuzdan
  pahalıya; imza geçmeden HİÇBİR veri veritabanına yazılmaz.
- [x] **Derinlemesine savunma**: sensör doğrulanmış olsa bile içeriği
  ayrıca doğrulanır — bir sensör ele geçirilmiş olabilir.
- [x] 30 birim testi.

**Neden kimlik doğrulama zorunlu?** Doğrulanmamış sensör raporlarını kabul
eden bir SOAR sistemi, **saldırganın elinde silaha dönüşür**: sahte
raporlarla masum IP'leri engelletebilir. Demo scripti bunu kanıtlamak için
kasıtlı olarak sahte bir sensör çalıştırır ve reddedildiğini gösterir.

## Faz 10 — Çelik Kubbe Komuta Merkezi (tamamlandı)

- [x] **Katmanlı savunma simülasyonu**: gelen her saldırı bir mermi, her
  savunma katmanı bir halka. **Çarptığı halka, o kaydı GERÇEKTEN işleyen
  katmandır** — animasyon süsü değil, veriden türetilir.
- [x] **Küresel saldırı haritası**: saldırgan kaynakları, saldırı yayları,
  şiddet renklendirmesi, engellenen IP işaretlemesi. Harici harita
  kütüphanesi yok — kıta hatları doğrudan çizilir (çevrimdışı çalışır).
- [x] **Canlı analiz laboratuvarı**: yükü yapıştır, tersine mühendislik
  sonucunu anında gör (kodlama çözümü, IOC, araç, ATT&CK, enjeksiyon uyarısı).
- [x] **Savunma katmanı sağlığı**: her katmanın canlı metrikleri.
- [x] Canlı tehdit radarı, saldırı akışı terminali, alarm zaman çizelgesi,
  kritik alarmda ses + toast bildirimi.
- [x] Tüm görselleştirmeler **saf Canvas 2D** — harici JS kütüphanesi yok,
  npm derleme adımı yok, `python main.py dashboard` ile çalışır.

**Dürüstlük ilkesi:** Panelde görünen HER sayı gerçek bir veritabanı
kaydından gelir. Senaryo demo scriptleri RFC 5737 dokümantasyon adres
aralıklarını kullanır (bu adresler tanım gereği gerçek bir cihaza ait
olamaz) ve panelde "Senaryo (RFC 5737)" olarak etiketlenir.

## Faz 11 — Aktif Savunma & Aldatma (tamamlandı)

> **Etik/hukuki çerçeve:** "Misilleme" değil, **aktif savunma**. Başka bir
> sisteme saldırmaz (hack-back yoktur — bu birçok ülkede suçtur). Tüm eylemler
> kendi honeypot yüzeyimizde kalır; dışarıya saldırı amaçlı tek paket gitmez.
> Bu, MITRE Engage / active-defense literatürünün savunulabilir uygulamasıdır.

- [x] **Tarpit** (`arachne/active_defense/tarpit.py`): saldırganı kasıtlı
  yavaşlatarak zamanını harcar (endlessh/LaBrea mantığı). Gecikme
  uyarlanabilir — düşük tehditli bağlantı neredeyse hiç bekletilmez (meşru
  kullanıcıyı cezalandırmamak için), yüksek tehditli/tekrarlayan saldırgan
  maksimuma yaklaşır. Maksimum gecikme sınırlı (kendi kaynağımızı koruruz).
- [x] **Aldatma motoru** (`deception.py`): yüksek tehditli saldırgana gerçek
  hata yerine inandırıcı ama **sahte** veri döner — sahte /etc/passwd, sahte
  dizin listesi, sahte "giriş başarılı". Amaç iki yönlü: saldırganı meşgul
  etmek ve niyetini gözlemlemek. Sahte veri gerçek hiçbir bilgi içermez.
- [x] 15 birim testi. Testler, aktif savunmanın başka sisteme dokunmadığını
  ve tüm eylemlerin kendi yüzeyimizde kaldığını da doğrular.

## Faz 12 — Honeytoken & Canary Sistemi (tamamlandı)

- [x] **Honeytoken kasası** (`arachne/active_defense/honeytokens.py`): hiçbir
  meşru amacı olmayan, yalnızca tuzak için var olan izlenebilir değerler
  (sahte AWS anahtarı, API key, DB bağlantısı, JWT, canary URL, SSH anahtarı).
  Gerçek servislerin format desenlerini taklit eder (AKIA…, sk_live_…) ki
  saldırgan gerçek sanıp kullansın.
- [x] **Tetikleme tespiti**: bir honeytoken kullanıldığı an, bu neredeyse
  kesin bir ihlal kanıtıdır — meşru kullanıcılar bu değerlerin varlığından
  habersizdir, dolayısıyla **yanlış pozitif oranı ~sıfırdır**. Bu, güvenlik
  izlemesinin en düşük-gürültülü sinyallerinden biridir (ticari karşılığı:
  Thinkst Canary).
- [x] Aldatma yanıtlarına gömülü honeytokenlar: saldırgan "çaldığı" tokeni
  başka yerde denerse yakalanır. Süreçler/sensörler arası (DB üzerinden) çalışır.
- [x] Honeypot yolu her yükü honeytoken'lara karşı kontrol eder.

## Faz 13 — Gelişmiş Kodlama Çözücü & Entropi (tamamlandı)

- [x] **İleri kodlama katmanları** (`arachne/reverse/advanced_decoder.py`):
  ROT13/Caesar, ondalık/hex karakter kodları (JS `String.fromCharCode`,
  HTML `&#NN;`), SQL `CHAR()`/`CHR()` zincirleri, PHP `chr()` birleştirmeleri,
  **gzip/zlib + base64** (sıkıştırılmış yük), ters çevrilmiş diziler, SQL
  yorum enjeksiyonu (`/**/`) temizliği.
- [x] **Shannon entropi analizi**: yüksek entropi (~6.5+ bit/karakter)
  sıkıştırılmış/şifrelenmiş — yani kasıtlı gizlenmiş — yüke işaret eder;
  meşru HTTP trafiği bu kadar rastgele değildir.
- [x] **Polyglot tespiti**: bir yük birden fazla bağlamda (hem SQL hem XSS
  hem Shell) geçerli saldırı içeriyorsa — birden fazla ayrıştırıcıyı atlatma
  girişimi — işaretlenir ve tehdit skoru yükseltilir.
- [x] Faz 5 analiz hattına entegre; 14 birim testi.

## Faz 14 — İmza Kural Motoru (YARA-benzeri) (tamamlandı)

- [x] **Bildirimsel kural dili** (`arachne/detection/rule_engine.py`):
  kurallar **veri** olarak tanımlanır, **derlenir** (regex önceden compile,
  bozuk kural çalıştırılmadan yakalanır) ve bir yüke karşı çalıştırılır.
- [x] Koşul türleri: `contains`, `icontains`, `regex`, `length_above`,
  `entropy_above`, `count_above`. Kural koşulu: `all` / `any` / `N of`.
- [x] **Açıklanabilirlik**: bir kural tetiklendiğinde HANGİ string'lerin
  eşleştiği de dönülür — "kural X tetiklendi çünkü s1, s3 eşleşti".
- [x] 7 yerleşik kural (SQLi UNION/blind, RCE zinciri, XSS, path traversal,
  yüksek entropi, web shell). 18 birim testi (yanlış pozitif kontrolü dahil).

## Faz 15 — İstatistiksel Anomali & Flood Tespiti (tamamlandı)

- [x] **Flood/DDoS tespiti** (`arachne/detection/anomaly.py`): kayan pencere
  hız ölçümü + öğrenilen taban çizgisi (baseline) üzerine **z-score** ile
  ani artış tespiti. Baseline'ın çok üstündeki hacim flood alarmı verir.
- [x] **Dağılım anomalisi**: bir kaynağın davranış dağılımı (servis/port)
  popülasyondan sapıyorsa (herkes web'e giderken bu IP sadece MySQL'i döverken)
  işaretlenir.
- [x] 7 birim testi.

> **Dürüstlük notu:** Bu bir DDoS *tespit* göstergesidir, gerçek internet
> ölçekli bir DDoS *azaltma* sistemi değildir (o, ISS/anycast seviyesinde
> ayrı bir mühendislik alanıdır). "Anormal hacmi tespit et ve işaretle"
> yeteneğini kuruyoruz; durdurmayı SOAR katmanı yapar.

## Faz 16 — Otomatik İmza Üretimi (feedback loop) (tamamlandı)

- [x] **İmza sentezi** (`arachne/intel/signature_synth.py`): yakalanan kötü
  niyetli yüklerden ortak n-gram'ları çıkarır, her aday için **yanlış pozitif
  kontrolü** yapar (bu dizi meşru trafikte de görünüyor mu?) ve ayırt edici
  olanları aday imza olarak önerir. Klasik bilgi-getirisi (information gain)
  problemi.
- [x] **İnsan onayı**: üretilen imzalar OTOMATİK aktif edilmez — "aday" olarak
  işaretlenir. Kötü bir otomatik imza meşru trafiği engelleyip kendi kendine
  DoS yaratabilir. Otomasyon öneri getirir, kararı insan verir.
- [x] Aday imzalar Faz 14 kural formatına çevrilebilir. 5 birim testi.

## Faz 17 — Kurcalama-Kanıtı Denetim Zinciri (tamamlandı)

- [x] **Hash zinciri** (`arachne/integrity/audit_chain.py`): her kayıt
  öncekinin hash'ini içerir — H(n)=SHA256(veri(n)+H(n-1)). Ortadaki tek bir
  kaydı değiştirmek sonraki tüm hash'leri bozar; kurcalama kanıtlanabilir olur.
- [x] **Merkle kökü**: tüm kayıt kümesini tek bir 32-byte parmak iziyle
  özetler; ayrı güvenli bir yere yazılıp periyodik doğrulanabilir.
- [x] Panel, SOAR denetim kayıtlarından bir zincir kurup "kayıtlarımız
  kurcalanmış mı?" sorusunu canlı yanıtlar. 12 birim testi.

> **Dürüstlük:** Buna "hafif blockchain" diyoruz ama gerçek dağıtık
> blockchain (proof-of-work, consensus) değildir — bize gereken tek şey
> kurcalama tespiti; onun için hash zinciri kriptografik olarak yeterlidir.

## Faz 18 — Çok Faktörlü Risk Skorlama (tamamlandı)

- [x] **Risk motoru** (`arachne/intel/risk_engine.py`): Risk = Olasılık ×
  Etki. Olasılık (otomatik/hedefli, kill chain ilerlemesi, tekrarlayan,
  kampanya üyeliği) ve Etki (saldırı sınıfı, ters kabuk/web shell) ayrı
  eksenlerde hesaplanır.
- [x] **Açıklanabilir vektör**: "Risk 82 çünkü hedefli saldırgan (+25), RCE
  denemesi (+30), kill chain %57 (+15)…" — ham bir sayıdan çok daha anlamlı.
- [x] CVSS'in temel vektör mantığını küçük ölçekte taklit eder (ama CVSS
  değildir — CVSS zafiyet puanlar, biz saldırgan davranışı puanlıyoruz).
- [x] Panelde risk-sıralı saldırgan tablosu. Risk hesabı test dosyasında
  doğrulanır (Faz 16/18/19 ortak: 18 birim testi).

## Faz 19 — Saldırı Grafiği & Kill Chain Modelleme (tamamlandı)

- [x] **Saldırı grafiği** (`arachne/intel/attack_graph.py`): bir saldırganın
  olaylarından yönlü graf kurar — düğümler kill chain aşamaları, kenarlar
  zaman içindeki geçişler. Saldırganın izlediği YOLU görselleştirir.
- [x] **Bir sonraki adım tahmini**: bu aşamadan sonra tipik olarak ne gelir?
- [x] **Yatay hareket (lateral movement)** modellemesi: saldırgan servisler
  arasında gezinirken.
- [x] **Doğal dilde anlatı (storyline)**: "Saldırgan keşif ile başladı →
  sömürü → kurulum'a ilerledi. 3 farklı servis arasında gezindi…" Kurumsal
  EDR/XDR ürünlerinin "attack storyline" özelliğinin küçük karşılığı.

## Faz 20 — Yeniden Tasarlanan Komuta Merkezi (tamamlandı)

- [x] **Tek-sayfa uygulama (SPA)**: eski dev-kaydırmalı panel, sol menüden
  geçilen **8 temiz görünüme** bölündü — Genel Bakış, Çelik Kubbe, Canlı Akış,
  Tehdit İstihbaratı, Tersine Mühendislik, Kurallar & Bütünlük, SOAR & Aktif
  Savunma, Sensör Ağı. Her görünüm tek bir işe odaklanır.
- [x] **İki hızlı poll döngüsü**: `/api/state` (4sn, canlı sayaçlar/görseller)
  ve `/api/deep` (20sn, pahalı analiz — profilleme, risk, saldırı grafiği,
  kural motoru, bütünlük). Ağır hesap hızlı döngüyü yavaşlatmaz.
- [x] **Birleşik toplayıcı** (`arachne/reporting/aggregator.py`): 20 fazın
  verisi tek yerde, düzenli bir sözleşmede toplanır.
- [x] Tüm görselleştirmeler saf Canvas 2D (dome, harita, radar, zaman
  çizelgesi, entropi çubuğu) — harici JS kütüphanesi/npm yok.
- [x] macOS AirPlay (port 5000) çakışması için `--port` seçeneği ve panelde
  net yönlendirme.

**Bu fazda düzeltilen gerçek entegrasyon hatası:** `check_payload_for_tokens`
kolaylık fonksiyonu honeytoken tetiklemesini tespit ediyor ama kalıcı
kaydetmiyordu (sadece `HoneytokenVault.check()` kaydediyordu). Uçtan uca
testte fark edildi ve düzeltildi.


# ADAPTİF SAVUNMA — Faz 21-30 (tamamlandı)

> **Tez: KO-EVRİM.** Faz 1-20 "saldırıyı gör, skorla, durdur, kaydet" hattıydı.
> Faz 21-30 bir adım öteye geçer: saldırgan savunmamızı **gözleyip taktik
> değiştirirse**, savunma da ona göre **adapte olur**. Statik duvar değil,
> saldırganla birlikte evrilen savunma. Her modül gerçek, adıyla anılan bir
> çerçeveye dayanır. **Etik değişmez:** tamamen savunma; hiçbir modül başka
> sisteme dokunmaz (hack-back yok). "Adaptif" olmak = kendi savunma
> yapılandırmamızı saldırganın davranışına göre yeniden düzenlemek.

## Faz 21 — Düşük-ve-Yavaş Tespiti (CUSUM/EWMA) (tamamlandı)

- [x] `arachne/adaptive/slow_detector.py`: flood eşiğinin **altında** kalarak
  kaçmaya çalışan sabırlı saldırganı yakalar. CUSUM kontrol kartı (birikimli
  sapma), EWMA kayma ve **inter-arrival ritim düzenliliği** (makine ritmi
  insan ritminden daha düzenlidir). Grounds: Darktrace "low and slow",
  D3FEND User Behavior Analysis. 12 test.

## Faz 22 — Parmak İzi & Kimlik Rotasyonu (JA3/JA4) (tamamlandı)

- [x] `arachne/adaptive/fingerprint.py`: tek bir aktörün user-agent/IP
  döndürerek **çok kimlik** gibi görünmesini (Sybil), değişebilir katmanın
  altındaki parmak izinden yakalar. JA3/JA4 mantığı (sıralı TLS/başlık
  öznitelikleri hash'i), imkânsız kombinasyon tespiti (Chrome UA + python
  TLS). Grounds: JA3/JA4, Cloudflare/Suricata/Zeek, D3FEND Identifier
  Analysis. 12 test.

## Faz 23 — Aldatma Ağı & Kırıntı Yolu (tamamlandı)

- [x] `arachne/adaptive/deception_grid.py`: katmanlı aldatma. Gerçek çapalara
  **kırıntı** (sahte kimlik/oturum) serpilir; bunlar kademeli sahte düğümlere
  işaret eder. Belirgin tuzaklardan kaçan gelişmiş saldırgan bile kırıntı
  yolunu izleyip 2-3. katman sahte düğüme düşer. Bir sahte düğüme dokunmak
  **yanlış-pozitif ~sıfır** ihlal kanıtıdır. Grounds: MITRE Engage, kurumsal
  deception (Acalvio/Zscaler/Fidelis), Thinkst Canary. 11 test.

## Faz 24 — Topluluk Tespit Motoru (Ensemble) (tamamlandı)

- [x] `arachne/adaptive/ensemble.py`: birden çok bağımsız dedektörü **ağırlıklı
  skor + k-of-N oylama** ile birleştirir. Tek bir kuralı tersine mühendislikle
  atlatmak sistemi atlatmaya yetmez. Aldatma-teması dedektörü diğerlerinden
  bağımsız ve yanlış-pozitifi ~sıfır olduğu için tek başına bile yeter.
  Grounds: savunma-derinliği, IDS ensemble literatürü. Test: test_adaptive_core.

## Faz 25 — Sıfır Güven Politika Motoru (NIST 800-207) (tamamlandı)

- [x] `arachne/adaptive/zero_trust.py`: "asla güvenme, hep doğrula". Her istek
  oturum bazında güven skoruyla değerlendirilir (PDP/PEP modeli); düşük güven
  reddedilir/challenge edilir/sahte ortama yönlendirilir. Mikrosegmentasyon
  grafı yatay hareketi engeller. Grounds: NIST SP 800-207 (7 ilke, PE/PA/PEP).
  12 test.

## Faz 26 — Adaptif Savunma Duruşu (tamamlandı)

- [x] `arachne/adaptive/posture.py`: **ko-evrimin merkez düğmesi.** Tehdit
  seviyesine göre yükselen/düşen durum makinesi: NORMAL → ELEVATED → HIGH →
  CRITICAL. Tırmandıkça daha güçlü ama maliyetli savunmalar açılır (MTD
  rotasyonu, sıfır-güven bütçe kısıtı, izolasyon). **Histerezis** ile tek bir
  gürültü tepesi sistemi savurmaz. Grounds: CISA "Shields Up", MITRE Center
  for Threat-Informed Defense. Test: test_adaptive_core.

## Faz 27 — Oyun-Teorik Savunma (Stackelberg) (tamamlandı)

- [x] `arachne/adaptive/game_theory.py`: savunan vs. adapte olan saldırgan bir
  **Stackelberg (lider-takipçi) oyunu** olarak modellenir. Savunan önce
  karışık (rastgele) stratejiye bağlanır; saldırgan bunu gözleyip en iyi
  yanıtı verir. Ko-evrim turlarında **re-randomize eden savunma** faydayı
  korurken statik savunma toprak kaybeder — MTD'nin biçimsel gerekçesi.
  Grounds: Stackelberg güvenlik oyunları (Tambe/USC — ARMOR/PROTECT). 11 test.

## Faz 28 — D3FEND & NIST CSF 2.0 Kapsam Haritası (tamamlandı)

- [x] `arachne/adaptive/coverage.py`: her fazı gerçek çerçeve tekniklerine
  eşler ve **kapsam karnesi** çıkarır. MITRE D3FEND'in 7 üst taktiği (Model,
  Harden, Detect, Isolate, Deceive, Evict, Restore) + NIST CSF 2.0'ın 6
  fonksiyonu (Govern, Identify, Protect, Detect, Respond, Recover). Jüriye
  gösterilecek **dört sütunlu eşleme** (Faz → D3FEND → CSF → karşıladığı
  ATT&CK). Projeyi "ad-hoc script" olmaktan çıkarıp threat-informed defense
  seviyesine taşır. Test: test_adaptive_core.

## Faz 29 — Kolektif Savunma & Gösterge Paylaşımı (STIX) (tamamlandı)

- [x] `arachne/adaptive/collective.py`: **sürü bağışıklığı.** Bir sensör bir
  saldırganı (parmak izi/IOC) yakalayınca yapılandırılmış göstergeyi paylaşır;
  saldırgan diğer sensörlere ulaşmadan hepsi bağışıklanır. Ulusal-CERT tarzı
  koordineli savunma ve STIX 2.1/TAXII bilgi paylaşımını modeller.
  "Paylaşım olmasaydı her sensör ayrı ayrı keşfetmeliydi" tasarrufunu
  ölçer. Grounds: ulusal CERT, STIX/TAXII, MITRE Engage. 10 test.

## Faz 30 — Genişletilmiş Komuta Merkezi & Çok-Katmanlı Kubbe (tamamlandı)

- [x] **Gök kubbe 5 → 14 halkaya (~2.8x)** genişletildi. Yeni halkalar Faz
  21-30 adaptif katmanlarını temsil eder; her halkanın "interceptions" değeri
  gerçek veriden türetilir (uydurulmaz; veri yoksa halka boş kalır — dürüstlük).
- [x] Panele **"Adaptif Savunma" görünümü** eklendi: duruş merdiveni, D3FEND/CSF
  kapsam karnesi, oyun-teorik ko-evrim tablosu, aldatma-ağı topolojisi,
  kolektif bağışıklık, dört-sütunlu eşleme tablosu.
- [x] `aggregator.adaptive_view()` + `/api/deep` içinde `adaptive` yükü.
  Toplam **387 test** yeşil.


# YARIŞMA SERTLEŞTİRMESİ — Faz 31-40 (TAMAMLANDI — motor + panel)

> **Amaç:** Sistemi katmanlı bir SOC hattına dönüştürmek (Sensör → Veri Toplama →
> SIEM → Tehdit İstihbaratı → Signature/Behavior → AI Correlation → Risk → SOAR →
> Olay Sonrası) ve başarıyı **gerçek benchmark verisiyle kanıtlamak**. Etik
> değişmez: tamamen savunma, hiçbir eylem başka sisteme dokunmaz.
>
> **DURUM:** Backend motorları/API'leri/testleri (481 test yeşil) VE tüm panel
> görünümleri tamamlandı: metrikler (39), SOAR (37), IOC korelasyon grafiği (33),
> Attack Replay oynatıcı (35/40), açıklanabilir Reverse (36) ve **Canlı Akış'ta
> gerçek varlık ilişki grafiği** (her düğüm gerçek IP/servis/sensör, tıklanabilir).
> Faz 1-40 tam.

## Faz 31 — Sensör Sağlığı & Telemetri (tamamlandı)
- [x] `arachne/mesh/health.py`: heartbeat, packet-loss (dizi boşluklarından),
  veri bütünlüğü, uptime; filo sağlık raporu. HMAC-SHA256/nonce/timestamp/replay
  korunur (Faz 9). Grounds: SNMP/health-check, SIEM sensor monitoring.

## Faz 32-33 — SIEM Normalizasyon + IOC Korelasyon Grafiği (motor tamamlandı · grafik görseli bekliyor)
- [x] `arachne/siem/normalizer.py`: olayları IP/domain/hash/kullanıcı/cihaz/
  process/zaman varlıklarına ayırır; ECS (Elastic Common Schema) uyumlu.
- [x] `arachne/intel/correlation_graph.py`: IOC→olay→saldırgan→ATT&CK→kampanya→
  hedef tipli grafiği; açılabilir node ilişkileri. Grounds: STIX 2.1, ATT&CK.
- [x] `aggregator.correlation_view` + `/api/deep` bağlı.
- [x] **Panel:** Tehdit İstihbaratı'nda 5 sütunlu (IOC→Saldırgan→ATT&CK→Kampanya→
  Hedef) tıklanabilir/açılabilir korelasyon grafiği CANLI.

## Faz 34-35 — AI Korelasyon + 9-Aşamalı Kill Chain (tamamlandı — Attack Replay CANLI)
- [x] `arachne/intel/correlator.py`: düşük seviyeli olayları kampanya/saldırı
  zincirine birleştirir (deterministik korelasyon, LLM değil).
- [x] `arachne/intel/attack_stages.py`: Recon→Scanning→Initial Access→Execution→
  Persistence→Priv Esc→Credential Access→Lateral→Exfiltration; her aşamaya
  devreye giren savunma katmanı + Attack Replay zaman çizelgesi verisi.
- [x] `aggregator.replay_view` + `/api/deep` bağlı.
- [x] **Panel:** "Saldırı Tekrarı" oynatıcısı CANLI — yavaşlat/geri al/scrubber,
  adım adım kill chain, her aşamada devreye giren savunma katmanı.

## Faz 36-37 — Açıklanabilir Tersine Mühendislik + SOAR Genişletme (tamamlandı)
- [x] `arachne/reverse/explainer.py`: SQLi/Command Injection/XSS/encoding/polyglot/
  prompt-injection için NEDEN tespit edildi + eşleşen pattern'ler + confidence +
  MITRE tekniği. `aggregator.explain_payload` bağlı.
- [x] SOAR (panelde canlı): 5→9 playbook, 9→12 eylem (oturum sonlandırma,
  izolasyon, analist bildirimi + credential-access/lateral-movement/
  exfiltration/honeytoken-breach).
- [x] **Panel:** açıklanabilir tespit gösterimi Tersine Mühendislik görünümünde
  CANLI (neden + pattern tablosu + confidence + MITRE + kaçınma notu).

## Faz 39 — Metrik & Değerlendirme Motoru (tamamlandı)
- [x] `arachne/metrics/evaluation.py`: Precision, Recall, F1, Detection Rate,
  FPR, FNR, MTTD, MTTR, P95 tespit gecikmesi, events/sec, müdahale başarı oranı,
  sensör sağlığı. Panelde "Genel Bakış" gerçek metrikleri gösterir.

## Faz 40 — Benchmark Harness + Uçtan-Uca Demo (benchmark + e2e tamamlandı · Attack Replay görseli bekliyor)
- [x] `arachne/benchmark/harness.py` + `scripts/demo_benchmark.py`: binlerce
  ETİKETLİ senaryoyu gerçek tespit hattından geçirir; her biri için Attack→
  Detection→Correlation→Response→Result zinciri. **Ölçülen sonuç: sadece-imza
  F1=0.834 → tam katmanlı sistem F1=0.976 (+0.142), yanlış pozitif %0.**
- [x] `scripts/demo_e2e.py`: tek saldırı, 9 adım uçtan uca (sensör→SIEM→
  istihbarat→tespit→aşama→korelasyon→risk→SOAR→kapanış).
- [x] Toplam **481 test** (+94). DURUSTLUK: metrikler yalnızca etiketli benchmark
  kümesinde ölçülür; mutlak gerçek-dünya garantisi verilmez.
- [x] **Panel:** Attack Replay oynatıcısı CANLI.

## Panel görselleştirmeleri — HEPSİ CANLI
- [x] Attack Replay oynatıcı (Faz 35/40)
- [x] IOC korelasyon grafiği (Faz 33)
- [x] Açıklanabilir Reverse paneli (Faz 36)
- [x] Canlı Akış'ta gerçek varlık ilişki grafiği (her düğüm gerçek IP/servis/
  sensör; tıkla → ilişkiler + detay açılır)


# İLERİ SAVUNMA + SİNEMATİK KOMUTA MERKEZİ — Faz 41-50 (TAMAMLANDI)

DÜRÜSTLÜK: Faz 41-44 gerçek, test edilmiş tespit motorlarıdır; her biri
Çelik Kubbe'de kendi halkasıyla temsil edilir ve sayıları GERÇEK veriden
türetilir (veri yoksa 0 = "bu koşuda tetiklenmedi"). Faz 45-50 komuta
merkezinin görsel/işitsel/etkileşim katmanıdır. Kubbe artık **18 halka**.

## Faz 41 — C2 İşaret (Beacon) Tespiti (tamamlandı)
- [x] `arachne/adaptive/beacon.py`: `BeaconMonitor` + `beacon_score()`.
  Bir IP'nin olay zaman damgalarındaki periyodik ritmi (C2 geri-arama)
  jitter/düzenlilik ile yakalar. Kubbe halkası: **C2 İşaret Tespiti**.

## Faz 42 — Sıfır-Gün Sezgisi (Novelty) (tamamlandı)
- [x] `arachne/adaptive/novelty.py`: karakter n-gram nadirliğiyle daha önce
  görülmemiş yükleri işaretler. Leave-one-out ile "her şeyi novel sayma"
  tuzağından kaçınır. Kubbe halkası: **Sıfır-Gün Sezgisi**.

## Faz 43 — Bayes Tehdit Füzyonu (tamamlandı)
- [x] `arachne/adaptive/threat_fusion.py`: bağımsız dedektör sinyallerini
  log-odds (Bayes) ile birleştirip tek olasılık üretir; hangi faktörün ne
  kadar katkı yaptığını açıklar. Kubbe halkası: **Bayes Tehdit Füzyonu**.

## Faz 44 — İmkânsız Seyahat (Geo-Velocity) (tamamlandı)
- [x] `arachne/adaptive/geo_velocity.py`: aynı aktörün (/24) bölgeler arası
  fiziksel imkânsız hızda görünmesini haversine ile yakalar. Kubbe halkası:
  **İmkânsız Seyahat**. (Jitter'sız bölge merkezleri → yanlış pozitif yok.)

## Faz 45-46 — Sinematik Çelik Kubbe + Küresel Harita (tamamlandı)
- [x] `command_center.js` yeniden yazıldı: atmosferik gökkubbe gradyanı +
  toz, dönen radar tarama huzmesi, halkalarda akan enerji, çok-katmanlı şok
  dalgaları + kalkan parıltısı, dönen reaktör çekirdek. Harita: parlayan
  kıyı şeritleri, nabızlı düğümler, kayan enerji yayları, sonar darbeleri.
  Tümü gerçek-zamanlı; altındaki sayılar tamamen gerçek.

## Faz 47 — Ortak Telsiz/SFX Motoru (tamamlandı)
- [x] `boot.js` `window.ArachneSFX`: nav geçişinde telsiz "kanal değişti"
  cızırtısı, hover tık, onay tonu, kritik klakson — giriş sesiyle AYNI
  prosedürel Web Audio motoru (sessel bütünlük).

## Faz 48 — AI Komuta Asistanı (tamamlandı)
- [x] `arachne/ai/assistant.py` + `/api/assistant` + `assistant.js`:
  operatör Türkçe doğal dilde sorar ("savunma durumu ne?", "en riskli
  saldırgan kim?"); asistan GERÇEK sistem verisinden yanıtlar ve sesli okur.
  Salt-okunur, harici LLM yok, deterministik (niyet sınıflandırma).

## Faz 49 — Proaktif Saldırı Anonsu (tamamlandı)
- [x] Yeni saldırı geldiğinde asistan otomatik, profesyonel durum raporu
  verir: "Saldırı tespit edildi · N yeni olay · karşılayan hat · SAVUNMA
  AKTİF — çekirdeğe sızıntı YOK". Görsel kart + sesli anons (kısılır, mute'e
  saygılı) + kritik klakson. `command_center.js` → `arachne:attack` olayı.

## Faz 50 — Sinematik yoğunluk katmanı + 50-faz bütünlüğü (tamamlandı)
- [x] `fx.js` sinematik HUD (köşe braketleri, üst ray + saat, kayan
  telemetri şeridi, scanline, arka plan parçacık/ızgara/veri-yağmuru).
  Boot/sidebar "50 FAZ", kubbe "18 halka" olarak bütünlendi.
- [x] Toplam **529 test** yeşil.

# GLOBAL SEVIYE — Faz 61-70 (TAMAMLANDI)

DURUSTLUK korunur: yeni dedektor gercek veriden turer (veri yoksa 0); tum
gorseller kozmetiktir, altindaki sayilar gercektir. Toplam **546 test** yesil.

## Faz 61 — Tarama & Kaba-Kuvvet Hiz Dedektoru (tamamlandi)
- [x] `arachne/adaptive/scan_bruteforce.py`: yatay port/servis taramasi ve
  ayni servise hizli tekrarli kaba-kuvvet/kimlik-doldurma tespiti; `SweepMonitor`
  + `analyze_recent()`. Testler: `tests/test_scan_bruteforce.py`.

## Faz 62 — AI Komuta Asistani genisletme (tamamlandi)
- [x] Yeni niyetler: beacon, novelty (sifir-gun), geo (imkansiz seyahat),
  fusion (Bayes), scan (tarama/kaba-kuvvet), health (sistem sagligi),
  layer_detail (belirli katman sorgusu). Hepsi GERCEK veriden, dogru Turkce
  seslendirmeyle (ozel `_LAYER_SPOKEN`/`_say_posture` ile ı/i dogru okunur).

## Faz 63 — Profesyonel Kritik-Olay Rayi (tamamlandi)
- [x] `static/js/incidents.js` + `#incident-rail`: sag kenarda canli KRITIK
  ALARM kartlari (IP, skor, zaman) — SCADA mimic-wall hissi. `/api/state`ten.

## Faz 64 — 3B Dunya derinlestirme (tamamlandi)
- [x] `globe3d.js`: gunes/terminator + prosedurel gece SEHIR ISIKLARI (shader),
  parlayan huzme yaylar, nabizli dugum haleleri, onem-renk gostergesi,
  fresnel atmosfer; yeni saldirgan bolgesi one doner ve buyur.

## Faz 65 — 3B Kalkan Kubbe derinlestirme (tamamlandi)
- [x] `dome3d.js`: enlem/boylam aksan cizgileriyle KATI enerji kalkani hissi,
  isin carpmasinda HEX KALKAN CATLAGI + yerel flas, tarama temas blipleri,
  okunakli plakali etiketler.

## Faz 66-67 — Birlesik Cam + 3B Tasarim Dili (tamamlandi)
- [x] Tum gorunumlerde cam (glassmorphism) paneller + canli 3B arka plan;
  saldiri aninda tum cerceve KIRMIZI alarm; tutarli aksan/tipografi cilasi.

## Faz 68 — Konsolide ko-evrim gorunumu (tamamlandi)
- [x] `aggregator.coevolution_advanced()`: beacon/novelty/geo/fusion/tarama
  ozetini tek, durust (0-guvenli) API'de birlestirir; asistan bunu kullanir.

## Faz 69-70 — Testler + butunluk (tamamlandi)
- [x] 529 -> **546 test** yesil; ROADMAP/README Faz 70'e guncellendi.

# ULTRA SEVIYE — Faz 71-80 (TAMAMLANDI)

DURUSTLUK korunur: yeni dedektorler gercek veriden turer (yoksa 0). Toplam **580 test** yesil.

## Faz 71 — Sinematik 3B Acilis/Guc Ekrani (tamamlandi)
- [x] `static/js/boot3d.js`: Three.js ile isikli, saydam, cok katmanli donen
  reaktor cekirdegi (jeodezik tel-kafes + yorunge parcaciklari + enerji halkalari
  + hacimsel hale). Guc tusuna basinca `ignite()` ile maviden beyaza isinir,
  enerji dalgasi yayar. boot.js entegrasyonu; WebGL yoksa 2B'ye duser.

## Faz 72-73 — Tum Gorunumlere Siber/3B Tasarim Dili (tamamlandi)
- [x] `app.css` + `static/js/views_fx.js`: KPI/metrik tile'larda neon kenar,
  kose braketleri, tarama-cizgisi shimmer, veri cubuklari (fx-meter), sayac
  animasyonu; liste/satir gorunumlerinde onem-renk aksani + glow; siber baslik
  cizgileri. Duz-yazi kalan sayfalar canli/profesyonel hale geldi.

## Faz 74 — Kimlik-Doldurma / Parola Spreyi (tamamlandi)
- [x] `arachne/adaptive/credential_spray.py` + testler: cok kullanici / az deneme
  (sprey) ile kaba-kuvveti ayirir; `SprayMonitor` + `analyze_recent()`.

## Faz 75 — Oturum Riski / Etkilesim Derinligi (tamamlandi)
- [x] `arachne/adaptive/session_risk.py` + testler: saldirganin kill-chain'de ne
  kadar derine gittigini (kesif->somuru->kaliciligk) artan agirlikla puanlar;
  bant (DUSUK/ORTA/YUKSEK/KRITIK). attack_stages ile entegre.

## Faz 76 — AI + aggregator entegrasyonu (tamamlandi)
- [x] `aggregator.credential_spray_view/session_risk_view`; asistanda yeni
  `spray` ve `session_risk` niyetleri (dogru Turkce seslendirme).

## Faz 77-80 — Testler + butunluk + tasarim cilasi (tamamlandi)
- [x] 546 -> **580 test** yesil; ROADMAP/README Faz 80'e guncellendi;
  tum yeni JS/CSS tarayicida dogrulandi, sifir konsol hatasi.


## Faz 81-100 — SON HAT: Yer Alti Ultra Savunma Kalesi (GERCEK motor) (tamamlandi)

Gok kubbe (yuzey kalkani) delinirse devreye giren, kubbeden ileri duzey,
tamamen savunma amacli yer alti kalesi. **Animasyon degil — gercek, test
edilebilir bir motor.** Kalkan delindikten <0.1 sn sonra devreye girer.

- [x] **`arachne/lastline/` gercek motor paketi:**
  - `base.py` — ortak sozlesme (DefenseContext, LayerResult, Layer) + FNV-1a
    32-bit (Python<->JS parite cekirdegi).
  - `identity.py` — **HAYALET** hiper hareketli hedef: korunan varligin
    kimligi (IP/port/parmak-izi/tek-kullanimlik jeton) her 100 ms'de
    DETERMINISTIK doner. Ayni (seed, dilim) -> ayni kimlik; sunucu ve tarayici
    birebir ayni uretir (dogrulanabilir MTD, rastgele degil).
  - `fortress.py` — orkestrator: ihlal karari gercek sinyallerden
    (`should_engage`), devreye girince tepki suresi olculur (<100 ms),
    50 katman sirayla `engage()` edilir, sonuclar hash-zinciriyle muhurlenir
    (`integrity_root`). `context_from_live()` aggregator/storage'dan gercek
    baglam kurar (uydurma yok — veri yoksa notr).
  - `layers.py` — **50 GERCEK katman.** 14'u uctan uca tam uygulama: Shamir
    kripto bolme (GF(256)), HOTP (RFC 4226), HKDF (RFC 5869), hash-zinciri +
    Merkle koku, k-of-n Bizans kuorum, homomorfik korleme, bagisiklik
    hafizasi, tarpit ustel geri-cekilme, yem suruleri. 36'si ctx'ten gercek
    deterministik karar ureten modeller.
- [x] **API:** `/api/fortress` (GET durum), `/api/fortress/engage` (tatbikat),
  `/api/fortress/standby`. Kubbe sinyalleri esigi asinca kale otomatik devreye.
- [x] **3B yer alti kasasi** (`bunker3d.js`): inen huni + 50 zirh halkasi + donen
  yem-cekirdek ordusu; gostergedeki kimlik artik **gercek motordan** gelir ve
  sunucuyla **birebir ayni** (FNV-1a paritesi tarayicida dogrulandi).
- [x] **Testler:** +68 lastline testi (Shamir/HOTP/HKDF/hash-zinciri/kuorum/
  homomorfik dogrulugu, tepki<=100ms, 50 katman muhurleme, **golden vektor
  Python<->JS paritesi**, API uc noktalari). Toplam **648 test** yesil.
- [x] **Dogrulama:** headless Chromium — 50 gercek katman, kimlik paritesi
  byte-byte ayni, breach -> AKTIF, 44 katman muhurlu, tepki 0.0 ms, sifir
  konsol hatasi. Butunluk koku canli veriden turer.

**Durustluk notu:** Kavramlar gercek savunma teknikleridir (MTD, sharding,
aldatma, sifir-guven, TPM-vari muhur). "reached_real_asset" daima False —
aldatma+MTD+kuorum ile gercek varliga ulasilmaz olarak modellenir; bu bir
GARANTI degil, olculebilir bir MODEL + gercek kripto uygulamalaridir. Hicbir
katman disari paket gondermez; hack-back yoktur.


## Sıradaki hedefler (stretch-goal, isteğe bağlı)

- İkinci bilgisayar (Windows/x86-64) edinildiğinde Faz 3'ün assembly
  çekirdeğinin x86-64 versiyonu — asıl kazanç, jürinin kendi makinesinde
  de native hızı canlı gösterebilmek.
- DDoS tespiti için trafik-anomali analizi (yine izole ortamda).
- TAXII 2.1 sunucu uç noktaları (STIX üretimi hazır; kalan iş taşıma katmanı).
- Uluslararası CTF'lere katılım (Google CTF, DEF CON quals).


## Sabit ilkeler (her fazda geçerli)

1. **Önce çalışan, test edilmiş, dokümante edilmiş bir MVP** — sonra kapsam
   genişletme.
2. **Mütevazı ve ölçülebilir iddialar.** "Sıfır risk" ya da "kırılamaz" gibi
   ifadeler yerine ölçülen sonuçlar: tespit oranı, yanlış pozitif oranı,
   tepki süresi.
3. Her faz sonunda: README/ARCHITECTURE güncellenir, testler yeşil kalır,
   bir demo/rapor üretilir.
