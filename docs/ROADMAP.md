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
