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

## Faz 2: WAF, tarayıcı ve ML katmanı

```
istemci (tarayıcı/istemci)
        │  HTTP isteği
        ▼
┌─────────────────────┐        ┌──────────────────┐
│ waf/middleware.py    │──────▶│  storage (SQLite) │
│ (WSGI middleware)    │  log  │   waf_events       │
└──────────┬───────────┘        └──────────────────┘
           │ engellenmediyse
           ▼
┌─────────────────────┐
│ waf/demo_app.py       │  (bilinçli zafiyetli, korunan gerçek uygulama)
└─────────────────────┘

scanner/vuln_scanner.py ──▶ scanner/port_scanner.py (banner grabbing)
                        └─▶ scanner/known_vulnerabilities.py (eşleştirme)
                        └─▶ storage.log_scan_finding()

detection/rules.py ──▶ detection/ml_classifier.py (TF-IDF + LogisticRegression)
```

**Neden WAF ayrı bir katman, honeypot kuralları değil?** Honeypot pasif
gözlem yapar (kimse gerçekten bir şeyi korumuyor), WAF ise gerçek bir
uygulamayı *aktif olarak* korur — isteği ya geçirir ya da 403 ile
engeller. Bu farklı bir sorumluluk olduğu için ayrı bir modül (`arachne/waf/`)
ve ayrı, daha hassas regex tabanlı imzalar (`waf/rules.py`) kullanıyoruz;
honeypot'un basit alt-string eşleşmesi burada çok fazla yanlış pozitif
üretirdi.

**URL-decode neden kritik?** WAF, HTTP isteklerini (query string, form
body) percent-encoded haliyle alır (`'` karakteri `%27` olarak gelir).
İmza taramasını decode etmeden yapmak saldırıların WAF'ı atlamasına yol
açar — bunu geliştirme sırasında gerçekten yaşadık (ilk versiyonda SQLi/XSS
denemeleri WAF'ı atlatıyordu), `urllib.parse.unquote_plus` ile düzelttik.
Bu, gerçek WAF ürünlerinin de dikkat etmesi gereken klasik bir tuzak.

**Neden ML modeli kural motorunun *yerine* değil de *yanına* eklendi?**
Kural motoru açıklanabilir ama sadece bildiği imzaları yakalar. Küçük,
elle derlenmiş bir eğitim verisiyle (`detection/training_data.py`) eğitilen
TF-IDF + Logistic Regression modeli, karakter n-gram'ları sayesinde hafif
değiştirilmiş varyasyonları da yakalayabilir — ama tek başına güvenilir
değildir (küçük veri seti). Bu yüzden `rule_ml_classifier` diğer kurallarla
birlikte, ek bir sinyal olarak çalışır; kararı tek başına vermez.

**Zafiyet tarayıcı neden `nmap` yerine kendi soket kodunu kullanıyor?**
Bağımlılıksız olsun, herkesin bilgisayarında ekstra bir sistem paketi
kurmasına gerek kalmasın diye. `known_vulnerabilities.py` içindeki liste
bilinçli olarak küçük ve tarihi örneklerden oluşuyor — gerçek bir üründe
NVD API gibi güncel bir kaynakla değiştirilmesi gerektiği README'de ve
ROADMAP'te açıkça belirtiliyor (yanlış/abartılı bir "gerçek zamanlı CVE
tarayıcısı" iddiası olmasın diye).

## Faz 3: ARM64 assembly imza tarama çekirdeği

```
detection/rules.py (rule_known_signature)
        │
        ▼
native/signature_engine.py  ── ctypes ──▶  native/arm64/fast_scan.s  (Apple Silicon)
        │                                    (az_find / az_scan_multi)
        │ (native yoksa/uyumsuz platform)
        ▼
   Python fallback (bytes.find tabanlı, BİREBİR aynı sonuç)

native/tools/byte_inspector.s  ── bağımsız CLI, projeden ayrı çalışır
```

**Neden ctypes köprüsü + zorunlu Python yedeği, sadece native değil?**
Projenin geri kalanı (dolayısıyla testleri, CI'ı, honeypot'un doğruluğu) bir
tek platforma (Apple Silicon Mac) bağımlı olamaz. `signature_engine.py` bu
yüzden native kütüphaneyi *fırsatçı* bir hızlandırma olarak ele alır: varsa
kullanır, yoksa aynı girdi/çıktı sözleşmesine sahip bir Python fonksiyonuna
sessizce düşer. `rule_known_signature`'ın davranışı (hangi imza, hangi
sırada eşleşir) her iki yolda da birebir aynıdır — bunu hem el ile yazılmış
hem fuzz testlerle doğruladık. Bu, "assembly'yi göstermek için assembly
kullanmak" yerine, gerçekten kullanılan bir bileşeni hızlandırmak demektir.

**Neden ARM64 (Apple Silicon), x86-64 değil?** Elimizdeki donanım MacBook
M3 — native derlenmiş bir `.dylib`'in gerçekten çalıştığını uçtan uca
görebileceğimiz tek mimari bu. x86-64 çoğu CTF/eğitim materyalinin standardı
olduğu için ikinci bir bilgisayar edinildiğinde ayrı bir hedef olarak
eklenmesi planlanıyor (bkz. ROADMAP.md); iki mimariyi aynı anda "doğru"
yapmaya çalışmak bu fazda kapsamı gereksiz büyütürdü.

**Mantık nasıl doğrulandı, sadece "derlendi, çalıştı" mı?** Hayır — bu
sandbox x86_64 Linux olduğu için Apple'ın Mach-O ARM64 ikili biçimini
doğrudan çalıştıramıyoruz. Bunun yerine iki adımlı bir doğrulama yapıldı:
(1) aynı assembly mantığı, sembol isimlendirmesi dışında değiştirilmeden,
`aarch64-linux-gnu-as`/`gcc` ile **gerçek ARM64 makine koduna** derlenip
`qemu-aarch64` üzerinde (donanım seviyesinde CPU emülasyonu, yorumlama
değil) 20.000+ rastgele girdiyle C'nin `strstr`'ına karşı fuzz test edildi
— 0 uyuşmazlık; (2) Mac'e taşınırken SADECE Mach-O/Apple clang'e özgü
sözdizimi farkları uygulandı: dış sembollere `_` öneki (`az_find` →
`_az_find`, tıpkı C derleyicisinin her zaman yaptığı gibi) ve adresleme için
GNU/ELF'in `:lo12:` yerine Apple'ın `@PAGE`/`@PAGEOFF` eki. Hesaplama
mantığının kendisi (register kullanımı, karşılaştırma/döngü sırası)
dokunulmadan taşındı.

**`byte_inspector` neden ayrı, projeye entegre olmayan bir araç?** Bilinçli
bir tercih: `fast_scan.s` gerçek bir üretim bileşeni (WAF/honeypot'un
kullandığı), `byte_inspector` ise saf assembly + libc I/O pratiği yapmak
için bağımsız bir demo. İkisini karıştırmak ("hepsi tek bir dev sistem")
yerine ayrı ayrı, her biri kendi başına savunulabilir iki küçük parça
olarak tutuldu.

## Faz 4: Moving Target Defense ("hayalet" savunma katmanı)

```
main.py mtd-demo
   ├─▶ honeypot/listeners.start_all_services(rotator=IdentityRotator)
   │       └─ baglanti geldiginde current_banner() cagirilir, arali
   │          doldiyse rotasyon yapilir ve storage.mtd_rotations'a yazilir
   ├─▶ mtd/port_hopper.PortHopper.run_forever()
   │       └─ gercekten bir port havuzunda (9101-9105) periyodik olarak
   │          kapanip yeniden acilir, her sicrama loglanir
   └─▶ mtd/dns_ghost.run_forever()
           └─ udp 5300'de dinler, her sorguda (veya N sorguda bir) farkli
              bir yerel IP dondurur, her rotasyon loglanir
```

**Neden buna "hayalet" deniyor ama bir VPN/anonimlik ürünü değil?**
Projenin ilk tasarım tartışmalarında hedef, "saldırganlara karşı görünmez
olmak" gibi büyük bir iddiaydı. Bunu iki ayrı soruna ayırdık: (a) *sizi*
(kullanıcıyı) gerçek internette anonimleştirmek — bu, Tor Project gibi
tek başına bir şirketin işi, bizim ölçeğimizde gerçekçi değil; (b) *kendi
korunan sisteminizin* kimliğini saldırgana karşı hareketli/kararsız bir
hedef haline getirmek — bu, "moving target defense" (MTD) olarak bilinen,
akademik güvenlik literatüründe (DARPA'nın da fon ayırdığı) gerçek bir
savunma kategorisi ve tam olarak bizim ölçeğimizde, gerçekten
uygulanabilir. Faz 4, sadece (b)'yi hedefler.

**Rotasyon neden "tembel" (lazy), ayrı bir arka plan thread'i değil?**
`IdentityRotator.current_banner()` her çağrıldığında (yani her yeni
bağlantıda) süresi dolup dolmadığını kontrol eder ve gerekirse o anda
rotasyon yapar. Bu, honeypot'un tek-thread'li asyncio döngüsüne ek bir
zamanlayıcı/thread senkronizasyonu karmaşıklığı eklemeden, deterministik
ve test edilebilir (sahte bir `clock` fonksiyonu enjekte edilebilir)
kalmasını sağlar.

**`port_hopper.py` gerçekten socket kapatıp yeniden açıyor mu, yoksa
simülasyon mu?** Gerçekten kapatıp açıyor: `asyncio.start_server`/`Server.
close()`/`wait_closed()` ile gerçek bir TCP dinleyicisi bir portta durur,
port havuzundaki bir sonraki portta yeniden başlar. `tests/test_mtd.py`
bunu gerçek (rastgele, işletim sisteminden alınmış boş) portlarla uçtan
uca doğrular - hem `hop()` çağrısının portu gerçekten değiştirdiğini hem
de yeni port üzerinden gerçek bir HTTP isteğinin yanıtlanabildiğini test
eder.

**`dns_ghost.py` neden kendi DNS paket ayrıştırıcısını yazdı, bir
kütüphane kullanmadı?** Bilinçli bir tercih (Faz 3'teki "kendi soket
kodunu yaz" ilkesiyle tutarlı): RFC 1035'in küçük, tek-soru/tek-A-kaydı
alt kümesini elle ayrıştırıp üretmek, hem "DNS paketi aslında nasıl
görünür" sorusuna gerçek bir cevap hem de test edilebilir, bağımsız bir
kod parçası. Gerçek bir üretim DNS sunucusu (BIND, dnsmasq vb.) yerine
geçmez ve bunu iddia etmiyoruz.

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
| `arachne/waf/rules.py` | Regex tabanlı WAF imzaları + rate-limit ayarları |
| `arachne/waf/middleware.py` | WSGI middleware: inceler, loglar, gerekirse 403 döner |
| `arachne/waf/demo_app.py` | Bilinçli zafiyetli demo Flask uygulaması |
| `arachne/scanner/port_scanner.py` | Bağımsız port tarama + banner grabbing |
| `arachne/scanner/known_vulnerabilities.py` | Küçük, elle derlenmiş demo zafiyet veri seti |
| `arachne/scanner/vuln_scanner.py` | Tarama + eşleştirmeyi birleştirip storage'a yazar |
| `arachne/detection/training_data.py` | ML modeli için etiketli örnek veri |
| `arachne/detection/ml_classifier.py` | TF-IDF + Logistic Regression sınıflandırıcı |
| `main.py` | CLI giriş noktası (`run` / `report` / `dashboard` / `waf-demo` / `scan` / `train-ml` / `mtd-demo`) |
| `scripts/demo_attack.py` | Honeypot için kendi kendini test eden saldırı simülasyonu |
| `scripts/demo_waf_attack.py` | WAF için kendi kendini test eden saldırı simülasyonu |
| `arachne/native/arm64/fast_scan.s` | ARM64 assembly imza tarama çekirdeği (`az_find`, `az_scan_multi`) |
| `arachne/native/signature_engine.py` | ctypes köprüsü + platform-bağımsız Python yedeği |
| `arachne/native/tools/byte_inspector.s` | Bağımsız native CLI: dosyada bilinen imza taraması |
| `scripts/benchmark_native_scan.py` | Native vs el-yazımı Python vs Python stdlib dürüst kıyaslaması |
| `arachne/mtd/identity_rotator.py` | Honeypot banner/sürüm kimliğinin periyodik rotasyonu |
| `arachne/mtd/port_hopper.py` | Gerçekten port değiştiren "hayalet admin" servisi |
| `arachne/mtd/dns_ghost.py` | Lab-içi, rotasyonlu sahte DNS yanıtlayıcısı |
