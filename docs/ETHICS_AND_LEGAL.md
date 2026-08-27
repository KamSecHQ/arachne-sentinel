# Etik ve Yasal Kullanım Notu

Bu proje **savunma amaçlı** (defensive/blue-team) bir güvenlik aracıdır:
sahte servisler açıp size gelen bağlantıları izler. Kendi başına bir
sisteme saldırmaz veya sızmaz.

**Buna rağmen dikkat edilmesi gerekenler:**

- Bu sistemi **yalnızca kendi sahip olduğunuz makinelerde veya izole bir
  lab/VM ortamında** çalıştırın. Başkasına ait bir ağda, izniniz olmadan
  bu servisleri (ya da herhangi bir güvenlik aracını) çalıştırmak birçok
  ülkede (Türkiye'de Türk Ceza Kanunu'nun bilişim suçlarına ilişkin
  hükümleri dahil) suç teşkil edebilir.
- `scripts/demo_attack.py` sadece `127.0.0.1` (kendi bilgisayarınız)
  üzerindeki honeypot servislerine bağlanacak şekilde yazılmıştır — gerçek
  bir saldırı aracı değildir ve başka bir hedefe yönlendirilmemelidir.
- Sistemi internete açık bir sunucuda çalıştırmayı düşünüyorsanız (ör.
  gerçek saldırgan trafiği toplamak için), önce ilgili hosting
  sağlayıcınızın kullanım şartlarını kontrol edin ve bunu ancak konuyu
  gerçekten anladığınızda, bilinçli bir risk değerlendirmesiyle yapın.
- Bu belge hukuki tavsiye niteliği taşımaz. Yarışma başvurusu, üniversite
  projesi ya da başka bir resmi bağlamda kullanmadan önce danışmanınızla
  veya üniversitenizin ilgili biriminden teyit alın.

**Sorumlu açıklama (responsible disclosure) ilkesi:** Bu proje üzerinden
gerçek bir zafiyet ya da saldırı tespit ederseniz, bunu ilgili sistemin
sahibine önce özel olarak bildirin; kamuya açık paylaşım yapmadan önce
makul bir düzeltme süresi tanıyın.

## Faz 4 (Moving Target Defense) için ek not

`python main.py mtd-demo` komutu, kendi honeypot servislerinizin
kimliğini (banner sürümü, dinlenen port, sahte bir DNS yanıtı) periyodik
olarak değiştirir. Bunu doğru anlamak önemli:

- **Bu bir VPN, anonimleştirme aracı veya gerçek internete karşı kimlik
  gizleme ürünü DEĞİLDİR.** Sadece sizin sahip olduğunuz, izole lab
  ortamındaki sahte servislerin kimliğini değiştirir.
- `arachne/mtd/dns_ghost.py`, işletim sisteminizin gerçek DNS ayarlarını
  **değiştirmez**, port 53'ü **kullanmaz** — sadece belgelenmiş bir lab
  portunda (varsayılan UDP 5300) çalışan, kendi kendine sorguladığınız
  bir demo yanıtlayıcısıdır.
- `arachne/mtd/port_hopper.py`'ın açtığı ek port da (varsayılan
  9101-9105 havuzu) sadece localhost/izole ağınızda dinler; gerçek bir
  hedefin kimliğini taklit etmez, sadece kendi sahte "hayalet admin"
  servisinizin dinlediği portu değiştirir.

## Faz 5-10 için ek notlar

### Faz 5 — "Tersine mühendislik" ne demek, ne demek değil

Bu projede "tersine mühendislik", **başkasının yazılımını kırmak veya
kopyalamak** anlamına GELMEZ. Kastedilen, bize gelen saldırının kendisini
analiz etmektir — yani savunma amaçlı adli bilişim (defensive forensics).

- Analiz edilen tek şey, kendi honeypot/WAF kayıtlarımızdır.
- Yükler **hiçbir zaman çalıştırılmaz**: bir kabuğa, SQL sorgusuna, şablon
  motoruna ya da `eval`'e geçirilmez. Sadece metin olarak incelenir.
- Hiçbir harici sisteme bağlanılmaz, hiçbir yazılım tersine derlenmez.

### Faz 6 — Konum tahmini ve dürüstlük

`arachne/intel/geo.py` bir GeoIP veritabanı **değildir**. Şehir seviyesi
doğruluk iddia edilmez ve edilmemelidir. Panelde her konum, hassasiyet
etiketiyle birlikte gösterilir:

- `lab` — yerel lab trafiği, gerçek konum yok
- `region-estimate` — RIR (bölge kayıt kurumu) seviyesinde **tahmin**
- `documentation` — RFC 5737 senaryo/demo adresi
- `unknown` — belirlenemedi

Lab trafiğini sahte bir ülkeye yerleştirmek görsel olarak etkileyici olurdu
ama yanıltıcı olurdu; bilinçli olarak yapmıyoruz.

### Faz 7 — Otomatik müdahalenin sınırları

`python main.py soar-demo` komutu **gerçekten** IP engelleyebilir. Bu yüzden:

- **Loopback (127.0.0.1) ve özel ağ adresleri asla engellenemez.** Bu bir
  kolaylık değil, güvenlik önlemidir: aksi hâlde sistem ilk demo
  saldırısında kendi kendini kilitlerdi.
- Tüm engellemeler **süreli**dir (TTL). Kalıcı engelleme yoktur — yanlış
  pozitif bir kararın kalıcı zarar vermesi mimari olarak engellenmiştir.
- Yıkıcı ya da geri alınamaz eylemler **insan onayına** yükseltilir,
  otomatik uygulanmaz.
- Her otomatik karar, gerekçesiyle birlikte denetim kaydına yazılır.

Bu sistemi kendi ağınız dışında bir yerde çalıştırmayı düşünüyorsanız,
otomatik engellemenin **meşru kullanıcıları da etkileyebileceğini** göz
önünde bulundurun ve önce `--dry-run` benzeri bir gözlem süresi uygulayın.

### Faz 8 — Yapay zekâ katmanı ve veri gizliliği

- API anahtarı **yalnızca ortam değişkeninden** okunur; koda, yapılandırma
  dosyasına ya da veritabanına asla yazılmaz. Depoya yanlışlıkla anahtar
  commit'lenmesi bu şekilde imkânsız hâle getirilmiştir.
- Dil modeli katmanı **varsayılan olarak KAPALIdır**. Açıkça
  etkinleştirilmeden hiçbir veri dışarı gönderilmez.
- Etkinleştirildiğinde, modele gönderilen tek şey **sterilize edilmiş
  saldırı yükü ve yapısal özet**tir. Veritabanı içeriği, kullanıcı verisi
  veya sistem yapılandırması gönderilmez.
- Yerel bir model (Ollama/LM Studio gibi) yapılandırılırsa veri hiç
  makineden çıkmaz — `ARACHNE_LLM_ENDPOINT` bunun için vardır.
- **Yapay zekâ çıktısı hiçbir zaman bir engelleme kararı tetikleyemez.**
  Bu, OWASP LLM06 (Excessive Agency) riskine karşı bilinçli bir sınırdır.

### Faz 9 — Sensör ağı ve paylaşılan sır

- Depoda bulunan varsayılan sır (`arachne-lab-shared-secret-degistirin`)
  **gizli değildir** — açık kaynak bir dosyada durmaktadır.
- Lab dışında herhangi bir kullanımda `ARACHNE_MESH_SECRET` ortam
  değişkeni ile uzun ve rastgele bir sırla değiştirilmelidir.
- Panel, varsayılan sır kullanılıyorsa uyarı gösterir.
- Sensörleri yalnızca **sahibi olduğunuz ya da izniniz olan** ağlara
  yerleştirin. Başkasının ağında trafik dinlemek birçok ülkede suçtur.

### Faz 10 — Senaryo verisi ve şeffaflık

`scripts/demo_global_attack.py` ve `scripts/demo_mesh.py` **senaryo verisi**
üretir. Bu:

- Gerçek internet trafiği değildir.
- Yalnızca RFC 5737 dokümantasyon adres aralıklarını kullanır
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) — bu adresler tanım
  gereği gerçek bir cihaza ait olamaz.
- Panelde "Senaryo (RFC 5737)" olarak etiketlenir.

Bir jüri/değerlendirme sunumunda bu ayrımı **açıkça belirtin**. Senaryo
verisiyle üretilmiş bir görüntüyü gerçek saldırı trafiği gibi sunmak,
projenin en temel ilkesiyle (ölçülebilir ve savunulabilir iddialar)
çelişir.

## Faz 11-20 için ek notlar

### Faz 11-12 — "Misilleme" değil, aktif savunma (KRİTİK)

Bu fazların adı "misilleme" çağrıştırabilir. **Bu proje başka bir sisteme
saldırmaz (hack-back yapmaz).** Karşı-saldırı — başkasının sistemine izinsiz
erişim/zarar — Türkiye'de Türk Ceza Kanunu'nun bilişim suçlarına ilişkin
hükümleri dahil birçok ülkede suçtur.

Burada kurulan şey **aktif savunmadır** ve tamamen kendi kontrolümüzdeki
yüzeyde gerçekleşir:

- **Tarpit** saldırganı *bizim* honeypot'umuzda oyalar; dışarıya saldırı
  amaçlı tek bir paket göndermez.
- **Aldatma** saldırgana sahte veri döndürür; bu veri gerçek hiçbir bilgi
  içermez ve gerçek hiçbir sisteme yaramaz.
- **Honeytoken** tuzakları pasiftir; yalnızca saldırgan onları kullandığında
  bir sinyal üretir.

Bir jüri/değerlendirme sunumunda bu ayrımı **açıkça belirtin**: "aktif
savunma yapıyoruz, karşı-saldırı değil". Bu, projenin en güçlü etik
duruşlarından biridir.

### Faz 15 — Anomali/flood tespiti, azaltma değil

Faz 15 anormal trafik hacmini *tespit eder ve işaretler*; gerçek internet
ölçekli bir DDoS *azaltma* sistemi değildir (o, ISS/anycast seviyesinde ayrı
bir altyapı gerektirir). Bu ayrımı sunumda net tutun.

### Faz 16 — Otomatik imzalar insan onayı olmadan aktif edilmez

Üretilen aday imzalar otomatik olarak canlı tespit hattına alınmaz. Kötü bir
otomatik imza meşru trafiği engelleyerek kendi kendine bir DoS yaratabilir.
Bu, bilinçli bir güvenlik kararıdır.

### Faz 17 — "Blockchain" değil, hash zinciri

Denetim zincirimize "hafif blockchain" benzetmesi yapılabilir ama bu gerçek
bir dağıtık blockchain değildir. Sunumda "kurcalama-kanıtı hash zinciri"
demek, "blockchain" demekten hem daha doğru hem daha dürüsttür.

## Faz 102-107 için ek notlar

> Bu bölüm, Faz 18-101 arasındaki fazlar için bu belgeye ayrı bir not
> eklenmediğini **açıkça** belirtir (proje bu belgeyi Faz 17'den sonra
> güncellemeye ara vermiş) — burada sadece en son eklenen Faz 102-107'nin
> ETİK/GİZLİLİK açısından yeni getirdiği noktalar ele alınıyor. Faz 18-101
> için etik çerçeve [ROADMAP.md](ROADMAP.md)'deki ilgili fazların
> "dürüstlük notu" bölümlerinde dağınık olarak mevcuttur; ayrı bir bölüm
> olarak buraya taşınmamıştır (bilinen, kabul edilmiş bir belgeleme borcu).

### Faz 102 — Dış tehdit istihbaratı: hangi veri nereye gidiyor

`python main.py threat-intel` ve arka plandaki `arachne/intel/threat_intel.py`,
etkinleştirildiğinde bir **saldırgan IP adresini** AbuseIPDB ve/veya
AlienVault OTX'e (üçüncü taraf servisler) gönderir.

- **Varsayılan olarak KAPALIdır** — `ARACHNE_THREAT_INTEL_ENABLED=1` ve en az
  bir API anahtarı olmadan hiçbir veri dışarı gitmez.
- **Sadece public (genel) IP'ler gönderilir.** Loopback/özel ağ/RFC 5737
  dokümantasyon adresleri (yani lab trafiğinizin tamamı) `geo.classify_ip_scope`
  ile filtrelenir ve **asla** dış API'ye gönderilmez.
- Gönderilen tek veri, sorgulanan IP adresidir — payload, kullanıcı verisi,
  veritabanı içeriği ya da sistem yapılandırması **gönderilmez**.
- AbuseIPDB/OTX'in kendi kullanım şartlarını ve gizlilik politikalarını
  kabul etmiş olmanız sizin sorumluluğunuzdadır — bu proje o şartları temsil
  etmez.

### Faz 103 — Genişletilmiş honeypot yüzeyi: gerçekçilik sınırı

Redis/Docker API/Elasticsearch sahte servisleri **gerçekçi görünen** ama
işlevsiz yanıtlar üretir (bkz. `arachne/honeypot/listeners.py`). Bunu
yanlış anlamamak önemli:

- Hiçbiri **gerçek** bir Redis/Docker/Elasticsearch kurulumu değildir; hiçbir
  komut gerçekten çalıştırılmaz, hiçbir konteyner gerçekten başlatılmaz,
  hiçbir arama sorgusu gerçekten işlenmez. Tamamı sabit/şablonlu yanıttır.
- RDP ve SMB servisleri **kasıtlı olarak minimaldir** — gerçek protokol
  müzakeresi yapılmaz, sadece bağlantı/ham bayt loglanır (bkz.
  ROADMAP Faz 103 dürüstlük notu). Bunları "tam RDP/SMB honeypot'u" olarak
  sunmak yanıltıcı olur.
- **Daha fazla port = daha geniş yüzey.** Bu faz, dinlenen port sayısını
  4'ten 10'a çıkarır. "Sadece izole/lab ortamında çalıştırın" ilkesi burada
  daha da kritik hâle gelir — özellikle Docker API portu (2375), gerçek
  hayatta açık bırakıldığında container kaçışına yol açabilen bilinen bir
  saldırı yüzeyini **taklit eder**; bu portu gerçek/güvenilmeyen bir ağa
  açmak, sahte de olsa, port tarayıcıları ve otomatik saldırı botlarını
  makinenize çekebilir.

### Faz 104 — SIEM dışa aktarımı: veri makineden çıkabilir

`python main.py siem-export --syslog-host ...` kullanıldığında, yakalanan
saldırgan olayları (IP, payload metni dahil) **gerçekten** belirttiğiniz
syslog sunucusuna gönderilir.

- **Varsayılan olarak ağ çağrısı YOKTUR** — `--syslog-host` (veya
  `ARACHNE_SIEM_HOST`) verilmedikçe çıktı sadece yerel bir dosyaya yazılır.
- Payload alanı **saldırganın gönderdiği ham metni** içerebilir (SQLi/XSS
  denemeleri, olası kişisel/hassas görünen içerik dahil) — hedef SIEM'in
  bu veriyi nasıl sakladığından/kime gösterdiğinden siz sorumlusunuz.
- CEF alanları enjeksiyona karşı kaçırılır (bkz. `arachne/siem/exporter.py`)
  ama bu bir **format bütünlüğü** önlemidir, veri gizliliği önlemi değildir.

### Faz 105 — Container dağıtımı: aynı kurallar, daha kolay açığa çıkma riski

`docker-compose.yml`, honeypot portlarını host makineye **eşler** (`ports:`).
Bunu bir bulut sunucusunda veya paylaşılan bir ağda çalıştırmak, bu belgenin
en başındaki "yalnızca izole lab" ilkesini ihlal eder — Docker kullanmak bu
ilkeyi gevşetmez, sadece kurulumu kolaylaştırır. `docs/DEPLOYMENT.md`'nin en
üstünde aynı uyarı tekrarlanır.

### Faz 106 — Davranışsal anomali: sentetik taban çizgisi

`arachne/detection/anomaly_ml.py`'nin "normal davranış" taban çizgisi gerçek
kullanıcı/ağ trafiğinden **öğrenilmemiştir** — elle yazılmış, küçük,
illüstratif bir veri kümesidir (bkz. `behavioral_training_data.py`). Bunu
kalibre edilmiş bir üretim modeli gibi sunmak yanıltıcı olur; `anomaly_score`
açıklayıcı bir gösterge olarak sunulmalıdır, kesin bir olasılık olarak değil.

### Faz 107 — NVD CVE zenginleştirmesi: veri minimizasyonu

`arachne/scanner/nvd_lookup.py` NVD'ye (NIST, ABD hükümeti) yalnızca bir
**anahtar kelime** (banner'dan türetilmiş ürün/sürüm ismi, örn. "vsftpd")
gönderir — IP adresiniz, ağ topolojiniz ya da tarama sonuçlarınızın geri
kalanı gönderilmez. Varsayılan olarak kapalıdır.

### Faz 108 — Çekirdek yemi ve anti-parmak-izi: neden ve nasıl

**Saldırgan psikolojisi tasarım ilkesi:** Bu fazda bilinçli bir karar verildi
— sızdırılan sahte veri (`db-internal.local`, `svc_user`) **dramatik veya
"değerli" görünmeyecek şekilde** isimlendirildi. Nedeni: deneyimli bir
saldırgan, "vault-core" ya da "TOP-SECRET" gibi bariz bir isim gördüğünde
bunun bir tuzak olduğunu anlar ve geri çekilir — tam da yakalamak
istediğimiz sofistike aktörü kaçırmış oluruz. Sıradan görünen bir yem,
hem düşük seviye botları hem de deneyimli saldırganları aynı şekilde
yakalayabilir. Bu, "aldatma ne kadar gerçekçiyse o kadar etkilidir"
ilkesinin doğrudan uygulamasıdır — pazarlama abartısı değil, ölçülebilir
bir tasarım tercihi.

**Anti-parmak-izi sertleştirmesi ne yapar, ne yapmaz:**
- Yeni `rule_honeypot_awareness_probe` kuralı, saldırganın ortamı bir
  honeypot/sandbox olarak tespit etmeye çalıştığına dair **bilinen, iyi
  belgeli** işaretleri arar (bilinen honeypot yazılım adları, sanallaştırma
  tespiti komutları, VM MAC önekleri). Bu bir **heuristiktir, kesin kanıt
  değildir** — bazı güvenlik araştırmacıları bu komutları zararsız amaçla
  da çalıştırabilir; bu yüzden kural motorunun DİĞER sinyalleriyle
  birlikte değerlendirilir, tek başına otomatik engellemeye yol açmaz.
- Yanıt gecikmesi (jitter) **güvenlik-kritik bir rastgelelik değildir** —
  sadece zamanlama analiziyle honeypot tespitini zorlaştıran kozmetik bir
  gerçekçilik katmanıdır. `random` modülü (kriptografik olmayan) bilinçli
  olarak yeterlidir; burada tahmin edilemezlik değil, doğal değişkenlik
  hedeflenir.
