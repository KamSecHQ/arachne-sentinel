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
