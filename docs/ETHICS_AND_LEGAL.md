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
