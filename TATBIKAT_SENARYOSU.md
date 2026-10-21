# Arachne Sentinel — Kırmızı/Mavi Takım Tatbikat Senaryosu

**Hazırlayan:** Emirhan · **Tarih:** 2026-10-21
**Ortam:** İzole lab ağı (hotspot/LAN) · **Katılımcılar:** Savunmacı (Mavi — Emirhan) · Saldırgan (Kırmızı — öğretim görevlisi)

> Bu belge tatbikatın kurgusunu, görev tanımını, kurulum adımlarını, güvenlik
> garantisini ve skor ölçütlerini tek bir yerde toplar. Gün öncesi ve gün içi
> tek bakışta kontrol için tasarlanmıştır.

---

## 1. Amaç ve doğru konumlama

Arachne Sentinel bir **"kırılamaz kasa" değildir** — hiçbir sistem değildir.
Değeri şudur: **tespit + geciktirme + istihbarat + müdahale.** Bir saldırganı
durdurmaktan çok, **görmek, yavaşlatmak, açıklanabilir şekilde kaydetmek ve
yanıt vermek.**

Bu tatbikatın gösterdiği şey "flag'i aldı mı" değil:

> **Saldırganın her hamlesi görüldü mü, ne kadar sürede yakalandı, MITRE'ye
> eşlendi mi, kaç alarm bıraktı, ne kadar oyalandı — ve kasaya uzandığında
> durduruldu mu?**

---

## 2. Mimari: Açık Tahta + Mühürlü Kasa

İki ayrı yüzey vardır ve biri bilerek açık, biri tamamen kapalıdır:

| Yüzey | Durum | Amaç |
|---|---|---|
| **Aldatma yüzeyi** (sahte servisler, yem uçları) | Bilerek **AÇIK** | Oyun burada oynanır; sistem burada tespit/aldatma yapar |
| **Kasa** (10 haneli parola, AES şifreli) | Tamamen **KAPALI** | Oyunun sonu: "mat" |

Açıklık bir zayıflık değil, ürünün kendisidir: sahte servisler kör edilirse
sistemin görecek bir şeyi kalmaz.

---

## 3. Savunma katmanları

| Katman | Ne yapar |
|---|---|
| **Honeypot** (SSH/FTP/MySQL/HTTP/Redis/ES...) | Sahte servisler; her etkileşimi kaydeder |
| **WAF** | Zararlı web isteklerini bloklar (ölçüm: ~%95 gerçek-saldırı önleme) |
| **Kural motoru** | Port tarama, brute-force, çoklu servis, tekrar — açıklanabilir alarm |
| **Tersine mühendislik** | Kodlanmış yükleri çözer, MITRE ATT&CK eşler |
| **SOAR** | Otonom müdahale; geri alınabilir eylemi otomatik, yıkıcı eylemi insan onayına yükseltir |
| **MTD (Hareketli Hedef)** | Banner ~90 sn, port ~45 sn döner — keşfi eskitir |
| **Yem / Honeytoken** | Cazip sahte hedefler; dokunulunca sessizce kritik alarm |
| **Son Hat (yer altı 50 katman)** | Çekirdek yemi tetiklenince devreye girer |
| **AES-256 kasa** | Flag'in son, kriptografik duvarı |

---

## 4. Görev tanımı (hocaya verilecek)

**Görev kartı:**

> **Sessiz Sızma — Arachne Sentinel**
> Şu IP'deki sistemde 10 haneli gizli bir parola korunuyor. Göreviniz: sistemi
> bu IP üzerinden yetkili olarak test edip o parolanın **düz metnini** ele
> geçirmek — ve bunu **mümkün olduğunca az alarm tetikleyerek** yapmak.
> Bu sistem bir tespit ızgarasıdır: her port taraması, her brute-force, her
> tuzağa dokunuş kaydedilir. **Başarı = en az alarmla flag'e en çok yaklaşmak.**
> Nerede olduğunu ve nasıl korunduğunu bulmak size kalmış. Her hamleniz izlenir.
> Yalnızca bu hedefe, izole lab ağında, yetkili test.

**Söylenmeyecekler:** flag'in yeri ("disk dosyası / proje dosyası" deme),
yöntem, uç nokta adları. Keşif görevin parçasıdır.

---

## 5. Kasa ulaşılamazlık garantisi

Şifreli metin iki yerde: diskte dosya (`~/.arachne_vault.enc`) ve `/api/vault`
(base64, auth arkasında). Ulaşmak için saldırgan **ikisinden birini** yapmalı:

### Yol A — Diskteki dosyayı okumak (host erişimi)
| Yöntem | Durum |
|---|---|
| SSH (22) | Kapalı |
| Açık servis sömürüsü (Ekran Paylaşımı/SMB/AFP/Uzaktan Yönetim) | Kapalı |
| Web uygulamasında RCE/LFI/SSTI | Kapalı (test edildi) |
| Fiziksel erişim | Mac kilitli tutulur |
| rapportd/OS zero-day | Teorik, çok düşük |

### Yol B — `/api/vault`'tan almak (geçerli oturum)
| Yöntem | Durum |
|---|---|
| Token tahmin/brute (256-bit) | İmkânsız |
| Auth bypass | Kapalı (test edildi) |
| HTTP oturum sniff | Kapalı — **panel yalnızca localhost'tan izlenirse** |
| XSS ile çerez çalma | Bulunamadı |
| Çerez sahteciliği | İmkânsız (secret_key tele düşmez) |

### Son kale
Her iki yol da (teorik olarak) aşılsa bile → **AES-256 + savunucunun kafasındaki
parola** → flag'in düz hali yine ulaşılamaz.

> **Özet:** Host'a girmeden ve oturum çalmadan kasaya giden hiçbir yol yoktur;
> ulaşılsa bile AES çözülemez.

---

## 6. Yem tuzakları (sessiz yakalama)

Cazip ama sahte uçlar — meşru kimse dokunmaz, yanlış pozitif ~sıfır:
`/flag.txt`, `/flag`, `/.env`, `/secrets.txt`, `/backup.sql`, `/.git/config`,
`/api/backup`, `/api/credentials`.

Saldırgan bunları fuzzing (ffuf/gobuster/nuclei) ile bulur, açar → **inandırıcı
sahte ganimet** (sahte `FLAG{...}`, sahte AWS/DB anahtarları) görüp "buldum"
sanır. Aynı anda:
- Panele **sessizce kritik alarm** düşer.
- Çekirdek yemi (`core_vault_breach_illusion`) kaydedilir → **Son Hat** devreye girer.

Sadece **istek atmak** tuzağı tetikler; "inanmak" gerekmez. İyi saldırgan bu
yemlere dokunmaz — ama dokunmazsa hedefe de ulaşamaz. "Alarmsız sızma" sınavı
tam burada.

---

## 7. Kurulum

### Savunmacı (gün başında)
```bash
cd "~/Desktop/security project/arachne-sentinel"
rm -f data/arachne.db                                  # taze veritabani

# Terminal 1 — honeypot + SOAR + MTD + honeytoken (agda erisilebilir):
python main.py full-demo --host 0.0.0.0

# Terminal 2 — komuta merkezi (auth ACIK; 0 KOYMA):
python main.py dashboard --host 0.0.0.0 --port 5001
```
LAN IP'ni öğren ve **yalnızca onu** hocaya ver:
```bash
ipconfig getifaddr en0     # or. 192.168.1.3
```
Komuta merkezini **kendi makinende** izle: `http://127.0.0.1:5001` + panel token.

### Saldırgan (hoca, kendi PC'sinden)
Sadece LAN IP'yi alır; honeypot portlarına ve web'e saldırır:
```bash
nmap -sV 192.168.1.3     # acik portlari gorur -> saldiriya baslar
```

### Akış
```
SAVUNMACI: servisleri baslat (portlar acilir) + LAN IP ver + localhost'tan izle
SALDIRGAN: nmap <LAN IP> -> acik portlar -> brute-force/web/fuzzing
SAVUNMACI: panelde her hamleyi canli gorur
```

---

## 8. Gün öncesi kontrol listesi (kritik)

- [ ] **Host servisleri kapalı:** SSH (Uzaktan Oturum Açma), Ekran Paylaşımı,
      SMB/AFP (Dosya Paylaşımı), Uzaktan Yönetim, AirPlay Alıcısı → **KAPALI**
      - Doğrula: `lsof -nP -iTCP -sTCP:LISTEN | grep -v 127.0.0.1`
- [ ] **Panel yalnızca localhost'tan izlenecek** — asla başka makineden ağ
      üzerinden giriş yapma (oturum sniff'ini engeller)
- [ ] **Dashboard auth AÇIK** (`ARACHNE_PANEL_AUTH=0` YOK)
- [ ] **Scrollback temiz** — flag ve panel token hiçbir terminal geçmişinde
      görünmesin (Cmd+K; gün başında tertemiz terminaller)
- [ ] **Mac kilitli tutulur** (fiziksel erişim yok)
- [ ] **Kasa mühürlü:** `~/.arachne_vault.enc` var, AES parolası sadece sende
- [ ] **Güvenlik duvarı açık**
- [ ] (Opsiyonel) Handoff'u kapat (rapportd yüzeyini azaltır)
- [ ] (Opsiyonel) Tüm sistemi Linux VM'de (bridged ağ) çalıştır → tam izolasyon

---

## 9. Skor tablosu

| Ölçüt | Nasıl okunur |
|---|---|
| **İlk alarma kadar süre** | Saldırgan ne kadar sessiz ilerledi |
| **Toplam alarm sayısı** | Kaç iz bıraktı |
| **Yeme dokundu mu** | Dokunduysa "sessizce yakalandı" |
| **En derin nokta** | Flag'e ne kadar yaklaştı (honeypot → web → vault 401) |
| **Flag düz metni** | Alındı mı (pratikte imkânsız = "mat") |

Mükemmel skor (sıfır alarm + flag) tasarım gereği imkânsızdır; "mat" budur.

---

## 10. Dürüst sınırlar

- Hiçbir sistem matematiksel olarak %100 güvenli değildir (OS/rapportd teorik
  yüzey). Pratik hedef: sömürülecek gerçek servis bırakmamak.
- Kaynak IP ≠ kesin saldırgan (proxy/VPN/spoofing).
- Honeypot kanıtı gözlemseldir; hash zinciri bütünlüğü yardımcı olur ama tek
  başına hukuki delil değildir.
- Kasayı asıl koruyan: **host güvenliği + AES.** Arachne bunların üzerine
  **tespit, aldatma, engelleme ve açıklanabilir alarm** katmanı koyar.

---

## 11. Sunum notu (hocaya çerçeve)

> "Arachne bir 'kırılamaz kasa' değil — öyle olduğunu iddia etmiyorum. O bir
> **tespit ve müdahale** sistemi. Sahte servislere istediğin kadar saldır;
> amaç oraya girmen değil. Her hamleni göreceğim, MITRE'ye eşleyeceğim,
> yavaşlatacağım. Asıl hedef kasadaysa, oraya giden yol savunmamın arkasında —
> ve ona uzandığın an seni yakalayacağım. Satranç oyna; ama şah matsın."
