# Native ARM64 imza tarama çekirdeği (Faz 3)

Bu klasör, Arachne Sentinel'in honeypot kural motorunun kullandığı imza
taramasını hızlandıran, elle yazılmış **ARM64 assembly** kodunu içerir.
Sadece **Apple Silicon Mac'lerde** (M1/M2/M3...) derlenip çalışır. Diğer her
platformda (Intel Mac, Linux, Windows, CI) proje otomatik olarak bir Python
yedeğine düşer — hiçbir şey bozulmaz, sadece hızlandırma devre dışı kalır.

## Derleme (Mac, Apple Silicon)

```bash
# 1) Ana motor (ctypes ile Python'dan çağrılan .dylib)
cd arachne/native/arm64
make
make test        # hızlı bir dogrulama calistirir
cd ../../..

# 2) Bağımsız CLI aracı (opsiyonel, projeden ayrı çalışır)
cd arachne/native/tools
make
./build/byte_inspector /etc/hosts
cd ../../..
```

Derleme sonrası honeypotu her zamanki gibi çalıştırın — `rule_known_signature`
artık native motoru otomatik kullanacaktır, hiçbir ek adım gerekmez:

```bash
python3 -c "from arachne.native import signature_engine as s; print(s.engine_status())"
# -> AKTIF (ARM64 native, libaz_fast_scan.dylib)
```

## Neden opsiyonel?

Projenin doğruluğu (testler, honeypot, WAF) tek bir donanıma bağımlı
olmamalı. `signature_engine.py`, native kütüphane bulunamazsa ya da farklı
bir platformdaysanız sessizce aynı sonucu üreten bir Python fonksiyonuna
döner — bu yüzden `pytest tests/` her zaman, her platformda geçer.

## Kıyaslama

```bash
python3 scripts/benchmark_native_scan.py
```

Bu script, "el yazımı Python döngüsü vs el yazımı assembly" ve "Python'un
kendi `str.find()`'ı vs assembly" karşılaştırmalarını ayrı ayrı gösterir —
detaylar için `docs/ARCHITECTURE.md`'deki "Faz 3" bölümüne bakın.
