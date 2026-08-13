"""Native (ARM64 assembly) imza tarama motoru icin durustce cerceveli bir
karsilastirma.

Bu script IKI ayri kiyaslama yapar, cunku ikisini karistirmak yanlis
(abartili) bir iddiaya yol acar:

  1. "El yazimi Python dongu" vs "el yazimi ARM64 assembly" - ikisi de ayni
     naif algoritmayi uygular (karakter karakter kaydirmali arama). Burada
     assembly'nin acik farkla one gectigini beklenir - cunku Python'un
     yorumlayici (interpreter) yuku devreye girer.
  2. "Python'un kendi bytes.find()" (zaten C ile yazilmis, cok optimize) vs
     "ARM64 assembly" - burada fark kucuk olabilir, hatta CPython'un
     algoritmasi (iyilestirilmis Boyer-Moore-Horspool benzeri) bazi
     girdilerde daha hizli bile olabilir. Bu beklenen ve dogaldir.

Amac "assembly her zaman kazanir" gibi sahte bir iddia degil; "yorumlanan
Python dongusu ile derlenmis native kod arasindaki fark nereden geliyor"
sorusunu somut sayilarla gostermek.

Kullanim (Apple Silicon Mac'te, once arachne/native/arm64'te `make` calistirin):
    python3 scripts/benchmark_native_scan.py
"""
import random
import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne.native import signature_engine  # noqa: E402


def naive_python_find(hay: str, needle: str) -> int:
    """az_find ile BIREBIR ayni naif algoritma, saf Python'da."""
    n, m = len(hay), len(needle)
    if m == 0:
        return 0
    if m > n:
        return -1
    for i in range(n - m + 1):
        if hay[i:i + m] == needle:
            return i
    return -1


def make_haystack(size: int, needle: str, seed: int) -> str:
    rng = random.Random(seed)
    text = "".join(rng.choice(string.ascii_lowercase) for _ in range(size))
    # ilginc olsun diye sona gercek bir imza ekleyelim (en kotu durum arama)
    return text + needle


def bench(fn, *args, repeat: int) -> float:
    start = time.perf_counter()
    for _ in range(repeat):
        fn(*args)
    return time.perf_counter() - start


def main():
    print(f"Native ARM64 cekirdek durumu: {signature_engine.engine_status()}\n")

    needle = "union select"
    for size in (1_000, 10_000, 100_000):
        haystack = make_haystack(size, needle, seed=size)
        repeat = max(5, 200_000 // size)

        t_naive_py = bench(naive_python_find, haystack, needle, repeat=repeat)
        t_native = bench(signature_engine.find, haystack, needle, repeat=repeat)
        t_builtin = bench(str.find, haystack, needle, repeat=repeat)

        print(f"haystack={size:>7} byte, {repeat} tekrar:")
        print(f"  el-yazimi Python dongusu : {t_naive_py*1000:8.2f} ms")
        print(f"  native ARM64 / yedek      : {t_native*1000:8.2f} ms"
              f"  ({'native' if signature_engine.NATIVE_ENGINE_ACTIVE else 'python yedek - fark gorulmeyecek'})")
        print(f"  Python bytes/str.find()   : {t_builtin*1000:8.2f} ms  (referans, C ile yazili)")
        if t_native > 0:
            print(f"  -> native, el-yazimi Python dongusune gore {t_naive_py / t_native:5.1f}x")
        print()

    if not signature_engine.NATIVE_ENGINE_ACTIVE:
        print("NOT: native cekirdek aktif degil, yukaridaki 'native' satiri aslinda\n"
              "Python yedegini olcuyor (ayni sayi). Gercek karsilastirma icin:\n"
              "  cd arachne/native/arm64 && make && cd ../../.. \n"
              "sonra bu scripti tekrar calistirin.")


if __name__ == "__main__":
    main()
