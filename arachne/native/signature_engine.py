"""Native (ARM64 assembly) imza tarama motoruna kopru + guvenli Python yedegi.

Faz 3'un merkezi fikri: honeypot ve WAF kural motorlarinin zaten kullandigi
"bu metin icinde bilinen bir saldiri imzasi var mi?" sorusunu, elle yazilmis
ARM64 assembly (bkz. arachne/native/arm64/fast_scan.s) cevaplayabilsin -
ama bu opsiyonel bir hizlandirma katmani olsun, projenin dogrulugu asla
derlenmis bir .dylib'in varligina bagimli olmasin.

Bu modul su sekilde davranir:
  - Eger mevcut platform Apple Silicon (arm64) Mac ise VE
    arachne/native/arm64/build/libaz_fast_scan.dylib derlenmis ve mevcutsa,
    aramalar gercekten native kod uzerinden yapilir.
  - Aksi durumda (Linux, Intel Mac, Windows, .dylib henuz derlenmemis...)
    ayni sonucu ureten saf Python fallback'e otomatik olarak duser. Cagiran
    kod acisindan davranis (girdi/cikti) HER IKI durumda da birebir aynidir -
    bu yuzden mevcut 29 testin hicbiri bu degisiklikten etkilenmez.

NATIVE_ENGINE_ACTIVE bayragi, hangi yolun kullanildigini rapor/CLI/dashboard
katmanlarinin gosterebilmesi icin disari acilir.
"""
from __future__ import annotations

import ctypes
import platform
from pathlib import Path

_MAX_NEEDLES = 32

_DYLIB_PATH = Path(__file__).parent / "arm64" / "build" / "libaz_fast_scan.dylib"

_lib = None
NATIVE_ENGINE_ACTIVE = False
_LOAD_ERROR: str | None = None


def _try_load_native():
    """Native kutuphaneyi bir kere yuklemeyi dener; basarisiz olursa sessizce
    Python fallback'e devam edilir (bu beklenen/normal bir durumdur - orn.
    Intel Mac, Linux, ya da henuz `make` calistirilmamis bir kurulum icin)."""
    global _lib, NATIVE_ENGINE_ACTIVE, _LOAD_ERROR

    if platform.system() != "Darwin" or platform.machine() not in ("arm64", "aarch64"):
        _LOAD_ERROR = (
            f"Native cekirdek sadece Apple Silicon Mac'te calisir "
            f"(tespit edilen: {platform.system()}/{platform.machine()}); Python yedegi kullaniliyor."
        )
        return

    if not _DYLIB_PATH.exists():
        _LOAD_ERROR = (
            f"{_DYLIB_PATH} bulunamadi - once 'cd arachne/native/arm64 && make' calistirin; "
            f"su an icin Python yedegi kullaniliyor."
        )
        return

    try:
        lib = ctypes.CDLL(str(_DYLIB_PATH))
        lib.az_find.restype = ctypes.c_int64
        lib.az_find.argtypes = [ctypes.c_char_p, ctypes.c_int64, ctypes.c_char_p, ctypes.c_int64]
        lib.az_scan_multi.restype = ctypes.c_int32
        lib.az_scan_multi.argtypes = [
            ctypes.c_char_p, ctypes.c_int64,
            ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int32,
        ]
        _lib = lib
        NATIVE_ENGINE_ACTIVE = True
    except OSError as exc:  # dylib bozuk / uyumsuz mimaride derlenmis vb.
        _LOAD_ERROR = f"Native kutuphane yuklenemedi ({exc}); Python yedegi kullaniliyor."


_try_load_native()


def _encode(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        return text
    return text.encode("utf-8", errors="replace")


def find(haystack: str | bytes, needle: str | bytes) -> int:
    """haystack icinde needle'in ilk gectigi index'i dondurur, yoksa -1.

    Native cekirdek aktifse ARM64 assembly (`az_find`) uzerinden, degilse
    Python'un kendi `bytes.find` fonksiyonu uzerinden calisir - iki yolun da
    davranisi (bos needle, needle > haystack, vb. kenar durumlar dahil)
    fuzz-test edilerek birebir ayni oldugu dogrulanmistir.
    """
    hay_b = _encode(haystack)
    needle_b = _encode(needle)

    if _lib is not None:
        return int(_lib.az_find(hay_b, len(hay_b), needle_b, len(needle_b)))
    return hay_b.find(needle_b)


def contains(haystack: str | bytes, needle: str | bytes) -> bool:
    """`needle in haystack` ile ayni anlama gelir; native/yedek arasinda
    seffaf gecis yapan tek-imza kisayolu."""
    return find(haystack, needle) >= 0


def contains_any(text: str | bytes, signatures: list[str]) -> list[str]:
    """signatures listesindeki hangi imzalarin text icinde gectigini
    dondurur (bulunma sirasina degil, signatures sirasina gore).

    En fazla 32 imza tek cagrida taranabilir (native bitmask genisligi);
    daha fazlasi icin fonksiyon otomatik olarak parcalara boler.
    """
    if not signatures:
        return []

    matched: list[str] = []
    for start in range(0, len(signatures), _MAX_NEEDLES):
        chunk = signatures[start:start + _MAX_NEEDLES]
        matched.extend(_scan_chunk(text, chunk))
    return matched


def _scan_chunk(text: str | bytes, signatures: list[str]) -> list[str]:
    text_b = _encode(text)

    if _lib is None:
        return [s for s in signatures if find(text_b, s) >= 0]

    encoded = [_encode(s) for s in signatures]
    needle_arr = (ctypes.c_char_p * len(encoded))(*encoded)
    len_arr = (ctypes.c_int64 * len(encoded))(*[len(e) for e in encoded])
    mask = _lib.az_scan_multi(text_b, len(text_b), needle_arr, len_arr, len(encoded))
    return [sig for i, sig in enumerate(signatures) if mask & (1 << i)]


def engine_status() -> str:
    """Insan-okunur bir durum satiri (CLI/dashboard/rapor icin)."""
    if NATIVE_ENGINE_ACTIVE:
        return f"AKTIF (ARM64 native, {_DYLIB_PATH.name})"
    return f"pasif - Python yedegi kullaniliyor ({_LOAD_ERROR})"
