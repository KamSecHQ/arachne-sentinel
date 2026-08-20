"""
Sinematik terminal acilis dizisi (JARVIS-vari).

`python main.py dashboard` calistirildiginda, panel sunucusu baslamadan once
terminalde ANSI renkli, akan bir acilis gosterir; Turkce sesli anons yapar
(macOS `say`, en iyi caba) ve ardindan tarayiciyi otomatik acar.

Tamamen kozmetiktir - sistemin islevine dokunmaz. Ses ve tarayici acma
best-effort'tur; olmazsa sessizce atlanir (Linux/CI'da da guvenle calisir).
"""
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser

# --- ANSI renkler ---
_C = {
    "cyan": "\033[38;5;51m", "blue": "\033[38;5;39m", "dim": "\033[38;5;245m",
    "green": "\033[38;5;46m", "red": "\033[38;5;196m", "white": "\033[97m",
    "amber": "\033[38;5;214m", "purple": "\033[38;5;141m",
    "b": "\033[1m", "r": "\033[0m",
}

_LOGO = r"""
       /\                       _             _
      /  \    _ __ __ _  ___| |__  _ __   ___
     / /\ \  | '__/ _` |/ __| '_ \| '_ \ / _ \
    / ____ \ | | | (_| | (__| | | | | | |  __/
   /_/    \_\|_|  \__,_|\___|_| |_|_| |_|\___|
        S E N T I N E L   ·   80   F A Z
"""

_STEPS = [
    ("CORE", "Cekirdek baslatiliyor", "green"),
    ("MEMORY", "Yerel vektor bellek veritabani senkronize ediliyor", "green"),
    ("SENSORS", "Sensor agi + saglik telemetrisi baglaniyor", "green"),
    ("SIEM", "SIEM normalizasyon hatti aciliyor", "green"),
    ("DEFENSE", "18 savunma halkasi / 80 faz yukleniyor", "green"),
    ("ADAPTIVE", "Adaptif ko-evrim motorlari kalibre ediliyor", "green"),
    ("SOAR", "SOAR playbook orkestrasyonu hazir", "green"),
    ("INTEGRITY", "Kurcalama-kaniti denetim zinciri dogrulandi", "green"),
    ("METRICS", "Benchmark metrik motoru cevrimici", "green"),
    ("SHIELD", "Celik Kubbe 18 halka aktif", "green"),
]

# Hem terminal hem native pencere hem asistan AYNI Turkce sesi kullanir (uyumlu).
_VOICE_LINE = ("Komuta merkezi devrede. Seksen faz aktif. "
               "Tüm savunma katmanları çevrimiçi. Sistem hazır.")

# Sentetik/otoriter ton icin inline say komutlari (pbas dusuk = derin).
_VOICE_PITCH = 46
_VOICE_RATE = 178
_VOICE_LANG = "tr_TR"

# Tercih: erkek Turkce ses (kuruluysa) > Yelda > ilk Turkce.
_VOICE_CANDIDATES = ("yelda", "ahmet", "cem", "mehmet", "burak")


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")


def pick_voice():
    """En uygun ELIT INGILIZCE erkek sesi sec (terminal + native pencere AYNISINI
    kullansin diye ortak).

    Oncelik: ARACHNE_VOICE env > elit Ingilizce erkek (Daniel, Alex...) > ilk
    Ingilizce ses > yok.
    """
    override = os.environ.get("ARACHNE_VOICE")
    if override:
        return override
    say = shutil.which("say")
    if not say:
        return None
    try:
        out = subprocess.run([say, "-v", "?"], capture_output=True,
                             text=True, timeout=3).stdout
    except Exception:
        return None
    turkish = []
    for line in out.splitlines():
        if _VOICE_LANG in line:
            name = line[:line.find(_VOICE_LANG)].strip()
            if name:
                turkish.append(name)
    # Aday sesleri oncelik sirasiyla ara (erkek Turkce > Yelda)
    for cand in _VOICE_CANDIDATES:
        for name in turkish:
            if cand in name.lower():
                return name
    return turkish[0] if turkish else None


# TEK KONUSMACI garantisi: ayni anda yalnizca bir `say` calisir. Yeni bir anons
# gelince oncekini keser (en guncel rapor konusur), boylece ust uste binme /
# yankilanma olmaz. Kilit + izlenen surec ile saglanir.
_say_lock = threading.Lock()
_say_proc = None


def _stop_current_say():
    """Halihazirda konusan `say` surecini (varsa) durdur - ust uste binmeyi onler."""
    global _say_proc
    p = _say_proc
    if p is not None and p.poll() is None:
        try:
            p.terminate()
        except Exception:
            pass


def say_line(text: str, blocking: bool = False):
    """macOS `say` ile TEK KONUSMACI anons. Terminal, native pencere ve asistan
    hepsi bunu kullanir; yeni anons oncekini keser (yankilanma/ust uste binme yok)."""
    say = shutil.which("say")
    if not say:
        return
    voice = pick_voice()
    spoken = f"[[pbas {_VOICE_PITCH}]][[rate {_VOICE_RATE}]] {text}"
    args = [say]
    if voice:
        args += ["-v", voice]
    args.append(spoken)

    def _run():
        global _say_proc
        # kilit sadece "oncekini kes + yenisini baslat" boyunca tutulur; bekleme
        # kilit disindadir ki yeni bir anons araya girip bunu kesebilsin.
        with _say_lock:
            _stop_current_say()
            try:
                _say_proc = subprocess.Popen(args)
            except Exception:
                _say_proc = None
                return
            proc = _say_proc
        try:
            proc.wait(timeout=30)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    if blocking:
        _run()
    else:
        threading.Thread(target=_run, daemon=True).start()


def _say_async(text: str):
    say_line(text, blocking=False)


def _type(text: str, delay: float = 0.006):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)


def _progress(width: int = 34, dur: float = 0.9, color: str = "cyan"):
    c = _C[color] if _supports_color() else ""
    r = _C["r"] if _supports_color() else ""
    steps = width
    for i in range(steps + 1):
        filled = "█" * i
        empty = "░" * (steps - i)
        pct = int(i / steps * 100)
        sys.stdout.write(f"\r   {c}[{filled}{empty}] {pct:3d}%{r}")
        sys.stdout.flush()
        time.sleep(dur / steps)
    sys.stdout.write("\n")


def play(host: str, port: int, open_browser: bool = True, voice: bool = True,
         fast: bool = False):
    """Acilis dizisini oynatir, sonra tarayiciyi acar (best-effort)."""
    color = _supports_color()
    def c(name):
        return _C[name] if color else ""
    R = _C["r"] if color else ""

    url = f"http://{host}:{port}"
    d = 0.0 if fast else 1.0  # hiz carpani

    # Ekrani temizle
    if color:
        sys.stdout.write("\033[2J\033[H")

    # Logo
    sys.stdout.write(c("cyan") + c("b") + _LOGO + R + "\n")
    sys.stdout.flush()
    time.sleep(0.2 * d)

    # Sesli anons (gorsel akisla es zamanli)
    if voice:
        _say_async(_VOICE_LINE)

    _type(f"{c('dim')}   UNIVERSAL COGNITIVE OS  ·  CORE ACCELERATOR{R}\n\n", 0.004 if not fast else 0)
    time.sleep(0.15 * d)

    # Adimlar
    for tag, desc, col in _STEPS:
        dots = "." * max(2, 40 - len(desc))
        sys.stdout.write(f"   {c('blue')}[{tag:<9}]{R} {desc}{c('dim')}{dots}{R} ")
        sys.stdout.flush()
        time.sleep((0.10 if not fast else 0.005) * (d if not fast else 1))
        sys.stdout.write(f"{c('green')}{c('b')}[OK]{R}\n")
        sys.stdout.flush()

    sys.stdout.write("\n")
    _progress(dur=(0.9 if not fast else 0.05))
    time.sleep(0.1 * d)

    # Cevrimici bildirimi
    sys.stdout.write("\n")
    _type(f"{c('green')}{c('b')}   ● SISTEM CEVRIMICI{R}{c('dim')}  —  tum katmanlar nominal{R}\n",
          0.004 if not fast else 0)
    sys.stdout.write(f"{c('cyan')}   ▸ KOMUTA MERKEZI: {c('b')}{url}{R}\n")
    sys.stdout.write(f"{c('dim')}   ▸ Tarayici otomatik aciliyor... (durdurmak icin Ctrl+C){R}\n\n")
    sys.stdout.flush()

    # Tarayiciyi kisa bir gecikmeyle ac (sunucu ayaga kalksin)
    if open_browser:
        def _open():
            time.sleep(1.6)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()
