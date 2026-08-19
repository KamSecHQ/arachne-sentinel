"""
Native masaustu Komuta Merkezi penceresi (PyWebView).

`python main.py app` calistirildiginda:
  1. Flask panel sunucusu arka planda baslar
  2. Terminalde sinematik acilis dizisi oynar (tarayici ACILMAZ)
  3. Sekmesiz/adres-cubuksuz NATIVE bir pencere acilir ve panelin
     sinematik (yogun) surumunu icinde gosterir (?mode=native)

Tarayicidan ve terminalden bagimsizdir - gercek bir masaustu uygulamasi
gibi davranir. PyWebView kurulu degilse kullaniciyi bilgilendirip
tarayiciya duser (best-effort).
"""
import socket
import threading
import time
import webbrowser


def _wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Sunucu ayaga kalkana kadar bekle."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def run_app(host: str = "127.0.0.1", port: int = 5001, cinematic_terminal: bool = True):
    import os
    from .dashboard import app as flask_app

    # 1) Flask'i arka plan thread'inde baslat
    def _serve():
        flask_app.run(host=host, port=port, debug=False, use_reloader=False)
    threading.Thread(target=_serve, daemon=True).start()

    # 2) Terminal acilis dizisi (tarayici ACMADAN)
    if cinematic_terminal:
        try:
            from . import boot_sequence
            boot_sequence.play(host, port, open_browser=False, voice=True,
                               fast=bool(os.environ.get("ARACHNE_FAST_BOOT")))
        except Exception:
            pass

    _wait_port(host, port)
    url = f"http://{host}:{port}/?mode=native"

    # 3) Native pencere (PyWebView)
    try:
        import webview
    except ImportError:
        import os as _os
        print("\n" + "=" * 64)
        print("  [!] AYRI KOMUTA MERKEZI PENCERESI ACILAMADI")
        print("      Native pencere icin PyWebView gerekli ama kurulu degil.")
        print("      (Bu yuzden onceden tarayiciya dusuyordu.)")
        print("")
        print("      Tek seferlik kurulum (macOS):")
        print("        pip install pywebview pyobjc-core \\")
        print("            pyobjc-framework-Cocoa pyobjc-framework-WebKit")
        print("      Sonra tekrar:  python main.py app")
        print("")
        # Kullanici acikca 'webten bagimsiz' istedi -> KENDILIGINDEN tarayici ACMA.
        # Isteyen ARACHNE_ALLOW_BROWSER=1 ile tarayici yedegini acabilir.
        if _os.environ.get("ARACHNE_ALLOW_BROWSER"):
            print(f"      ARACHNE_ALLOW_BROWSER=1 -> tarayicida aciliyor: {url}")
            try:
                webbrowser.open(url)
            except Exception:
                pass
        else:
            print(f"      Sunucu calisiyor. Istersen elle ac: {url}")
        print("=" * 64 + "\n")
        # Sunucu calismaya devam etsin (Ctrl+C ile cik)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return
        return

    # JS köprüsü: native pencere de terminalin AYNI `say` motorunu kullansın
    # (böylece iki yerde de ses birebir aynı olur).
    class _Api:
        def speak(self, text):
            try:
                from . import boot_sequence
                boot_sequence.say_line(str(text), blocking=False)
            except Exception:
                pass
            return True

    win = webview.create_window(
        "ARACHNE SENTINEL — KOMUTA MERKEZI",
        url,
        width=1680, height=1020,
        min_size=(1120, 720),
        background_color="#03060a",
        js_api=_Api(),
    )
    # webview.start() ANA thread'de calismali (bu fonksiyon ana thread'den cagrilir)
    try:
        webview.start()
    except Exception as exc:  # pragma: no cover
        print(f"  [!] Native pencere baslatilamadi: {exc}")
        webbrowser.open(url)
