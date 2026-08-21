#!/usr/bin/env python3
"""
CANLI KORUYAN PROXY — Arachne WAF'in arkasindaki bilincli-zafiyetli lab hedefini
calistirir. Tarayici/curl ile saldirip WAF'in engelleyisini CANLI gorursun.
WAF olaylari storage'a yazilir; komuta merkezi canli akisi da bunlari isler.

Kullanim:
  python scripts/waf_live.py                 # KORUMALI (WAF aktif), port 8090
  python scripts/waf_live.py --unprotected   # WAF'siz — farki gormek icin
  python scripts/waf_live.py --port 9000

Ornek saldirilar (baska bir terminalde):
  curl "http://127.0.0.1:8090/search?name=' OR '1'='1"
  curl "http://127.0.0.1:8090/comment?text=<script>alert(1)</script>"
  curl "http://127.0.0.1:8090/file?path=../../../../etc/passwd"
  curl "http://127.0.0.1:8090/ping?host=127.0.0.1;whoami"
  curl "http://127.0.0.1:8090/render?name={{7*7}}"
KORUMALI modda bunlar 403 (WAF bloklad); KORUMASIZ modda saldiri "calisir".

SADECE kendi izole lab ortaminizda calistirin. Dis sisteme dokunmaz.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arachne.waf import labtarget


def main():
    ap = argparse.ArgumentParser(description="Arachne WAF canli koruyan proxy (lab)")
    ap.add_argument("--unprotected", action="store_true", help="WAF'siz calistir")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--threshold", type=int, default=50, help="WAF blok esigi (varsayilan 50)")
    args = ap.parse_args()

    protected = not args.unprotected
    app = labtarget.build(protected=protected, block_threshold=args.threshold)
    mode = "KORUMALI (WAF aktif)" if protected else "KORUMASIZ (WAF KAPALI!)"
    base = f"http://{args.host}:{args.port}"
    print("=" * 64)
    print(f"  Arachne LAB Hedefi — {mode}")
    print(f"  {base}")
    print("=" * 64)
    print("  Ornek saldirilar (baska terminalde):")
    print(f"    curl \"{base}/search?name=' OR '1'='1\"")
    print(f"    curl \"{base}/comment?text=<script>alert(1)</script>\"")
    print(f"    curl \"{base}/file?path=../../../../etc/passwd\"")
    print(f"    curl \"{base}/ping?host=127.0.0.1;whoami\"")
    print(f"    curl \"{base}/render?name={{{{7*7}}}}\"")
    print("=" * 64)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
