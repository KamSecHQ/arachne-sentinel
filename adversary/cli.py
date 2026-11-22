#!/usr/bin/env python3
"""
Arachne Adversary — komut satiri.

  python -m adversary.cli campaign        # tek saldiri kampanyasi (yerel lab)
  python -m adversary.cli coevolve        # kirmizi-mavi ko-evrim döngusu
  python -m adversary.cli report          # ko-evrim + HTML rapor uretir

TAMAMEN YEREL. Motor yalnizca localhost/kendi lab hedefimize saldirir; loopback
disi hedef kod seviyesinde reddedilir. Amac savunma testidir.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    ap = argparse.ArgumentParser(description="Arachne Adversary — yerel red-team test motoru")
    ap.add_argument("command", choices=["campaign", "coevolve", "report", "panel"])
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=50)
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()

    if args.command == "panel":
        from adversary import dashboard
        dashboard.run(port=args.port)
        return

    if args.command == "campaign":
        from adversary import engine
        res = engine.run_campaign(block_threshold=args.threshold, use_mutations=True)
        print("=== ARACHNE ADVERSARY — YEREL KAMPANYA ===")
        for l in engine.summary_lines(res):
            print("  " + l)
        if res["bypassed"]:
            print("  Atlatan yükler (savunmaya sinyal):")
            for b in res["bypassed"][:10]:
                print(f"    - {b['category']} / {b['mutation']}: {b['payload'][:56]}")

    elif args.command == "coevolve":
        from adversary import coevolution as co
        res = co.run(rounds=args.rounds, block_threshold=args.threshold)
        print("=== ARACHNE ADVERSARY — KIRMIZI vs MAVI KO-EVRIM ===")
        for l in co.summary_lines(res):
            print("  " + l)

    elif args.command == "report":
        from datetime import datetime
        from adversary import report
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        path, res = report.generate("adversary_report.html", rounds=args.rounds,
                                    generated_at=ts + " (yerel lab)")
        s = res["summary"]
        print(f"Ko-evrim raporu olusturuldu: {path}")
        print(f"  atlatma: %{s['start_bypass_rate']*100:.1f} -> %{s['end_bypass_rate']*100:.1f}"
              f" | yanlis pozitif %{s['final_false_positive_rate']*100:.1f}")


if __name__ == "__main__":
    main()
