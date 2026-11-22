"""
Ko-evrim raporu — kirmizi-mavi yarisini tek-dosya HTML olarak gorsellestirir.
Tur tur atlatma orani, savunmanin ogrendikleri ve kalan boslular açikça yazilir.
"""
from __future__ import annotations

import html
from . import coevolution


def _bar(pct, color):
    return (f"<div class='bar'><div class='fill' style='width:{max(pct,1.5):.1f}%;background:{color}'></div>"
            f"<span>{pct:.1f}%</span></div>")


def build_html(res: dict, generated_at: str = "") -> str:
    s = res["summary"]
    rounds = res["rounds"]
    round_rows = ""
    for h in rounds:
        learned = ", ".join(h["defense_learned"]) or "—"
        round_rows += (
            f"<tr><td><b>{h['round']}</b></td>"
            f"<td>{_bar(h['attacker_bypass_rate']*100, '#ff5a4d')}</td>"
            f"<td>{h['bypassed']} / {h['exploited']}</td>"
            f"<td>{html.escape(learned)}</td>"
            f"<td class='mono'>{html.escape(', '.join(h['defense_after']) or '—')}</td></tr>")
    residual = rounds[-1]["bypass_examples"]
    has_residual = bool(residual)
    residual_html = "".join(f"<li><code>{html.escape(x)}</code></li>" for x in residual) or "<li>Kalan atlatma yok — savunma bu korpusta yakınsadı.</li>"
    residual_note = ("Bu atlatmalara karşı basit normalleştirme yetmiyor; bir sonraki adım davranışsal/ayrıştırma-tabanlı tespittir. Dürüstlük gereği raporlanır."
                     if has_residual else
                     "Savunma bu saldırı korpusundaki tüm çalışan atlatmaları yakaladı — yanlış pozitif üretmeden. Daha zengin/yeni bir saldırı korpusu yarışı yeniden açar; sistemin amacı tam da budur.")
    gen = f"<div class='gen'>Üretim: {html.escape(generated_at)}</div>" if generated_at else ""
    conv = "Savunma yakaladı (yakınsadı)" if s["converged"] else "Yarış sürüyor — kalan boşluk davranışsal tespit gerektiriyor"

    return f"""<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arachne Adversary — Kırmızı vs Mavi Ko-Evrim Raporu</title>
<style>
 :root{{--bg:#07060f;--card:#12101f;--line:#2a2740;--red:#ff5a4d;--teal:#35e0d0;--violet:#9b6bff;--gold:#ffcf6a;--muted:#8b95a8;--txt:#e8ecf5}}
 *{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#1a1530,var(--bg) 60%);color:var(--txt);font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:2.2rem;line-height:1.5}}
 h1{{font-size:1.5rem;margin:0 0 .2rem}} h1 span{{color:var(--red)}} .sub{{color:var(--muted);margin:.1rem 0 1rem;font-size:.9rem}}
 .warn{{background:rgba(53,224,208,.08);border:1px solid rgba(53,224,208,.3);border-radius:10px;padding:.6rem .9rem;font-size:.82rem;color:#bdeee8;margin-bottom:1.4rem}}
 .gen{{color:var(--muted);font-size:.72rem;margin-bottom:1rem}}
 .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.4rem}}
 .kpi{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1rem 1.15rem}}
 .kpi .l{{font-size:.66rem;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}}
 .kpi .v{{font-size:1.9rem;font-weight:800;margin-top:.15rem}}
 .red{{color:var(--red)}} .teal{{color:var(--teal)}} .violet{{color:var(--violet)}} .gold{{color:var(--gold)}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.1rem 1.25rem;margin-bottom:1.3rem}}
 .card h2{{font-size:1rem;margin:0 0 .8rem}}
 table{{width:100%;border-collapse:collapse;font-size:.85rem}} th,td{{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:middle}}
 th{{color:var(--muted);font-size:.68rem;letter-spacing:.05em;text-transform:uppercase}}
 .bar{{position:relative;background:#0c0a17;border:1px solid var(--line);border-radius:7px;height:20px;min-width:120px;overflow:hidden}}
 .bar .fill{{height:100%;border-radius:6px 0 0 6px}} .bar span{{position:absolute;right:7px;top:1px;font-size:.72rem;font-weight:700}}
 .mono,code{{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;color:var(--gold)}}
 code{{background:#0c0a17;border:1px solid var(--line);border-radius:5px;padding:.05rem .3rem;word-break:break-all}}
 ul{{margin:.3rem 0}} li{{margin:.25rem 0}}
 .note{{color:var(--muted);font-size:.8rem;border-left:2px solid var(--violet);padding-left:.8rem}}
</style></head><body>
<h1>🕷 Arachne Adversary — <span>Kırmızı vs Mavi Ko-Evrim</span></h1>
<p class="sub">Saldırı geliştikçe savunma yukarı çekilir — tur tur ölçülmüş yarış.</p>
<div class="warn">🔒 <b>Yalnızca yerel test.</b> Tüm saldırılar kendi izole lab hedefimize (localhost) yöneliktir; motor loopback dışına çıkamaz. Amaç dışarı saldırmak değil, kendi savunmamızı ölçüp güçlendirmektir.</div>
{gen}
<div class="kpis">
 <div class="kpi"><div class="l">Başlangıç atlatma</div><div class="v red">{s['start_bypass_rate']*100:.1f}%</div></div>
 <div class="kpi"><div class="l">Son atlatma</div><div class="v teal">{s['end_bypass_rate']*100:.1f}%</div></div>
 <div class="kpi"><div class="l">Savunmanın öğrendiği</div><div class="v violet">{len(s['final_defense'])}</div><div class="l" style="text-transform:none">normalleştirici</div></div>
 <div class="kpi"><div class="l">Yanlış pozitif</div><div class="v gold">{s['final_false_positive_rate']*100:.1f}%</div></div>
</div>

<div class="card">
 <h2>Tur Tur Yarış</h2>
 <table><thead><tr><th>Tur</th><th>Saldırgan atlatma oranı</th><th>Geçen / çalışan</th><th>Savunma bu turda öğrendi</th><th>Aktif savunma</th></tr></thead>
 <tbody>{round_rows}</tbody></table>
 <p class="note" style="margin-top:.7rem">{html.escape(conv)}.</p>
</div>

<div class="card">
 <h2>Kalan Boşluklar (son turda hâlâ geçen)</h2>
 <ul>{residual_html}</ul>
 <p class="note">{html.escape(residual_note)}</p>
</div>

<div class="card">
 <h2>Nasıl Çalışır</h2>
 <p class="note">Kırmızı takım (saldırgan) temel yükleri mutasyona uğratarak (büyük/küçük harf, yorum ekleme, kodlama, boşluk hilesi) WAF'ı atlatmayı dener. Mavi takım (savunma), atlatan her varyanta karşı uygun normalleştiriciyi (yorum sil, boşluk daralt, URL çöz…) devreye alır ve bir sonraki turda daha güçlü olur. Kırmızı ilerledikçe mavi öğrenir — savunma yukarı çekilir.</p>
</div>
</body></html>"""


def generate(path: str = "adversary_report.html", rounds: int = 5, generated_at: str = ""):
    res = coevolution.run(rounds=rounds)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(res, generated_at=generated_at))
    return path, res
