"""
Faz 27 - Oyun-Teorik Savunma / Ko-Evrim (Stackelberg guvenlik oyunu).

--- Ko-evrim fikri ---
Savunmayi statik bir duvar gibi kurarsan, ADAPTE OLAN bir saldirgan onu
gozler, zayif noktayi ogrenir ve oraya yuklenir. Bu modul savunucu ile
adaptif saldirgan arasindaki iliskiyi bir STACKELBERG (lider-takipci)
oyunu olarak formel modeller:

  1. Savunucu ONCE baglanir (commit): savunma yapilandirmalari (ornek:
     honeypot yerlesimleri / MTD konfigurasyonlari) uzerinde bir KARMA
     (rastgele) strateji ilan eder - "her config'i su olasilikla kullanacagim".
  2. Saldirgan bu DAGILIMI gozler ve EN IYI YANITI (best response) verir:
     kendi beklenen faydasini maksimize eden saldiriyi secer.
  3. Savunucu, saldirganin bu en iyi yanit verecegini BILEREK, kendi beklenen
     faydasini maksimize eden dagilimi secer.

Temel sonuc (ve bu modulun tezi): saldirgan adapte oldugunda, herhangi bir
SAF (tek, sabit) strateji sömürülebilir; buna karsin KARMA (randomize)
strateji savunucunun garanti edebilecegi en kotu-durum faydasini yukseltir.
Iste bu, Hareketli Hedef Savunmasinin (Moving Target Defense) formel
gerekcesidir: surekli yeniden-randomize et ki saldirganin ogrendigi model
BAYATLASIN.

--- Model ---
  * payoff[(config, attack)] = (defender_util, attacker_util)  -> her hucre iki
    tarafin faydasini verir (varsayilan oyun sabit-toplamlidir ama kod genel
    toplamlari da kabul eder).
  * attacker_best_response: dagilima karsi saldirganin beklenen faydasini
    maksimize eden saldiri (beraberlik savunucu ALEYHINE bozulur - zayif/
    guvenli Stackelberg okumasi).
  * stackelberg_defense: savunucunun karma stratejisini bir simpleks IZGARASI
    uzerinde KABA KUVVETLE (brute-force) tarar; ML/harici cozucu yok.
  * coevolve: turlar boyunca saldirgan-adapte / savunucu-yeniden-optimize
    dongusunu isletir ve yakinsamayi (MTD dersini) gosterir.

--- DURUSTLUK NOTU ---
Bu, Stackelberg guvenlik oyunlarinin CEKIRDEK mantigini kucuk, deterministik
ve aciklanabilir sekilde gosterir; tam olcekli bir SSG cozucusu (kolonu-
uretme, MILP, ORIGAMI/ERASER) DEGILDIR. Getiri matrisleri minik ve elle
tasarlanmistir; cozum simpleks izgarasinda kaba kuvvet aramadir (kesin LP
optimumu degil, izgara cozunurlugune bagli yaklasik optimum). Amac oyunun
mantigini gostermek, gercek bir savunma butcesi dagitimi yapmak degildir.

--- Gercek cerceve eslemesi ---
Stackelberg guvenlik oyunlari (Tambe/USC soyu: ARMOR-LAX, PROTECT-USCG,
IRIS), siber aldatma oyun teorisi, ko-evrimsel saldiri/savunma dinamikleri,
Hareketli Hedef Savunmasi (Moving Target Defense).

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Oyun yalnizca KENDI izleme yuzeyimizdeki savunma
yapilandirmalarimizin dagitimini optimize eder; hicbir baska sisteme saldirmaz,
hack-back yoktur. "Saldirgan" burada modellenen bir soyutlamadir, gercek bir
hedefe donuk bir eylem degildir. "Adaptif" olmak, kendi konfigurasyonumuzu
yeniden-randomize etmek demektir - karsi saldiri degil.

Harici bagimlilik yok - sadece stdlib (random, math).
"""
import math
import random


# --- VARSAYILAN KUCUK OYUN: 3 honeypot-yerlesimi vs 3 saldiri stratejisi ---
# Her savunma config'i bir saldiriyi "yakalar" (kosegen): yakalarsa savunucu
# faydasi yuksek (3), saldirgan faydasi dusuk (0); kacarsa tersi (0 / 3).
# Sabit-toplamli (defender_util + attacker_util = 3). Tek bir config'e
# baglanmak (saf strateji) saldirgan tarafindan tam somurulur; karma strateji
# tabani yukseltir -> MTD dersi.
DEFAULT_CONFIGS = ["edge_decoys", "core_decoys", "spread_decoys"]
DEFAULT_ATTACKS = ["recon_edge", "pivot_core", "low_slow"]

_CATCH = {
    "edge_decoys": "recon_edge",
    "core_decoys": "pivot_core",
    "spread_decoys": "low_slow",
}
_DEFAULT_PAYOFF = {}
for _c in DEFAULT_CONFIGS:
    for _a in DEFAULT_ATTACKS:
        if _CATCH[_c] == _a:
            _DEFAULT_PAYOFF[(_c, _a)] = (3.0, 0.0)   # yakalandi: savunucu kazanir
        else:
            _DEFAULT_PAYOFF[(_c, _a)] = (0.0, 3.0)   # kacti: saldirgan kazanir

DEFAULT_HONEYPOT_GAME = {
    "configs": list(DEFAULT_CONFIGS),
    "attacks": list(DEFAULT_ATTACKS),
    "payoff": dict(_DEFAULT_PAYOFF),
    "aciklama_tr": (
        "3 honeypot-yerlesim config'i vs 3 saldiri; her config bir saldiriyi "
        "yakalar. Saf strateji somurulur, karma strateji tabani yukseltir (MTD)."
    ),
}


def _attacks_from_payoff(payoff: dict) -> list:
    """Getiri tablosundan saldiri kumesini (sirali) cikarir."""
    return sorted({a for (_c, a) in payoff})


def attacker_best_response(defender_mixed: dict, payoff: dict) -> dict:
    """Savunucunun karma stratejisine karsi saldirganin en iyi yaniti.

    `defender_mixed`: config -> olasilik (toplam 1). `payoff[(config, attack)]`
    = (defender_util, attacker_util). Saldirgan, beklenen SALDIRGAN faydasini
    maksimize eden saldiriyi secer:
        E_att(a) = sum_c defender_mixed[c] * attacker_util(c, a)

    Beraberlik durumunda (birden fazla saldiri ayni saldirgan faydasini verir)
    savunucu ALEYHINE, yani savunucu beklenen faydasi EN DUSUK olan saldiri
    secilir (zayif/guvenli Stackelberg okumasi); tam beraberlikte isim sirasi.

    Doner: {action, expected_attacker_utility, expected_defender_utility}.
    """
    rows = []
    for a in _attacks_from_payoff(payoff):
        att_u = 0.0
        def_u = 0.0
        for c, p in defender_mixed.items():
            du, au = payoff[(c, a)]
            att_u += p * au
            def_u += p * du
        rows.append((att_u, def_u, a))
    # Sec: en yuksek att_u; beraberlikte en dusuk def_u; sonra isim.
    best = min(rows, key=lambda r: (-r[0], r[1], r[2]))
    return {
        "action": best[2],
        "expected_attacker_utility": round(best[0], 4),
        "expected_defender_utility": round(best[1], 4),
    }


def _simplex_grid(n: int, grid: int):
    """n-boyutlu olasilik simpleksini `grid` seviyeyle tarar (izgara noktalari).

    Adim = 1/(grid-1). i_1+...+i_n = grid-1 olan tum tamsayi bilesimlerini
    olasiliklara cevirip verir (generator)."""
    steps = grid - 1

    def rec(parts_left, remaining):
        if parts_left == 1:
            yield (remaining,)
            return
        for i in range(remaining + 1):
            for rest in rec(parts_left - 1, remaining - i):
                yield (i,) + rest

    for combo in rec(n, steps):
        yield tuple(c / steps for c in combo)


def _entropy(probs) -> float:
    """Bir olasilik vektorunun Shannon entropisi (max-entropi beraberlik icin)."""
    h = 0.0
    for p in probs:
        if p > 0:
            h -= p * math.log(p)
    return h


def _best_pure_utility(configs: list, payoff: dict) -> dict:
    """Saldirgan adapte oldugunda EN IYI SAF stratejinin savunucuya kazandirdigi.

    Her saf config icin saldirgan en iyi yaniti verir; savunucu bunlarin
    en iyisini secebilir. Karma strateji bu tabani asarsa MTD kazanir."""
    best_c = None
    best_u = None
    for c in configs:
        pure = {cc: (1.0 if cc == c else 0.0) for cc in configs}
        du = attacker_best_response(pure, payoff)["expected_defender_utility"]
        if best_u is None or du > best_u:
            best_u = du
            best_c = c
    return {"config": best_c, "defender_utility": best_u}


def stackelberg_defense(configs: list, attacks: list, payoff: dict,
                        grid: int = 11) -> dict:
    """Savunucunun kendini baglayacagi en iyi KARMA stratejiyi kaba kuvvetle bulur.

    Simpleks izgarasindaki her aday dagilim icin saldirganin en iyi yaniti
    hesaplanir ve savunucunun beklenen faydasi olculur. Saldirganin adapte
    olacagi bilindiginden, savunucu bu "en iyi-yanit sonrasi" faydayi maksimize
    eder (Stackelberg lider optimumu). Beraberlikte MAX-ENTROPI (uniform'a en
    yakin) strateji tercih edilir - bu MTD ruhudur (mumkun oldugunca randomize).

    Doner: {strategy (config->prob), defender_utility, attacker_action,
            is_pure (bool), best_pure_utility, reason (Turkce)}.
    """
    best = None  # (def_util, probs, attacker_action, entropy)
    for probs in _simplex_grid(len(configs), grid):
        mixed = {c: probs[i] for i, c in enumerate(configs)}
        br = attacker_best_response(mixed, payoff)
        du = br["expected_defender_utility"]
        ent = _entropy(probs)
        cand = (du, probs, br["action"], ent)
        if best is None or du > best[0] + 1e-12:
            best = cand
        elif abs(du - best[0]) <= 1e-12 and ent > best[3] + 1e-12:
            best = cand  # esit fayda -> daha cok randomize olani sec

    du, probs, action, _ent = best
    strategy = {c: round(probs[i], 4) for i, c in enumerate(configs)}
    is_pure = any(p >= 1.0 - 1e-9 for p in probs)
    pure = _best_pure_utility(configs, payoff)
    best_pure_u = pure["defender_utility"]

    if not is_pure and du > best_pure_u + 1e-9:
        reason = (
            f"Karma (rastgele) strateji savunucuya beklenen {du} fayda saglar; "
            f"en iyi saf strateji ('{pure['config']}') saldirgan adapte olunca "
            f"yalnizca {best_pure_u} garanti eder. Saldirgan dagilimi gozleyip "
            f"en iyi yaniti verse bile, hicbir tek config'e sabitlenmedigimiz "
            f"icin somuremiyor - yeniden-randomize etmek (MTD) saldirganin "
            f"ogrendigi modeli bayatlatir."
        )
    else:
        reason = (
            f"Bu oyunda saf strateji yeterli: savunucu '{pure['config']}' ile "
            f"{best_pure_u} garanti eder, karma strateji ek fayda saglamaz "
            f"(karma optimum {du})."
        )

    return {
        "strategy": strategy,
        "defender_utility": du,
        "attacker_action": action,
        "is_pure": is_pure,
        "best_pure_utility": best_pure_u,
        "reason": reason,
    }


def _sample_config(strategy: dict, rng: random.Random) -> str:
    """Karma stratejiden bu tur canli olacak config'i ornekler (MTD eylemi)."""
    r = rng.random()
    cum = 0.0
    last = None
    for c, p in strategy.items():
        last = c
        cum += p
        if r <= cum:
            return c
    return last


def coevolve(configs: list, attacks: list, payoff: dict,
             rounds: int = 8, seed: int = 1337) -> dict:
    """Ko-evrim dongusu: her tur savunucu yeniden-optimize eder (yeniden-
    randomize), saldirgan gozledigi dagilima en iyi yaniti verir.

    Her tur:
      1. Savunucu Stackelberg karma stratejisini yeniden hesaplar (MTD:
         yeniden-randomize). Dagilimdan bu turun CANLI config'i orneklenir
         (deployed_config) - `random.Random(seed)` ile deterministik.
      2. Saldirgan dagilima en iyi yaniti verir.
      3. Savunucunun beklenen faydasi kaydedilir.

    Ders: yeniden-randomize eden savunucu her tur karma-optimum tabanini TUTAR;
    oysa tek config'e sabitlenen STATIK savunucu, saldirgan uyum sagladikca en
    iyi saf degerine (ya da altina) surulur. Bu, MTD'nin ko-evrimsel gerekcesi.

    Doner: {history: [{round, defender_strategy, deployed_config,
            attacker_action, defender_utility}], converged (bool), summary_tr}.
    """
    rng = random.Random(seed)
    history = []
    for r in range(1, rounds + 1):
        opt = stackelberg_defense(configs, attacks, payoff)
        strat = opt["strategy"]
        deployed = _sample_config(strat, rng)
        br = attacker_best_response(strat, payoff)
        history.append({
            "round": r,
            "defender_strategy": strat,
            "deployed_config": deployed,
            "attacker_action": br["action"],
            "defender_utility": br["expected_defender_utility"],
        })

    utils = [h["defender_utility"] for h in history]
    tail = utils[-3:] if len(utils) >= 3 else utils
    converged = bool(tail) and (max(tail) - min(tail) <= 1e-6)

    pure = _best_pure_utility(configs, payoff)
    held = utils[-1] if utils else 0.0
    summary_tr = (
        f"{rounds} tur ko-evrim: yeniden-randomize eden savunucu her tur "
        f"beklenen {held} faydayi TUTTU (yakinsama={'evet' if converged else 'hayir'}). "
        f"Saldirgan dagilimi ogrense de sabit bir config olmadigindan somuremedi. "
        f"Buna karsilik tek config'e sabitlenmis STATIK savunucu en fazla "
        f"{pure['defender_utility']} alabilirdi - iste bu fark, surekli "
        f"yeniden-randomize etmenin (Hareketli Hedef Savunmasi) kazancidir."
    )

    return {
        "history": history,
        "converged": converged,
        "summary_tr": summary_tr,
    }
