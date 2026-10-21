"""
Yem (honeytoken) uc noktalari — SESSIZ tripwire + inandirici sahte icerik.

--- Amac ---
Web'i tarayan saldirgani cazip ama SAHTE hedeflerle kandirmak. Hicbir mesru
kullanici /flag.txt, /.env, /api/backup gibi uclara dokunmaz; dolayisiyla her
dokunus neredeyse kesin bir ihlal sinyalidir (yanlis pozitif ~sifir).

--- Tasarim: SESSIZ yakalama ---
Yem, saldirganin ekranina "YAKALANDIN" BAGIRMAZ. Bunun yerine INANDIRICI sahte
icerik (sahte flag, sahte .env, sahte yedek) doner — saldirgan "buldum" sanip
zaman kaybeder. Alarm ise SESSIZCE savunucunun paneline dusser. Boylece:
  * Zayif saldirgan yeme kanar, farkinda olmadan yakalanir.
  * Iyi saldirgan "bu cok kolay, tuzak olabilir" deyip DOKUNMAZ — ama dokunmazsa
    hedefe de ulasamaz. Iste "alarmsiz sizma" sinavi tam burada.

Yem ucuna dokunulan an (sadece ISTEK yeterli, "inanmak" gerekmez):
  1. Komuta merkezine KRITIK alarm dusser (savunucunun ekrani).
  2. core_vault_breach_illusion kaydedilir -> Son Hat (yer alti 50 katman)
     "GERCEK SINYAL" ile devreye girer.
  3. Saldirganin ekranina sahte ganimet doner (makinesinde KOD CALISMAZ).

--- Tum degerler SAHTE ---
Asagidaki anahtar/parola/hash'lerin HICBIRI gercek degildir; klasik honeytoken
(kanarya) degerleridir. Gercek flag AES ile sifreli kasadadir, burada DEGIL.

--- Neden auth'tan once? ---
Yem uclari bilerek KIMLIK DOGRULAMASIZ erisilebilir olmali (tuzak davetkar
olmali). Bu yuzden decoy.install(app), panel_auth.install'dan ONCE cagrilir.
"""
import logging

from flask import Response, request

from .. import storage

logger = logging.getLogger("arachne.decoy")

# Yol -> (inandirici SAHTE icerik, mimetype). Hepsi sahte honeytoken degeri.
DECOYS = {
    "/flag.txt": (
        "# production flag dosyasi - gizli\n"
        "FLAG{ar4chn3_pr0d_c0r3_2026_rotate_weekly}\n", "text/plain"),
    "/flag": (
        "FLAG{ar4chn3_pr0d_c0r3_2026_rotate_weekly}\n", "text/plain"),
    "/.env": (
        "DATABASE_URL=postgres://arachne:S3cr3t_db_P4ss@db.internal:5432/arachne\n"
        "SECRET_KEY=8f3a9c2e7b1d4056a9e8c7b6d5f4e3a2\n"
        "AWS_ACCESS_KEY_ID=AKIA-DECOY-HONEYPOT-NOTREAL\n"
        "AWS_SECRET_ACCESS_KEY=decoy-honeypot-secret-not-a-real-aws-value\n"
        "ADMIN_PASSWORD=Adm1n_2026_change_me\n", "text/plain"),
    "/secrets.txt": (
        "admin:Adm1n_2026_change_me\n"
        "backup:B4ckup_svc_2026\n"
        "api_token=DECOY-api-token-not-a-real-key\n", "text/plain"),
    "/backup.sql": (
        "-- MySQL dump (arachne prod)  Server version 8.0.34\n"
        "INSERT INTO users VALUES (1,'admin','$2b$12$aBcFakeHashFakeHashFakeHa');\n"
        "INSERT INTO api_keys VALUES (1,'DECOY-api-token-not-a-real-key');\n", "text/plain"),
    "/.git/config": (
        "[core]\n\trepositoryformatversion = 0\n"
        "[remote \"origin\"]\n"
        "\turl = https://arachne:DECOY-git-token-not-a-real-key@github.com/internal/arachne.git\n",
        "text/plain"),
    "/api/backup": (
        '{"ok":true,"generated":"2026-10-21T02:00:00Z",'
        '"users":[{"id":1,"user":"admin","role":"superadmin"}],'
        '"api_token":"DECOY-api-token-not-a-real-key"}', "application/json"),
    "/api/credentials": (
        '{"db_password":"S3cr3t_db_P4ss","admin_password":"Adm1n_2026_change_me",'
        '"jwt_secret":"8f3a9c2e7b1d4056a9e8c7b6d5f4e3a2"}', "application/json"),
}


def install(app):
    """Yem uclarini (sessiz tripwire + sahte ganimet) ekler.

    ONEMLI: panel_auth.install(app)'ten ONCE cagrilmalidir ki yem uclari kimlik
    dogrulamasiz erisilebilsin ve istek auth guard'indan once kisa devre yapilsin."""

    @app.before_request
    def _decoy():
        path = request.path
        entry = DECOYS.get(path)
        if entry is None:
            return None
        remote = request.remote_addr or "bilinmiyor"
        try:
            # SESSIZ yakalama: panele kritik alarm + cekirdek-yemi (Son Hat).
            storage.log_event(remote, "decoy", "yem-acildi")
            storage.log_alert(remote, score=100, severity="critical", reasons=[
                f"Yem (honeytoken) acildi: {path} — saldirgan sahte hedefi "
                "gercek sandi; neredeyse kesin ihlal sinyali (yanlis pozitif ~sifir)"
            ])
            storage.log_active_defense(
                source_ip=remote, technique="core_vault_breach_illusion",
                detail=f"Yem ucu acildi: {path}")
        except Exception:
            logger.warning("Yem tetikleyici kaydedilemedi", exc_info=True)
        body, mimetype = entry
        # Saldirganin ekranina INANDIRICI sahte ganimet (kod CALISMAZ, sadece yanit).
        return Response(body, status=200, mimetype=f"{mimetype}; charset=utf-8")
