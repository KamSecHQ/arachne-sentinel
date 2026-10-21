"""
Kasa (crown jewel) uc noktasi — tatbikat hedefi.

--- Amac ---
Korunan 10 haneli sirri (AES-256 ile sifreli) YALNIZCA Arachne'nin savunma
kanalindan sunmak. Flag'e giden tek yol:

    HTTP istegi -> WAF -> panel auth (401) -> SOAR -> /api/vault

Yani flag'i almak = Arachne'yi asmak. Uc, panel_auth tarafindan korunur
(auth'suz /api/ istekleri 401 alir). Ele gecse bile icerik AES-256 ile sifreli
kalir; cozmek icin savunucunun (diskte durmayan) parolasi gerekir. Boylece
tek bir kat (auth) delinse bile sir sizmaz — derinlemesine savunma.

--- Canary ---
/api/vault'a gelen HER istek (auth'suz 401'lenenler dahil) kritik alarma
yazilir. Mesru hicbir kullanici/panel bu ucu cagirmaz, dolayisiyla her dokunus
neredeyse kesin bir kesif/ihlal sinyalidir (yanlis pozitif ~sifir). Savunucu
boylece saldirganin kasayi NE ZAMAN kesfettigini birebir gorur.
"""
import base64
import logging
import os
from pathlib import Path

from flask import jsonify, request

from .. import storage

logger = logging.getLogger("arachne.vault")

VAULT_FILE_ENV = "ARACHNE_VAULT_FILE"
DEFAULT_VAULT_FILE = Path.home() / ".arachne_vault.enc"
VAULT_PATH = "/api/vault"


def _vault_file() -> Path:
    """Sifreli kasa dosyasinin yolu (ortam degiskeni > varsayilan)."""
    env = os.environ.get(VAULT_FILE_ENV)
    return Path(env) if env else DEFAULT_VAULT_FILE


def install(app):
    """Kasa ucunu ve canary'sini uygulamaya ekler.

    ONEMLI: panel_auth.install(app)'ten ONCE cagrilmalidir. Boylece canary
    before_request'i auth guard'indan ONCE calisir ve auth'suz denemeleri de
    (401 donmeden once) kaydeder."""

    @app.before_request
    def _vault_canary():
        if request.path != VAULT_PATH:
            return None
        remote = request.remote_addr or "bilinmiyor"
        reasons = [
            "Kasa (crown jewel) erisim denemesi: /api/vault — mesru hicbir "
            "kullanici bu ucu cagirmaz; neredeyse kesin kesif/ihlal sinyali"
        ]
        try:
            storage.log_event(remote, "vault", "kasa-erisim-denemesi")
            storage.log_alert(remote, score=100, severity="critical", reasons=reasons)
        except Exception:
            logger.warning("Kasa canary kaydedilemedi", exc_info=True)
        return None  # zinciri birakma: panel_auth guard'i devrede kalir

    @app.route(VAULT_PATH)
    def vault():
        # Buraya YALNIZCA kimlik dogrulamis istek ulasir: panel_auth /api/'yi
        # korudugu icin auth'suz istek bu route'tan ONCE 401 alir.
        path = _vault_file()
        if not path.exists():
            return jsonify({"ok": False, "error": "Kasa yapilandirilmamis"}), 404
        try:
            blob = path.read_bytes()
        except OSError:
            logger.warning("Kasa dosyasi okunamadi: %s", path, exc_info=True)
            return jsonify({"ok": False, "error": "Kasa okunamadi"}), 500
        return jsonify({
            "ok": True,
            "vault": base64.b64encode(blob).decode("ascii"),
            "note": "AES-256 ile sifreli. Cozmek icin savunucunun parolasi gerekir.",
        })
