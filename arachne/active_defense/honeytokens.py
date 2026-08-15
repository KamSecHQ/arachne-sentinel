"""
Faz 12 - Honeytoken / Canary sistemi.

--- Honeytoken nedir? ---
Hicbir mesru amaci olmayan, YALNIZCA tuzak icin var olan bir veri parcasi:
sahte bir API anahtari, sahte bir AWS kimligi, sahte bir veritabani
baglantisi, benzersiz bir "canary" URL'i. Mesru hicbir kullanici bunlara
dokunmaz - cunku onlarin varligindan haberi bile yoktur.

Dolayisiyla bir honeytoken KULLANILDIGI an, bu neredeyse kesin bir izinsiz
erisim kanitidir. Yanlis pozitif orani neredeyse sifirdir - bu, honeytoken'i
guvenlik izlemesinin en dusuk-gurultulu, en yuksek-guvenli sinyallerinden
biri yapar.

Bu, ticari bir urun kategorisidir (Thinkst Canary, AWS honeytokens) ve
kavramin kucuk ama gercek bir uygulamasini kuruyoruz.

--- Nasil calisir? ---
  1. Benzersiz, izlenebilir tokenlar uretilir ve "kasa"ya (vault) kaydedilir.
  2. Bu tokenlar sahte veriye gomulur (Faz 11 aldatma yanitlari) - saldirgan
     onlari "calar".
  3. Saldirgan calinan tokeni baska bir yerde kullanmaya calisirsa (honeypot'a
     geri gonderirse, ya da mesh'teki baska bir sensore giderse), yuk icinde
     token'i taniriz ve YUKSEK GUVENLI bir alarm ureteriz.

--- Format inandiriciligi ---
Tokenlar gercek servislerin format desenlerini taklit eder (AWS anahtari
'AKIA' ile baslar, vb.) ki saldirgan gercek sanip kullanmaya kalksin.
Ama hicbiri gercek bir servise baglanmaz.
"""
import hashlib
import secrets
from dataclasses import dataclass

TOKEN_TYPES = {
    "aws_key": {
        "prefix": "AKIA",
        "description_tr": "Sahte AWS erisim anahtari",
    },
    "api_key": {
        "prefix": "sk_live_",
        "description_tr": "Sahte API anahtari (Stripe format)",
    },
    "db_uri": {
        "prefix": "postgres://",
        "description_tr": "Sahte veritabani baglanti dizesi",
    },
    "jwt": {
        "prefix": "eyJ",
        "description_tr": "Sahte JWT oturum tokeni",
    },
    "canary_url": {
        "prefix": "https://internal-",
        "description_tr": "Canary URL - erisilirse alarm",
    },
    "ssh_key": {
        "prefix": "AAAAB3NzaC1yc2E",
        "description_tr": "Sahte SSH ozel anahtar parcasi",
    },
}


@dataclass
class Honeytoken:
    token_id: str
    token_type: str
    value: str
    description_tr: str
    context: str = ""

    def to_dict(self):
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "value": self.value,
            "description_tr": self.description_tr,
            "context": self.context,
        }


def generate_honeytoken(token_type: str = "api_key", context: str = "") -> Honeytoken:
    """Belirtilen turde benzersiz bir honeytoken uretir."""
    spec = TOKEN_TYPES.get(token_type, TOKEN_TYPES["api_key"])
    # Benzersiz ve izlenebilir govde
    body = secrets.token_hex(16)
    token_id = "ht_" + hashlib.sha256(body.encode()).hexdigest()[:12]

    if token_type == "aws_key":
        value = spec["prefix"] + body[:16].upper()
    elif token_type == "db_uri":
        value = f"{spec['prefix']}svc_user:{body[:12]}@db-internal.local:5432/prod"
    elif token_type == "canary_url":
        value = f"{spec['prefix']}{body[:8]}.corp.local/health?t={token_id}"
    elif token_type == "jwt":
        value = spec["prefix"] + body[:30]
    else:
        value = spec["prefix"] + body[:24]

    return Honeytoken(
        token_id=token_id, token_type=token_type, value=value,
        description_tr=spec["description_tr"], context=context,
    )


class HoneytokenVault:
    """Uretilmis honeytokenlarin kasasi + yuk icinde tespit motoru.

    Kasa, uretilen tum tokenlari (deger -> token_id) tutar. Bir yuk
    geldiginde, kasadaki HERHANGI bir token degeri yuk icinde geciyorsa,
    bu bir honeytoken tetiklenmesidir - yuksek guvenli alarm."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self._tokens = {}         # value -> Honeytoken
        self._by_id = {}          # token_id -> Honeytoken

    def mint(self, token_type: str = "api_key", context: str = "") -> Honeytoken:
        """Yeni bir honeytoken uretir, kasaya ve veritabanina kaydeder."""
        token = generate_honeytoken(token_type, context)
        self._tokens[token.value] = token
        self._by_id[token.token_id] = token
        try:
            from .. import storage
            storage.register_honeytoken(
                token_id=token.token_id, token_type=token.token_type,
                value=token.value, context=context, db_path=self.db_path,
            )
        except Exception:
            pass
        return token

    def mint_set(self, context: str = "aldatma") -> list:
        """Standart bir honeytoken seti uretir (her turden birer tane)."""
        return [self.mint(t, context=context) for t in TOKEN_TYPES]

    def check(self, payload: str, source_ip: str = None) -> list:
        """Bir yuk icinde tetiklenmis honeytoken var mi kontrol eder.

        Once bellek kasasina, sonra kalici veritabanina bakar (baska bir
        surecte/sensorde uretilmis tokenlar da yakalanabilsin)."""
        if not payload:
            return []
        triggered = []

        # Bellekteki tokenlar
        for value, token in self._tokens.items():
            if value in payload:
                triggered.append(token.to_dict())

        # Veritabanindaki tokenlar (surecler/sensorler arasi)
        try:
            from .. import storage
            for row in storage.get_honeytokens(db_path=self.db_path):
                if row["value"] in payload and not any(
                        t["token_id"] == row["token_id"] for t in triggered):
                    triggered.append(row)
        except Exception:
            pass

        # Tetiklenenleri kaydet - bu cok yuksek guvenli bir alarmdir
        for token in triggered:
            self._record_trigger(token, source_ip, payload)

        return triggered

    def _record_trigger(self, token: dict, source_ip: str, payload: str):
        try:
            from .. import storage
            storage.trigger_honeytoken(
                token_id=token["token_id"], source_ip=source_ip or "bilinmiyor",
                context=payload[:200], db_path=self.db_path,
            )
        except Exception:
            pass


def check_payload_for_tokens(payload: str, source_ip: str = None,
                             db_path=None) -> dict:
    """Kolaylik fonksiyonu: bir yuku veritabanindaki tum tokenlara karsi
    kontrol eder VE tetiklenenleri kalici olarak kaydeder.

    source_ip verilirse tetikleme o IP'ye atfedilir; verilmezse 'bilinmiyor'."""
    triggered = []
    try:
        from .. import storage
        for row in storage.get_honeytokens(db_path=db_path):
            if payload and row["value"] in payload:
                triggered.append(row)
                # Tetiklemeyi kalici kaydet (zaten tetiklenmisse tekrar
                # yazmak zararsiz - son goruleni gunceller)
                storage.trigger_honeytoken(
                    token_id=row["token_id"],
                    source_ip=source_ip or "bilinmiyor",
                    context=payload[:200], db_path=db_path,
                )
    except Exception:
        pass
    return {
        "triggered": triggered,
        "count": len(triggered),
        "high_confidence_breach": len(triggered) > 0,
        "assessment_tr": (
            f"HONEYTOKEN TETIKLENDI ({len(triggered)} adet) - bu neredeyse "
            f"kesin bir izinsiz erisim kanitidir; mesru kullanicilar bu "
            f"tuzak degerlerin varligini bilmez, dolayisiyla yanlis pozitif "
            f"olasiligi cok dusuktur"
            if triggered else "Honeytoken tetiklenmedi"
        ),
    }
