"""
Aldatma motoru - saldirgani sahte veriyle yanlis yone yonlendirme.

--- Fikir ---
Saldirgan bir zafiyet aradiginda, ona GERCEK bir hata ya da bos yanit
yerine INANDIRICI AMA SAHTE bir basari donebiliriz. Ornek:
  - Sahte bir "/etc/passwd" icerigi (gercek olmayan kullanicilar)
  - Sahte bir dizin listesi (var olmayan dosyalar)
  - Sahte bir "giris basarili" yaniti (var olmayan bir panele)

Amac cift yonlu:
  1. Saldirgani MESGUL ETMEK: sahte bir izi kovalarken zaman kaybeder.
  2. ISTIHBARAT toplamak: saldirganin sahte veriye nasil tepki verdigi
     (hangi sahte dosyayi indirmeye calisti, hangi sahte krediyi denedi)
     niyeti hakkinda bilgi verir.

--- Kritik guvenlik siniri ---
Sahte veri GERCEK bilgi icermez. Sahte kimlik bilgileri gercek hicbir
sisteme yaramaz. Sahte dosyalar gercek yapilandirma sizdirmaz. Bu, aldatma
ile gercek sizinti arasindaki farktir ve titizlikle korunur.

--- Honeytoken baglantisi ---
Sahte kimlik bilgileri ayni zamanda HONEYTOKEN'dir (Faz 12): eger saldirgan
bu sahte kimligi baska bir yerde kullanmaya calisirsa, bu benzersiz
izlenebilir deger sayesinde yakalanir.
"""
import hashlib
from dataclasses import dataclass

# Sahte veri uretiminde kullanilan belirlenimci havuzlar. Rastgelelik
# yerine IP'den turetilen belirlenimci secim kullaniyoruz ki ayni saldirgan
# tutarli bir sahte dunya gorsun (inandiricilik) ve testler tekrarlanabilir
# olsun.
_FAKE_USERS = ["admin", "backup", "deploy", "svc_sql", "webadmin",
               "jenkins", "oracle", "postgres", "ubuntu", "ec2-user"]
_FAKE_FILES = ["config.php.bak", "database.yml", ".env.production",
               "backup_2026.sql", "id_rsa", "credentials.json",
               "wp-config.php", "settings.py", "docker-compose.yml"]
_FAKE_SHELLS = ["/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/false"]


def _seed(source_ip: str) -> int:
    """IP'den belirlenimci bir tohum uretir (rastgelelik yok - tutarlilik)."""
    return int(hashlib.sha256((source_ip or "x").encode()).hexdigest()[:8], 16)


@dataclass
class DeceptionDecision:
    action: str            # "tarpit" | "fake-success" | "fake-data" | "normal"
    reason: str
    fake_payload: str = ""

    def to_dict(self):
        return {"action": self.action, "reason": self.reason,
                "fake_payload": self.fake_payload[:200]}


def decide_response(threat_score: int, attack_classes=None) -> DeceptionDecision:
    """Tehdit seviyesine gore hangi aldatma stratejisinin uygulanacagina karar verir.

    Dusuk tehdit -> normal honeypot davranisi (mudahale etme).
    Orta tehdit  -> tarpit (yavaslat).
    Yuksek tehdit + belirli saldiri -> sahte veri besle (yanlis yonlendir)."""
    attack_classes = attack_classes or []

    if threat_score < 25:
        return DeceptionDecision("normal", "Dusuk tehdit - standart honeypot yaniti")

    if threat_score < 55:
        return DeceptionDecision(
            "tarpit", "Orta tehdit - saldirgan yavaslatiliyor (zaman harcama)")

    # Yuksek tehdit: saldiri turune gore hedefli sahte veri
    if "Path Traversal" in attack_classes:
        return DeceptionDecision(
            "fake-data", "Dosya okuma denemesi - sahte /etc/passwd donuluyor",
            fake_payload="[deception]")
    if "SQL Injection" in attack_classes:
        return DeceptionDecision(
            "fake-data", "SQLi denemesi - sahte veritabani yaniti donuluyor",
            fake_payload="[deception]")
    if "Brute Force" in attack_classes:
        return DeceptionDecision(
            "fake-success",
            "Brute-force - sahte 'giris basarili' ile saldirgan tuzaga cekiliyor",
            fake_payload="[deception]")

    return DeceptionDecision(
        "tarpit", "Yuksek tehdit - saldirgan yavaslatiliyor ve izleniyor")


def generate_fake_credentials(source_ip: str, count: int = 3) -> list:
    """Sahte (ama honeytoken olarak izlenebilir) kimlik bilgileri uretir.

    Bu kimlikler GERCEK hicbir sisteme yaramaz. Her biri benzersizdir;
    saldirgan bunlari baska bir yerde denerse yakalanir (Faz 12)."""
    seed = _seed(source_ip)
    creds = []
    for i in range(count):
        user = _FAKE_USERS[(seed + i) % len(_FAKE_USERS)]
        # Sahte ama inandirici parola - honeytoken imzasi tasir
        token = hashlib.sha256(f"{source_ip}:{i}:decoy".encode()).hexdigest()[:12]
        creds.append({
            "username": user,
            "password": f"{user.capitalize()}{token[:6]}!",
            "honeytoken_id": f"ht_cred_{token}",
            "note": "SAHTE - gercek hicbir sisteme yaramaz, izlenebilir tuzak",
        })
    return creds


def generate_fake_filesystem(source_ip: str, count: int = 6) -> list:
    """Sahte bir dizin listesi uretir (var olmayan hassas dosyalar)."""
    seed = _seed(source_ip)
    files = []
    for i in range(count):
        name = _FAKE_FILES[(seed + i) % len(_FAKE_FILES)]
        files.append({
            "name": name,
            "size": 1024 + ((seed + i * 37) % 65536),
            "honeytoken_id": f"ht_file_{hashlib.sha256(f'{source_ip}:{name}'.encode()).hexdigest()[:10]}",
        })
    return files


def generate_fake_passwd(source_ip: str, lines: int = 8) -> str:
    """Sahte bir /etc/passwd icerigi (Path Traversal aldatmasi icin).

    Gercek bir sistemden ALINMAMISTIR; tamamen uydurmadir ve gercek
    kullanici/parola icermez."""
    seed = _seed(source_ip)
    rows = ["root:x:0:0:root:/root:/bin/bash"]
    for i in range(1, lines):
        user = _FAKE_USERS[(seed + i) % len(_FAKE_USERS)]
        uid = 1000 + i
        shell = _FAKE_SHELLS[(seed + i) % len(_FAKE_SHELLS)]
        rows.append(f"{user}:x:{uid}:{uid}::/home/{user}:{shell}")
    return "\n".join(rows) + "\n"


class DeceptionEngine:
    """Aldatma eylemlerini uygulayan ve kaydeden motor."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.deception_count = 0

    def apply(self, source_ip: str, threat_score: int,
              attack_classes=None) -> dict:
        """Bir saldirgana karsi aldatma stratejisi uygular ve kaydeder."""
        decision = decide_response(threat_score, attack_classes)

        fake_data = None
        if decision.action == "fake-data":
            if "Path Traversal" in (attack_classes or []):
                fake_data = generate_fake_passwd(source_ip)
            else:
                fake_data = str(generate_fake_credentials(source_ip))
        elif decision.action == "fake-success":
            fake_data = str(generate_fake_credentials(source_ip, count=1))

        if decision.action != "normal":
            self.deception_count += 1
            self._log(source_ip, decision)

        return {
            "decision": decision.to_dict(),
            "fake_data_preview": (fake_data or "")[:300],
            "deception_applied": decision.action != "normal",
        }

    def _log(self, source_ip: str, decision: DeceptionDecision):
        try:
            from .. import storage
            storage.log_active_defense(
                source_ip=source_ip, technique=decision.action,
                detail=decision.reason, db_path=self.db_path,
            )
        except Exception:
            pass
