"""
Kucuk, elle derlenmis bir "bilinen zafiyet" veri seti.

ONEMLI: Bu liste GERCEK ZAMANLI bir CVE beslemesi DEGILDIR - guncel ve
otoriter bir kaynak degildir, sadece egitim/demo amacli, iyi bilinen,
tarihi ornekleri icerir. Gercek bir urunde NVD API (services.nvd.nist.gov)
gibi guncel bir kaynakla degistirilmesi gerekir - bkz. docs/ROADMAP.md.

Format: banner metninde aranacak alt string (kucuk harfe cevrilmis) ->
bulgu bilgisi.
"""

KNOWN_VULNERABLE_BANNERS = {
    "vsftpd 2.3.4": {
        "cve": "CVE-2011-2523",
        "description": (
            "vsFTPd 2.3.4'un bu surumunde, ozel bir kullanici adi girildiginde "
            "arka kapi (backdoor) acan, iyi bilinen bir zafiyet vardir."
        ),
        "severity": "critical",
    },
    "openssh_5.": {
        "cve": "CVE-2011-4327 (ve donem ile ilgili diger CVE'ler)",
        "description": "Bu OpenSSH surum ailesi, guncel olmayan ve bilinen "
                        "zafiyetleri olan bir surumdur.",
        "severity": "medium",
    },
    "apache/2.2": {
        "cve": "CVE-2017-15715 (ve donem ile ilgili diger CVE'ler)",
        "description": "Apache HTTP Server 2.2.x artik guncellenmiyor ve "
                        "bilinen birden fazla zafiyet icerir.",
        "severity": "medium",
    },
    "proftpd 1.3.3": {
        "cve": "CVE-2010-4221",
        "description": "ProFTPd 1.3.3'un bu surumunde bir stack tampon "
                        "tasmasi (buffer overflow) zafiyeti bilinmektedir.",
        "severity": "high",
    },
}


def lookup(banner: str):
    """Verilen banner metnini bilinen zafiyet veri setiyle karsilastirir.

    Donen: dict (finding bilgisi) ya da None (eslesme yoksa).
    """
    if not banner:
        return None
    lowered = banner.lower()
    for needle, info in KNOWN_VULNERABLE_BANNERS.items():
        if needle in lowered:
            return info
    return None
