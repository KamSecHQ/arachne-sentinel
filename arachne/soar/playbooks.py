"""
SOAR playbook tanimlari.

Yapi, ticari SOAR urunlerinin ortak sozlugunu takip eder:

    TETIKLEYICI -> ZENGINLESTIRME -> KARAR -> EYLEM -> KAPANIS
    (trigger)      (enrichment)      (decision) (action)  (closure)

Playbook'lar SAF VERIdir - Python sozlugu, calistirilabilir kod degil.
Bunun iki faydasi var: (1) test etmek onemsiz derecede kolay,
(2) ileride bir YAML/JSON dosyasindan okunabilirler, kod degisikligi
gerekmez.

--- Insan onay kapisi politikasi (kritik tasarim karari) ---
| Guven      | Eylem turu                        | Insan onayi |
|------------|-----------------------------------|-------------|
| Herhangi   | Zenginlestirme, kayit, IOC        | Hayir       |
| Yuksek + geri alinabilir | Hiz sinirlama, TTL'li engelleme | Hayir |
| Yuksek + yikici          | Kalici engelleme               | EVET   |
| AI etkili                | Herhangi bir kisitlama         | EVET   |

Son satir en onemlisi: Faz 8'deki yapay zeka katmaninin cikti si HICBIR
ZAMAN dogrudan bir engelleme tetikleyemez (bkz. docs/ARCHITECTURE.md,
OWASP LLM06 "Excessive Agency").
"""

# Her playbook'un yapisi:
#   name          : benzersiz kimlik
#   title_tr      : panelde gosterilen baslik
#   description_tr: neden var oldugunu aciklar
#   trigger       : {"min_score": int, "severities": [...], "requires": [...]}
#   enrichment    : otomatik calisan salt-okunur eylem isimleri
#   decision      : karar kurallari listesi - ilk eslesen kazanir
#   attck         : bu playbook'un ele aldigi teknik ID'leri
#
# decision kurali:
#   {"if": {...kosullar...}, "then": [(eylem_adi, {parametreler}), ...],
#    "because": "insan-okunabilir gerekce"}

PLAYBOOKS = [
    {
        "name": "pb-recon-sweep",
        "title_tr": "Kesif/Tarama Mudahalesi",
        "description_tr": (
            "Port taramasi veya coklu servis kesfi tespit edildiginde devreye girer. "
            "Kesif henuz zarar vermez ama saldirganin haritasini bozmak icin en "
            "dogru andir - bu yuzden MTD rotasyonunu tetikler."
        ),
        "trigger": {"min_score": 25, "severities": ["low", "medium", "high", "critical"],
                    "requires_any": ["Port Scan", "Service Discovery"]},
        "enrichment": ["enrich_ip_scope", "enrich_history"],
        "attck": ["T1046", "T1595.001"],
        "decision": [
            {
                "if": {"repeat_offender": True},
                "then": [("trigger_mtd_rotation", {}),
                         ("rate_limit", {"seconds": 300}),
                         ("tag_and_log", {"tags": ["kesif", "tekrarlayan"]})],
                "because": "Daha once de alarm uretmis bir IP tekrar tariyor - "
                           "firsatci degil, israrli davranis",
            },
            {
                "if": {},
                "then": [("trigger_mtd_rotation", {}),
                         ("tag_and_log", {"tags": ["kesif"]})],
                "because": "Ilk kesif denemesi - hedefi hareket ettirip gozlemeye devam et",
            },
        ],
    },
    {
        "name": "pb-brute-force",
        "title_tr": "Brute-Force Mudahalesi",
        "description_tr": (
            "Ayni servise tekrarli kimlik dogrulama denemeleri. Otomatik araclar "
            "icin hizli ve sureli engelleme yeterlidir; yavas/dagitik denemeler "
            "ise daha sinsi oldugu icin insan onayina yukseltilir."
        ),
        "trigger": {"min_score": 40, "severities": ["medium", "high", "critical"],
                    "requires_any": ["Brute Force"]},
        "enrichment": ["enrich_ip_scope", "enrich_history", "enrich_reverse_engineering"],
        "attck": ["T1110.001"],
        "decision": [
            {
                "if": {"automated": True, "min_events": 15},
                "then": [("block_ip", {"seconds": 900}),
                         ("create_incident", {}),
                         ("tag_and_log", {"tags": ["brute-force", "otomatik-arac"]})],
                "because": "Yuksek hacimli otomatik brute-force - 15 dakikalik "
                           "engelleme hem etkili hem geri alinabilir",
            },
            {
                "if": {"automated": False},
                "then": [("rate_limit", {"seconds": 120}),
                         ("escalate_to_human", {}),
                         ("tag_and_log", {"tags": ["brute-force", "yavas-deneme"]})],
                "because": "Yavas/elle brute-force otomatik araclardan daha hedeflidir; "
                           "kalici karar icin analist degerlendirmesi gerekir",
            },
            {
                "if": {},
                "then": [("rate_limit", {"seconds": 300}),
                         ("tag_and_log", {"tags": ["brute-force"]})],
                "because": "Standart brute-force tepkisi",
            },
        ],
    },
    {
        "name": "pb-web-exploit",
        "title_tr": "Web Somuru Mudahalesi (SQLi/XSS/Command Injection)",
        "description_tr": (
            "Bilinen bir web saldiri imzasi yakalandiginda calisir. Kesiften "
            "farkli olarak burada saldirgan artik SOMURU asamasindadir - "
            "kill chain'de ilerlemis, dolayisiyla daha sert tepki hak eder."
        ),
        "trigger": {"min_score": 50, "severities": ["medium", "high", "critical"],
                    "requires_any": ["SQL Injection", "XSS", "Command Injection",
                                     "Path Traversal"]},
        "enrichment": ["enrich_ip_scope", "enrich_history", "enrich_reverse_engineering"],
        "attck": ["T1190", "T1059.004"],
        "decision": [
            {
                "if": {"has_class": "Command Injection"},
                "then": [("block_ip", {"seconds": 1800}),
                         ("create_incident", {}),
                         ("escalate_to_human", {}),
                         ("tag_and_log", {"tags": ["rce-denemesi", "kritik"]})],
                "because": "Komut enjeksiyonu = uzaktan kod calistirma denemesi. "
                           "En yuksek etkili saldiri sinifi; hem aninda engelle "
                           "hem analist bilgilendir",
            },
            {
                "if": {"automated": True},
                "then": [("block_ip", {"seconds": 900}),
                         ("create_incident", {}),
                         ("tag_and_log", {"tags": ["web-somuru", "otomatik-arac"]})],
                "because": "Otomatik zafiyet tarayicisi - engelle ve kaydet, "
                           "insan mudahalesine gerek yok",
            },
            {
                "if": {},
                "then": [("block_ip", {"seconds": 600}),
                         ("escalate_to_human", {}),
                         ("tag_and_log", {"tags": ["web-somuru", "elle-hazirlanmis"]})],
                "because": "Elle hazirlanmis somuru denemesi hedefli saldiri "
                           "gostergesidir - analist incelemeli",
            },
        ],
    },
    {
        "name": "pb-obfuscated-payload",
        "title_tr": "Gizlenmis Yuk Mudahalesi",
        "description_tr": (
            "Cok katmanli kodlama (base64/URL/hex) ile gizlenmis yuk tespit "
            "edildiginde calisir. Mesru trafik yukunu 3 kat kodlamaz; bu "
            "davranisin kendisi kotu niyet kanitidir (MITRE T1027.010)."
        ),
        "trigger": {"min_score": 30, "severities": ["low", "medium", "high", "critical"],
                    "requires_any": ["Obfuscation"]},
        "enrichment": ["enrich_reverse_engineering", "enrich_history"],
        "attck": ["T1027.010", "T1140"],
        "decision": [
            {
                "if": {"hidden_attack_found": True},
                "then": [("block_ip", {"seconds": 1200}),
                         ("create_incident", {}),
                         ("tag_and_log", {"tags": ["gizlenmis-saldiri", "waf-atlatma"]})],
                "because": "Kodlama katmani altinda GERCEK bir saldiri imzasi bulundu - "
                           "kasitli WAF atlatma girisimi",
            },
            {
                "if": {},
                "then": [("rate_limit", {"seconds": 180}),
                         ("tag_and_log", {"tags": ["gizlenmis-yuk"]})],
                "because": "Gizleme var ama altinda bilinen imza yok - "
                           "supheli, izlemeye devam",
            },
        ],
    },
    {
        "name": "pb-targeted-actor",
        "title_tr": "Hedefli Saldirgan Mudahalesi",
        "description_tr": (
            "Yuksek skor + coklu servis + uzun sureli etkinlik birlesimi. "
            "Bu artik firsatci bir tarayici degil, sistemi ANLAMAYA calisan "
            "kararli bir saldirgandir. En yuksek onceliklidir."
        ),
        "trigger": {"min_score": 90, "severities": ["critical"]},
        "enrichment": ["enrich_ip_scope", "enrich_history", "enrich_reverse_engineering"],
        "attck": ["T1190", "T1046", "T1110"],
        "decision": [
            {
                "if": {},
                "then": [("block_ip", {"seconds": 3600}),
                         ("trigger_mtd_rotation", {}),
                         ("create_incident", {}),
                         ("escalate_to_human", {}),
                         ("tag_and_log", {"tags": ["hedefli-saldirgan", "yuksek-oncelik"]})],
                "because": "Kritik skorlu, coklu vektorlu saldirgan: tam kapsamli "
                           "mudahale - engelle, kimlik degistir, olay ac, analisti cagir",
            },
        ],
    },
]

PLAYBOOKS_BY_NAME = {pb["name"]: pb for pb in PLAYBOOKS}


def find_matching_playbooks(score: int, severity: str, attack_classes: list) -> list:
    """Verilen alarm baglamina uyan tum playbook'lari dondurur.

    Birden fazla playbook eslesirse HEPSI calisir - gercek SOAR
    urunlerinde de boyledir (Sentinel'de otomasyon kurallari sirayla
    calisir). Sonuclar min_score'a gore azalan sirada dondurulur ki en
    ozel/ciddi playbook once islensin."""
    attack_classes = set(attack_classes or [])
    matched = []

    for pb in PLAYBOOKS:
        trigger = pb["trigger"]
        if score < trigger.get("min_score", 0):
            continue
        severities = trigger.get("severities")
        if severities and severity not in severities:
            continue
        requires_any = trigger.get("requires_any")
        if requires_any and not (attack_classes & set(requires_any)):
            continue
        matched.append(pb)

    matched.sort(key=lambda pb: -pb["trigger"].get("min_score", 0))
    return matched


def playbook_summary() -> list:
    """Panelde gosterilecek playbook katalogu."""
    return [
        {
            "name": pb["name"],
            "title_tr": pb["title_tr"],
            "description_tr": pb["description_tr"],
            "min_score": pb["trigger"].get("min_score", 0),
            "triggers_on": pb["trigger"].get("requires_any", ["(skor esigi)"]),
            "attck": pb.get("attck", []),
            "decision_count": len(pb["decision"]),
            "enrichment_count": len(pb["enrichment"]),
        }
        for pb in PLAYBOOKS
    ]
