"""
Faz 23 - Aldatma Agi & Kirinti Yolu (deception grid & breadcrumb trail).

--- Ko-evrim fikri ---
Faz 1-14'te acikca "honeypot" gibi duran tuzaklar kurduk. Olgun bir saldirgan
bunu OGRENIR: bariz honeypot desenlerini (asiri acik portlar, sahte banner,
0-gun gibi duran servis) tanir ve KACINIR - onlara dokunmadan gecer. Tek
katmanli tuzak bu yuzden kordur. Bu modul o kor noktayi kapatir: tuzagi tek
bir kutu olmaktan cikarip KATMANLI bir AGA cevirir.

--- Fikir: kirinti yolu (breadcrumb trail) ---
Gercek yuzeye, hicbir mesru kullanicinin ihtiyac duymadigi KIRINTILAR
(breadcrumb) ekilir: sahte kimlik bilgileri, kayitli SSH/RDP oturumlari,
eslenmis ag surucusu, tarayici parolasi. Her kirinti bir DECOY (yem) hosta
isaret eder. Decoy'lar KATMANLIDIR (tier 1/2/3): tier-1 bariz tuzaklardan
kacan sofistike saldirgan, kirintiyi izleyip tier-2/3 yemine dogru
ilerlediginde yakalanir. Bir decoy'a HERHANGI bir dokunus = SIFIR yanlis
pozitif (zero false positive), cunku hicbir mesru is bu nesnelere dokunmaz.

--- DURUSTLUK NOTU ---
Bu bir yon-graf modelidir; gercek bir agi ele gecirip trafik yonlendirmez.
Kurumsal aldatma gridlerinin (Acalvio/Zscaler/Fidelis), Thinkst Canary'nin ve
MITRE Engage lure/decoy mantiginin CEKIRDEGINI - "kirinti -> katmanli yem ->
dokunus = ihlal" - kucuk, deterministik ve aciklanabilir gosterir. "Sifir
yanlis pozitif" iddiasi TASARIM geregidir (nesneye mesru erisim yolu yoktur),
matematiksel bir garanti degil; yanlis yapilandirma bunu bozabilir. Dokunusu
isaretler; "durdurma"/yanit SOAR katmaninin (Faz 7) isidir.

--- Gercek cerceve eslemesi ---
MITRE Engage (Lures EAC0011, Decoy Account/Content), MITRE D3FEND "Decoy
Object" (D3-DO) / "Decoy Environment", kurumsal aldatma gridleri
(Acalvio ShadowPlex, Zscaler Deception, Fidelis), Thinkst Canary /
canarytokens, ATT&CK "Valid Accounts" tuzagi.

--- ETIK/HUKUKI CERCEVE (degismez) ---
Tamamen SAVUNMADIR. Tum kirinti ve yemler KENDI izleme yuzeyimizde kalir;
hicbir baska sisteme dokunmaz, hack-back yoktur. Kirintilar sahtedir ve
sadece saldirgani kendi yem agimiza cekmeye yarar - baska bir sisteme
saldiri araci degildir.

Harici bagimlilik yok - sadece stdlib.
"""
import random
from dataclasses import dataclass, field


# Bir decoy'a dokununca uretilecek balcik/kirinti (breadcrumb) tipleri.
# Hepsi acikca SAHTE olarak isaretlenir - mesru kullanim yolu yoktur.
_LURE_TYPES = (
    "fake_credential",      # sahte kullanici/parola cifti
    "saved_ssh_session",    # kayitli SSH oturumu (known_hosts girdisi)
    "saved_rdp_session",    # kayitli RDP baglantisi (.rdp dosyasi)
    "mapped_drive",         # eslenmis ag surucusu (\\host\share)
    "browser_password",     # tarayicida kayitli parola
)


@dataclass
class _Intruder:
    """Bir kaynak IP'nin dokundugu nesnelerin izi."""
    source_ip: str
    path: list = field(default_factory=list)      # dokunulan node_id'ler (sirali)
    tiers_seen: set = field(default_factory=set)  # decoy tier'leri
    decoy_touches: int = 0


class DeceptionGrid:
    """Katmanli aldatma agi: gercek capa -> kirinti kenari -> katmanli yem.

    Yonlu bir graf kurar:
      * REAL dugumler   - gercek/gercekcik gorunumlu capa hostlar (kirintinin
                          uzerinde durdugu yer). Bunlara dokunmak ihlal DEGIL.
      * BREADCRUMB       - capanin uzerine ekilmis sahte iz (lure). Kirinti bir
                          decoy'a isaret eder.
      * DECOY dugumler   - yem hostlar, katmanli (tier 1/2/3). Bunlardan
                          herhangi birine dokunmak = ihlal (zero false positive).

    Kenarlar bir `lure_type` tasir (kirintinin turu). `build_default` gercekci
    bir grid doldurur.
    """

    def __init__(self, seed=1337):
        self._rng = random.Random(seed)
        self.nodes = {}   # id -> {id, kind, tier, label, honeytoken_id?}
        self.edges = []   # {from, to, lure_type}
        self._intruders = {}  # source_ip -> _Intruder

    # ---- graf insasi ----

    def add_node(self, node_id: str, kind: str, tier: int = 0,
                 label: str = "", honeytoken_id: str = None) -> dict:
        """Bir dugum ekler. kind: 'real' | 'breadcrumb' | 'decoy'."""
        node = {"id": node_id, "kind": kind, "tier": tier, "label": label}
        if honeytoken_id is not None:
            node["honeytoken_id"] = honeytoken_id
        self.nodes[node_id] = node
        return node

    def add_edge(self, from_id: str, to_id: str, lure_type: str) -> dict:
        """Kirinti kenari: from_id uzerindeki iz to_id'ye isaret eder."""
        edge = {"from": from_id, "to": to_id, "lure_type": lure_type}
        self.edges.append(edge)
        return edge

    def _honeytoken(self, prefix: str) -> str:
        """Deterministik sahte honeytoken kimligi (seed'e bagli)."""
        return f"SAHTE-{prefix}-{self._rng.randrange(16**6):06x}"

    def build_default(self) -> "DeceptionGrid":
        """Gercekci bir aldatma agi doldurur: birkac capa, kirintilar, 3 tier yem.

        Yapi: bir is istasyonu ve bir dosya sunucusu (capa) uzerine sahte
        kimlik/oturum kirintilari ekilir; bunlar tier-1 yemine, o tier-2'ye,
        o da tier-3 'crown jewel' yemine isaret eder. Sofistike saldirgan
        tier-1'i atlasa bile derindeki kirintiyi izleyince tier-2/3'te yakalanir.
        """
        # Gercek capa hostlar (kirintinin uzerinde durdugu, mesru gorunen yer).
        self.add_node("ws-01", "real", tier=0, label="Kullanici is istasyonu")
        self.add_node("fs-01", "real", tier=0, label="Dosya sunucusu")

        # Katmanli yemler (decoy). Artan etkilesim seviyesi.
        self.add_node("decoy-t1-jump", "decoy", tier=1,
                      label="Sahte atlama sunucusu (jump box)",
                      honeytoken_id=self._honeytoken("JUMP"))
        self.add_node("decoy-t2-db", "decoy", tier=2,
                      label="Sahte veritabani sunucusu",
                      honeytoken_id=self._honeytoken("DB"))
        self.add_node("decoy-t3-dc", "decoy", tier=3,
                      label="Sahte etki alani denetleyici (crown jewel)",
                      honeytoken_id=self._honeytoken("DC"))

        # Kirinti dugumleri (breadcrumb) - capa uzerinde duran sahte izler.
        self.add_node("bc-ws-cred", "breadcrumb", tier=0,
                      label="ws-01 uzerinde sahte kimlik bilgisi")
        self.add_node("bc-ws-rdp", "breadcrumb", tier=0,
                      label="ws-01 uzerinde kayitli RDP oturumu")
        self.add_node("bc-fs-ssh", "breadcrumb", tier=0,
                      label="fs-01 uzerinde kayitli SSH oturumu")
        self.add_node("bc-fs-drive", "breadcrumb", tier=0,
                      label="fs-01 uzerinde eslenmis ag surucusu")

        # Kenarlar: capa -> kirinti -> yem zinciri.
        self.add_edge("ws-01", "bc-ws-cred", "fake_credential")
        self.add_edge("ws-01", "bc-ws-rdp", "saved_rdp_session")
        self.add_edge("fs-01", "bc-fs-ssh", "saved_ssh_session")
        self.add_edge("fs-01", "bc-fs-drive", "mapped_drive")

        # Kirintilar tier-1 yemine isaret eder.
        self.add_edge("bc-ws-cred", "decoy-t1-jump", "fake_credential")
        self.add_edge("bc-ws-rdp", "decoy-t1-jump", "saved_rdp_session")
        self.add_edge("bc-fs-ssh", "decoy-t1-jump", "saved_ssh_session")
        self.add_edge("bc-fs-drive", "decoy-t2-db", "mapped_drive")

        # Yemler daha derin yemlere isaret eder (tirmanan etkilesim).
        self.add_edge("decoy-t1-jump", "decoy-t2-db", "saved_ssh_session")
        self.add_edge("decoy-t2-db", "decoy-t3-dc", "fake_credential")
        return self

    # ---- izinsiz giris kaydi ----

    def record_touch(self, node_id: str, source_ip: str, clock=None) -> bool:
        """Bir davetsiz misafirin bir dugume dokundugunu kaydeder.

        Bilinmeyen dugumde nazikce yok sayar (False doner). Mesru bir dokunus
        beklenmez - ozellikle decoy dokunuslari ihlal sayilir. `clock` API
        uyumlulugu icin kabul edilir (siralama dokunus sirasiyla korunur).
        """
        if node_id not in self.nodes:
            return False
        intr = self._intruders.get(source_ip)
        if intr is None:
            intr = _Intruder(source_ip=source_ip)
            self._intruders[source_ip] = intr
        intr.path.append(node_id)
        node = self.nodes[node_id]
        if node["kind"] == "decoy":
            intr.decoy_touches += 1
            intr.tiers_seen.add(node["tier"])
        return True

    def intruder_depth(self, source_ip: str) -> dict:
        """Bir kaynagin aldatma agindaki derinligini/ihlal durumunu ozetler."""
        intr = self._intruders.get(source_ip)
        if intr is None or not intr.path:
            return {
                "source_ip": source_ip,
                "max_tier": 0,
                "decoy_touches": 0,
                "path": [],
                "is_breach": False,
                "verdict": "Bu kaynak henuz hicbir aldatma nesnesine dokunmadi",
            }
        max_tier = max(intr.tiers_seen) if intr.tiers_seen else 0
        is_breach = intr.decoy_touches > 0
        if is_breach:
            verdict = (
                f"IHLAL: {source_ip} kirinti yolunu izleyip tier-{max_tier} "
                f"yemine ulasti ({intr.decoy_touches} decoy dokunusu). Mesru "
                f"hicbir is bu nesnelere dokunmaz -> yuksek guven, sifir yanlis "
                f"pozitif.")
        else:
            verdict = (
                f"{source_ip} sadece kirinti/capa nesnelerine dokundu "
                f"(henuz yem yok) - iz suruluyor, tirmanma izleniyor.")
        return {
            "source_ip": source_ip,
            "max_tier": max_tier,
            "decoy_touches": intr.decoy_touches,
            "path": list(intr.path),
            "is_breach": is_breach,
            "verdict": verdict,
        }

    def plant_breadcrumbs(self) -> list:
        """Ekilecek kirintilari (lure) acikca SAHTE degerlerle uretir.

        Her kirinti bir kenardan turer; degerler bariz sahtedir (SAHTE- oneki)
        boylece bir mesru kullanici yanlislikla kullanamaz ama bir saldirgan
        icin cazip gorunur. Sadece breadcrumb/decoy'a isaret eden kenarlar.
        """
        lures = []
        for edge in self.edges:
            src = self.nodes.get(edge["from"])
            dst = self.nodes.get(edge["to"])
            if not src or not dst:
                continue
            # Yalnizca capa/kirintidan cikan gorunur izleri ek (yem-yem ici degil).
            if src["kind"] not in ("real", "breadcrumb"):
                continue
            lure_type = edge["lure_type"]
            token = self._honeytoken(lure_type.upper())
            if lure_type == "fake_credential":
                value = f"SAHTE\\svc-backup : SAHTE-Passw0rd-{token[-6:]}"
            elif lure_type == "saved_ssh_session":
                value = f"SAHTE root@{dst['id']} (known_hosts: {token})"
            elif lure_type == "saved_rdp_session":
                value = f"SAHTE {dst['id']}.corp.local.rdp ({token})"
            elif lure_type == "mapped_drive":
                value = f"SAHTE Z: -> \\\\{dst['id']}\\finans ({token})"
            elif lure_type == "browser_password":
                value = f"SAHTE https://{dst['id']} : admin/{token}"
            else:
                value = f"SAHTE {token}"
            lures.append({
                "on_node": edge["from"],
                "points_to": edge["to"],
                "lure_type": lure_type,
                "value": value,
                "is_fake": True,
            })
        return lures

    def grid_summary(self) -> dict:
        """Grid'in genel ozeti: kind/tier sayilari, aktif davetsizler."""
        by_kind = {}
        by_tier = {}
        for node in self.nodes.values():
            by_kind[node["kind"]] = by_kind.get(node["kind"], 0) + 1
            if node["kind"] == "decoy":
                t = node["tier"]
                by_tier[t] = by_tier.get(t, 0) + 1
        breadcrumbs = by_kind.get("breadcrumb", 0)
        active = sum(1 for i in self._intruders.values() if i.path)
        breached = sum(1 for i in self._intruders.values() if i.decoy_touches > 0)
        return {
            "by_kind": by_kind,
            "decoys_by_tier": by_tier,
            "total_breadcrumbs": breadcrumbs,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "active_intruders": active,
            "breached_intruders": breached,
            "zero_false_positive_note": (
                "Bir decoy'a dokunmak tasarim geregi yanlis pozitif uretmez: "
                "hicbir mesru kullanici/servis bu yem nesnelerine erisim yoluna "
                "sahip degildir - dokunus = kasitli kesif."
            ),
        }
