"""
Kurcalama-kaniti denetim zinciri (hash chain + Merkle root).

--- Hash zinciri nasil kurcalamayi ele verir? ---
Her kayit bir hash tutar:  H(n) = SHA256( veri(n) + H(n-1) )
Yani her kaydin hash'i bir oncekine baglidir. Ortadaki tek bir kaydi
degistirirseniz, o kaydin hash'i degisir; bu da bir sonraki kaydin
hash'ini bozar ve zincir boyunca yayilir. Sonuc: en son hash'i (zincir
ucunu) bilen biri, gecmisin degistirilip degistirilmedigini anlar.

--- Merkle koku ne ise yarar? ---
Zincirin ucu tek bir kaydin butunlugunu dogrular; Merkle koku ise TUM
kumeyi tek bir 32-byte parmak iziyle ozetler. Bu koku, veritabanindan ayri
guvenli bir yere (ornek: yazma-korumali bir dosya ya da harici sistem)
kaydedilirse, tum denetim gunlugunun butunlugu tek bir degerle dogrulanir.

--- Neden "hafif blockchain"? ---
Gercek dagitik blockchain'ler is-kaniti (proof-of-work), fikir birligi
(consensus) ve dagitik defter gerektirir - bize gereksiz agirlik. Bize
gereken tek sey KURCALAMA TESPITI; onun icin hash zinciri yeterlidir ve
kriptografik olarak saglamdir. Bunu boyle acikca soylemek (blockchain
pazarlamasi yapmamak) projenin durustluk ilkesine uygundur.

Sadece stdlib hashlib - harici bagimlilik yok.
"""
import hashlib
import json

GENESIS_HASH = "0" * 64


def _hash_record(data: dict, prev_hash: str) -> str:
    """H(n) = SHA256( belirlenimci_json(veri) + H(n-1) )."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256((canonical + prev_hash).encode("utf-8")).hexdigest()


class AuditChain:
    """Bellek-ici kurcalama-kaniti denetim zinciri.

    Kullanim:
        chain = AuditChain()
        chain.append({"action": "block_ip", "target": "203.0.113.5"})
        chain.append({"action": "unblock_ip", "target": "203.0.113.5"})
        ok, idx = chain.verify()   # (True, None) - zincir saglam
    """

    def __init__(self):
        self.records = []   # her kayit: {"index", "data", "prev_hash", "hash"}

    @property
    def head(self) -> str:
        """Zincirin ucundaki hash (son kaydin hash'i)."""
        return self.records[-1]["hash"] if self.records else GENESIS_HASH

    def append(self, data: dict) -> dict:
        """Yeni bir kaydi zincire ekler ve hash'ini hesaplar."""
        prev = self.head
        record_hash = _hash_record(data, prev)
        record = {
            "index": len(self.records),
            "data": data,
            "prev_hash": prev,
            "hash": record_hash,
        }
        self.records.append(record)
        return record

    def verify(self) -> tuple:
        """Tum zinciri bastan sona yeniden hesaplayarak dogrular.

        Donen: (gecerli_mi, ilk_bozuk_indeks)
        Zincir saglamsa (True, None); bir kayit kurcalanmıssa
        (False, o kaydin indeksi)."""
        prev = GENESIS_HASH
        for record in self.records:
            if record["prev_hash"] != prev:
                return False, record["index"]
            expected = _hash_record(record["data"], prev)
            if record["hash"] != expected:
                return False, record["index"]
            prev = record["hash"]
        return True, None

    def merkle_root(self) -> str:
        """Tum kayitlarin Merkle koku."""
        return merkle_root([r["hash"] for r in self.records])

    def to_list(self) -> list:
        return list(self.records)

    def __len__(self):
        return len(self.records)


def verify_chain(records: list) -> tuple:
    """Serilestirilmis bir kayit listesinin butunlugunu dogrular.

    (Veritabanindan/dosyadan okunmus kayitlar icin bagimsiz dogrulama.)"""
    prev = GENESIS_HASH
    for record in records:
        if record.get("prev_hash") != prev:
            return False, record.get("index")
        expected = _hash_record(record["data"], prev)
        if record.get("hash") != expected:
            return False, record.get("index")
        prev = record["hash"]
    return True, None


def merkle_root(hashes: list) -> str:
    """Bir hash listesinin Merkle kokunu hesaplar.

    Cift sayida degilse son elemani kendisiyle esler (standart yaklasim).
    Bos liste icin genesis hash doner."""
    if not hashes:
        return GENESIS_HASH
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])   # tek eleman: kendisiyle esle
        nxt = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            nxt.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
        level = nxt
    return level[0]


def tamper_report(chain: AuditChain) -> dict:
    """Panelde gosterilecek butunluk durum raporu."""
    valid, bad_index = chain.verify()
    return {
        "record_count": len(chain),
        "chain_valid": valid,
        "first_tampered_index": bad_index,
        "head_hash": chain.head,
        "merkle_root": chain.merkle_root(),
        "assessment_tr": (
            f"Denetim zinciri SAGLAM - {len(chain)} kayit kurcalanmamis"
            if valid else
            f"KURCALAMA TESPIT EDILDI - {bad_index}. kayit degistirilmis; "
            f"bu indeksten sonraki tum kayitlarin guvenilirligi supheli"
        ),
    }
