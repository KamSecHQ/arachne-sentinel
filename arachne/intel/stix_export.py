"""
STIX 2.1 formatinda tehdit istihbarati disari aktarimi.

STIX (Structured Threat Information eXpression), OASIS tarafindan
standartlastirilmis, tehdit istihbaratinin makineler arasi paylasim
formatidir. MISP, OpenCTI, ThreatConnect, Anomali gibi platformlar ve
neredeyse tum ticari SIEM'ler bu formati okur.

--- Neden bunu yaptik? ---
Bir guvenlik urununun "gercek" olup olmadiginin en somut testlerinden biri
sudur: ciktilarini baska bir sistem okuyabiliyor mu? Kendi ozel formatinda
JSON basmak kolaydir; standarda uygun STIX uretmek, sistemin ekosisteme
katilabildigini kanitlar.

Uyguladigimiz detaylar (hepsi bilincli):
  * `id` alanlari spec'e uygun: <type>--<UUIDv4>
  * zaman damgalari RFC 3339, UTC, 'Z' ile biter (spec zorunlulugu)
  * `kill_chain_phases` HEM Lockheed Martin HEM MITRE ATT&CK ile doldurulur
    (spec bunu destekler; cift esleme birlikte calisabilirligi artirir)
  * `object_marking_refs` gercek OASIS TLP:GREEN UUID'sini kullanir -
    rastgele UUID uydurmak yerine spec'te tanimli sabit degeri
  * `external_references` ile ATT&CK ve CWE ID'leri kaynaklariyla baglanir

Kaynak: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""
import uuid
from datetime import datetime, timedelta, timezone

from . import attck

SPEC_VERSION = "2.1"

# OASIS spec'inde SABIT olarak tanimli TLP marking ID'leri. Bunlar
# uydurulamaz - spec'te birebir bu UUID'ler yazar.
TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
# Not: yukaridaki TLP:WHITE ve TLP:GREEN ID'leri STIX 2.1 spec Ek E'de
# tanimlidir. Varsayilan olarak GREEN kullaniyoruz: bulgular topluluk
# icinde paylasilabilir ama kamuya acik yayina uygun degildir.
DEFAULT_TLP = "green"

IDENTITY_NAME = "Arachne Sentinel"


def _now_stix() -> str:
    """STIX zorunlulugu: RFC 3339, UTC, milisaniye, 'Z' son eki."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _to_stix_time(ts) -> str:
    """SQLite 'YYYY-MM-DD HH:MM:SS' -> STIX zaman damgasi."""
    if not ts:
        return _now_stix()
    try:
        dt = datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, TypeError):
        return _now_stix()


def _sid(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def build_identity() -> dict:
    """Bulgulari kimin urettigini belirten Identity nesnesi."""
    now = _now_stix()
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _sid("identity"),
        "created": now,
        "modified": now,
        "name": IDENTITY_NAME,
        "description": (
            "Honeypot tabanli erken uyari ve saldiri tespit sistemi "
            "(Topkapi Universitesi ogrenci arastirma projesi)"
        ),
        "identity_class": "system",
        "sectors": ["technology"],
    }


def indicator_for_ip(source_ip: str, *, name=None, description=None,
                     attack_classes=None, tools=None, confidence=50,
                     first_seen=None, identity_id=None, tlp=DEFAULT_TLP,
                     valid_days=30) -> dict:
    """Bir saldirgan IP'si icin STIX Indicator nesnesi uretir."""
    attack_classes = attack_classes or []
    tools = tools or []
    created = _to_stix_time(first_seen)

    # Cerceve eslemelerini topla
    technique_ids, cwe_ids = [], []
    phases = []
    for cls in attack_classes:
        mapping = attck.map_attack_class(cls)
        technique_ids.extend(mapping["attck"])
        cwe_ids.extend(mapping["cwe"])
        phases.append(mapping["kill_chain_phase"])
    technique_ids = sorted(set(technique_ids))
    cwe_ids = sorted(set(cwe_ids))

    lm_phase = attck.furthest_kill_chain_phase(phases or ["reconnaissance"])
    # ATT&CK taktigini teknikten turet
    attck_tactic = "reconnaissance"
    if technique_ids:
        tactic_name = attck.technique_info(technique_ids[0])["tactic"]
        attck_tactic = tactic_name.lower().replace(" ", "-")

    kill_chain_phases = [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": lm_phase},
        {"kill_chain_name": "mitre-attack", "phase_name": attck_tactic},
    ]

    external_references = []
    for tid in technique_ids:
        external_references.append({
            "source_name": "mitre-attack",
            "external_id": tid,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    for cwe in cwe_ids:
        num = cwe.split("-")[-1]
        external_references.append({
            "source_name": "cwe",
            "external_id": cwe,
            "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
        })

    labels = ["honeypot-sourced"]
    labels.extend(tools)
    if attack_classes:
        labels.extend(c.lower().replace(" ", "-") for c in attack_classes)

    # valid_until: gostergenin ne zamana kadar gecerli sayilacagi. IP tabanli
    # gostergeler eskir (adres yeniden tahsis edilir), o yuzden sonlu bir
    # gecerlilik suresi vermek dogru pratiktir.
    valid_until = None
    try:
        dt = datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        valid_until = (dt + timedelta(days=valid_days)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, TypeError):
        valid_until = None

    obj = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _sid("indicator"),
        "created": created,
        "modified": _now_stix(),
        "name": name or f"Honeypot'a saldiran kaynak IP: {source_ip}",
        "description": description or (
            f"{source_ip} adresinden Arachne Sentinel honeypot yuzeyine yonelik "
            f"kotu niyetli etkinlik gozlendi."
        ),
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{source_ip}']",
        "pattern_type": "stix",
        "pattern_version": SPEC_VERSION,
        "valid_from": created,
        "confidence": max(0, min(100, int(confidence))),
        "labels": sorted(set(labels)),
        "kill_chain_phases": kill_chain_phases,
        "object_marking_refs": [TLP_MARKINGS.get(tlp, TLP_MARKINGS[DEFAULT_TLP])],
    }
    if valid_until:
        obj["valid_until"] = valid_until
    if identity_id:
        obj["created_by_ref"] = identity_id
    if external_references:
        obj["external_references"] = external_references
    return obj


def observed_data_for_events(source_ip: str, event_count: int,
                             first_seen=None, last_seen=None,
                             identity_id=None) -> dict:
    """Gozlenen ham veriyi temsil eden ObservedData nesnesi.

    Indicator 'bu kotudur' der; ObservedData 'bunu su kadar kez, su zaman
    araliginda gordum' der. Ikisini birlikte uretmek STIX'in dogru
    kullanimidir."""
    obj = {
        "type": "observed-data",
        "spec_version": SPEC_VERSION,
        "id": _sid("observed-data"),
        "created": _now_stix(),
        "modified": _now_stix(),
        "first_observed": _to_stix_time(first_seen),
        "last_observed": _to_stix_time(last_seen or first_seen),
        "number_observed": max(1, int(event_count)),
        "object_refs": [],
        "object_marking_refs": [TLP_MARKINGS[DEFAULT_TLP]],
    }
    if identity_id:
        obj["created_by_ref"] = identity_id
    return obj


def build_stix_bundle(profiles: list, campaigns: list = None) -> dict:
    """Profillerden tam bir STIX 2.1 Bundle olusturur.

    Bundle icerigi:
      - 1 adet Identity (bulgu ureticisi: Arachne Sentinel)
      - her saldirgan IP icin 1 Indicator + 1 ObservedData
      - korele edilmis her kampanya icin 1 Grouping nesnesi
    """
    campaigns = campaigns or []
    identity = build_identity()
    objects = [identity]
    indicator_ids_by_ip = {}

    for profile in profiles:
        ip = profile.get("source_ip")
        if not ip:
            continue
        attack_classes = profile.get("attack_classes") or []
        tools = [t for t, _ in profile.get("tools", [])]
        # Guven skoru: alarm skoru ve olay hacminden turetilir, 0-100'e sikistirilir
        confidence = min(100, int(profile.get("max_alert_score", 0) * 0.6)
                         + min(30, profile.get("event_count", 0)))

        indicator = indicator_for_ip(
            ip,
            attack_classes=attack_classes,
            tools=tools,
            confidence=confidence,
            first_seen=profile.get("first_seen"),
            identity_id=identity["id"],
            description=(
                f"{ip}: {profile.get('event_count', 0)} olay, "
                f"{profile.get('alert_count', 0)} alarm. "
                f"Tehdit sinifi: {profile.get('threat_class', 'bilinmiyor')}. "
                f"{profile.get('threat_class_reason', '')}"
            ),
        )
        indicator_ids_by_ip[ip] = indicator["id"]
        objects.append(indicator)
        objects.append(observed_data_for_events(
            ip, profile.get("event_count", 0),
            first_seen=profile.get("first_seen"),
            last_seen=profile.get("last_seen"),
            identity_id=identity["id"],
        ))

    for campaign in campaigns:
        refs = [indicator_ids_by_ip[ip] for ip in campaign.get("member_ips", [])
                if ip in indicator_ids_by_ip]
        if len(refs) < 2:
            continue
        objects.append({
            "type": "grouping",
            "spec_version": SPEC_VERSION,
            "id": _sid("grouping"),
            "created_by_ref": identity["id"],
            "created": _now_stix(),
            "modified": _now_stix(),
            "name": f"Korele kampanya {campaign.get('campaign_id', '')}",
            "description": campaign.get("assessment_tr", ""),
            "context": "suspicious-activity",
            "object_refs": refs,
            "object_marking_refs": [TLP_MARKINGS[DEFAULT_TLP]],
        })

    return {
        "type": "bundle",
        "id": _sid("bundle"),
        "objects": objects,
    }


def bundle_stats(bundle: dict) -> dict:
    """Bundle icerigini ozetler (panelde gostermek icin)."""
    counts = {}
    for obj in bundle.get("objects", []):
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1
    return {
        "total_objects": len(bundle.get("objects", [])),
        "by_type": counts,
        "indicators": counts.get("indicator", 0),
        "groupings": counts.get("grouping", 0),
    }
