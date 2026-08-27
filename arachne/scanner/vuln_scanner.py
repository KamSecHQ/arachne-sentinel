"""Port tarama + banner grabbing + bilinen zafiyet eslestirmeyi birlestiren
otonom zafiyet tarayici. Sonuclari storage'a kaydeder ki reporting katmani
bunlari da rapora dahil edebilsin."""
import logging

from .. import storage
from . import known_vulnerabilities, port_scanner

logger = logging.getLogger("arachne.scanner")


def scan_and_report(host: str, ports=None, timeout: float = 1.0, db_path=None,
                    use_nvd: bool = False):
    """Hedefi tarar, her acik port icin bir bulgu kaydeder (zafiyet olsun ya
    da olmasin - acik bir port da basli basina bir bulgudur), donen listeyi
    de verir.

    `use_nvd=True` (Faz 107) verilirse, statik `known_vulnerabilities`
    listesine EK olarak NVD'nin canli CVE veritabani da sorgulanir (ayrica
    ARACHNE_NVD_ENABLED=1 gerekir - cift kilit, bkz. nvd_lookup.py).
    NVD kapali/basarisiz/kotaya takilirsa bos liste doner ve sistem
    SESSIZCE sadece statik listeyle calismaya devam eder - regresyon yok."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            "UYARI: %s yerel olmayan bir hedef. Sadece sahip oldugunuz veya "
            "test izniniz olan sistemleri tarayin (bkz. docs/ETHICS_AND_LEGAL.md).",
            host,
        )

    open_ports = port_scanner.scan_target(host, ports=ports, timeout=timeout)
    findings = []

    for entry in open_ports:
        static_vuln = known_vulnerabilities.lookup(entry["banner"])

        nvd_matches = []
        if use_nvd and entry.get("service_guess"):
            try:
                from . import nvd_lookup
                nvd_matches = nvd_lookup.lookup_by_keyword(
                    entry["service_guess"], db_path=db_path)
            except Exception:
                logger.debug("NVD sorgusu basarisiz, statik listeyle devam ediliyor",
                            exc_info=True)

        # Statik + NVD sonuclarini CVE ID'ye gore birlestir/tekillestir -
        # statik liste her zaman ONCE gelir (elle dogrulanmis, daha guvenilir).
        merged = []
        seen_cves = set()
        if static_vuln:
            merged.append({"cve": static_vuln["cve"], "description": static_vuln["description"],
                          "severity": static_vuln["severity"], "source": "static"})
            seen_cves.add(static_vuln["cve"])
        for match in nvd_matches:
            if match["cve"] not in seen_cves:
                merged.append(match)
                seen_cves.add(match["cve"])

        if merged:
            top = merged[0]
            finding_text = f"{top['cve']} [{top['source']}]: {top['description']}"
            severity = top["severity"]
        else:
            finding_text = "Acik port tespit edildi, bilinen bir zafiyet eslesmedi."
            severity = "info"

        storage.log_scan_finding(
            target=host, port=entry["port"], service_guess=entry["service_guess"],
            banner=entry["banner"], finding=finding_text, severity=severity,
            db_path=db_path,
        )
        findings.append({**entry, "finding": finding_text, "severity": severity,
                         "all_matches": merged})

    return findings
