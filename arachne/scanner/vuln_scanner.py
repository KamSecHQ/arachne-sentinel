"""Port tarama + banner grabbing + bilinen zafiyet eslestirmeyi birlestiren
otonom zafiyet tarayici. Sonuclari storage'a kaydeder ki reporting katmani
bunlari da rapora dahil edebilsin."""
import logging

from .. import storage
from . import known_vulnerabilities, port_scanner

logger = logging.getLogger("arachne.scanner")


def scan_and_report(host: str, ports=None, timeout: float = 1.0, db_path=None):
    """Hedefi tarar, her acik port icin bir bulgu kaydeder (zafiyet olsun ya
    da olmasin - acik bir port da basli basina bir bulgudur), donen listeyi
    de verir."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            "UYARI: %s yerel olmayan bir hedef. Sadece sahip oldugunuz veya "
            "test izniniz olan sistemleri tarayin (bkz. docs/ETHICS_AND_LEGAL.md).",
            host,
        )

    open_ports = port_scanner.scan_target(host, ports=ports, timeout=timeout)
    findings = []

    for entry in open_ports:
        vuln = known_vulnerabilities.lookup(entry["banner"])
        if vuln:
            finding_text = f"{vuln['cve']}: {vuln['description']}"
            severity = vuln["severity"]
        else:
            finding_text = "Acik port tespit edildi, bilinen bir zafiyet eslesmedi."
            severity = "info"

        storage.log_scan_finding(
            target=host, port=entry["port"], service_guess=entry["service_guess"],
            banner=entry["banner"], finding=finding_text, severity=severity,
            db_path=db_path,
        )
        findings.append({**entry, "finding": finding_text, "severity": severity})

    return findings
