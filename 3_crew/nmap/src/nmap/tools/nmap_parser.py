import re
from pathlib import Path
from typing import Dict, List


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def parse_open_services(nmap_text: str) -> List[Dict[str, str]]:
    """Parse open services from Nmap normal output.

    Returns a list of dicts: port, protocol, state, service, product, version, product_version, cpe
    """
    services: List[Dict[str, str]] = []
    if not nmap_text:
        return services

    # Capture the table under PORT ... lines
    in_ports = False
    for line in nmap_text.splitlines():
        if line.strip().startswith("PORT "):
            in_ports = True
            continue
        if in_ports:
            if not line.strip():
                # blank line ends the section in most outputs
                in_ports = False
                continue
            # Common line format examples:
            # 22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
            # 80/tcp open  http    Apache httpd 2.4.49 ((Unix))
            # 53/udp open  domain
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)?\s*(.*)$", line.strip())
            if not m:
                # If doesn't match, continue scanning
                continue
            port, proto, state, service, rest = m.groups()
            product = ""
            version = ""
            product_version = ""
            cpe = ""
            if rest:
                # Try to extract product/version
                # Heuristic: product words + version-like token within rest
                ver = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9._-]+)?)", rest)
                if ver:
                    version = ver.group(1)
                # Product as first tokens if present
                tokens = rest.split()
                if tokens:
                    product = tokens[0]
                    # If product then version, combine
                    product_version = (product + " " + version).strip()
            services.append(
                {
                    "port": port,
                    "protocol": proto,
                    "state": state,
                    "service": service or "",
                    "product": product,
                    "version": version,
                    "product_version": product_version,
                    "cpe": cpe,
                }
            )
    return services


def extract_cves(nmap_text: str) -> List[str]:
    if not nmap_text:
        return []
    return sorted(set(_CVE_RE.findall(nmap_text)))


def _load_cve_mappings() -> List[Dict[str, object]]:
    """Load simple regex-based CVE mappings from knowledge file.

    The file is optional and meant for extensibility.
    """
    # Relative to this file: ../../../knowledge/cve_mappings.txt (simple CSV-like)
    this_dir = Path(__file__).resolve().parents[3]
    mapping_file = this_dir / "knowledge" / "cve_mappings.txt"
    mappings: List[Dict[str, object]] = []
    if not mapping_file.exists():
        return mappings
    for line in mapping_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: regex_pattern | CVE-YYYY-NNNN[,CVE-YYYY-NNNN]
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 2:
            continue
        pat, cves = parts
        cve_list = [c.strip() for c in cves.split(",") if c.strip()]
        mappings.append({"pattern": re.compile(pat, re.IGNORECASE), "cves": cve_list})
    return mappings


_MAPPINGS = _load_cve_mappings()


def correlate_versions_to_cves(open_services: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """Use simple regex mappings to suggest possible CVEs for found services."""
    results: List[Dict[str, object]] = []
    if not open_services or not _MAPPINGS:
        return results
    for svc in open_services:
        text = " ".join(
            filter(
                None,
                [
                    svc.get("service", ""),
                    svc.get("product", ""),
                    svc.get("version", ""),
                    svc.get("product_version", ""),
                ],
            )
        )
        matched: List[str] = []
        for rule in _MAPPINGS:
            pat = rule["pattern"]
            if pat.search(text):
                matched.extend(rule["cves"])  # type: ignore[index]
        if matched:
            results.append(
                {
                    "port": svc.get("port"),
                    "protocol": svc.get("protocol"),
                    "service": svc.get("service"),
                    "product_version": svc.get("product_version") or svc.get("version"),
                    "cves": sorted(set(matched)),
                }
            )
    return results


def aggregate_scan_outputs(scan_results: List[Dict[str, object]]) -> str:
    """Combine multiple scan outputs into one text with phase headers."""
    parts: List[str] = []
    for r in scan_results:
        phase = str(r.get("phase", "scan"))
        cmd = str(r.get("stdin", ""))
        success = r.get("success", False)
        parts.append(f"===== PHASE: {phase} =====")
        parts.append(f"$ {cmd}")
        if success:
            parts.append(str(r.get("stdout", "")).rstrip())
        else:
            parts.append("[Scan failed]\n" + str(r.get("stderr", "")).rstrip())
        parts.append("")
    return "\n".join(parts).strip() + "\n"
