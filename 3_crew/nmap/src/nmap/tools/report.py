from pathlib import Path
from typing import Dict, List


def build_markdown_report(
    *,
    target: str,
    timestamp: str,
    open_services: List[Dict[str, str]],
    analysis_text: str,
    cves_in_output: List[str],
    matched_cves: List[Dict[str, object]],
    raw_output: str,
    scan_results: List[Dict[str, object]],
) -> str:
    """Create the Markdown report content with required sections."""
    lines: List[str] = []
    lines.append(f"# Nmap Report for {target}")
    lines.append("")
    lines.append(f"Generated: {timestamp} UTC")
    lines.append("")

    # Summary section
    lines.append("## Summary")
    if open_services:
        lines.append("Open services:")
        for svc in open_services:
            v = svc.get("product_version") or svc.get("version") or ""
            lines.append(
                f"- {svc['protocol']}/{svc['port']} {svc['service']} {svc.get('product','').strip()} {v}".rstrip()
            )
    else:
        lines.append("No open services were detected in the performed scans.")
    lines.append("")

    # Vulnerability analysis section
    lines.append("## Vulnerability Analysis")
    lines.append(analysis_text.strip())
    lines.append("")

    # Known CVEs (directly from output script results)
    lines.append("### CVEs Referenced in Output")
    if cves_in_output:
        for cve in sorted(set(cves_in_output)):
            lines.append(f"- {cve} — https://nvd.nist.gov/vuln/detail/{cve}")
    else:
        lines.append("- None found in output")
    lines.append("")

    # Inferred CVEs from version mappings
    lines.append("### Inferred CVEs from Service Versions")
    if matched_cves:
        for match in matched_cves:
            pv = match.get("product_version") or ""
            svc = f"{match.get('service','')} {pv}".strip()
            cves = ", ".join(match.get("cves", []))
            lines.append(f"- {match.get('protocol')}/{match.get('port')} {svc}: {cves}")
    else:
        lines.append("- No inferred CVEs from local mapping")
    lines.append("")

    # Raw output section
    lines.append("## Raw Nmap Output")
    lines.append("```bash")
    lines.append(raw_output.rstrip())
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def write_report(directory: Path, filename: str, content: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path

