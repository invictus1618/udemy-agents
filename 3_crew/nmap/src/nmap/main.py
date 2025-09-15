#!/usr/bin/env python
import argparse
import logging
import os
import re
import sys
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from nmap.crew import Nmap
from nmap.tools.cli import CommandRunner
from nmap.tools.nmap_parser import (
    aggregate_scan_outputs,
    correlate_versions_to_cves,
    extract_cves,
    parse_open_services,
)
from nmap.tools.report import build_markdown_report, write_report

# Simple ANSI colors for console output
GREEN = "\033[92m"
WHITE = "\033[97m"
RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, color: str) -> str:
    if _supports_color():
        return f"{color}{text}{RESET}"
    return text

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


def _default_scan_plan(target: str, quick: bool = True) -> List[Dict[str, str]]:
    """Return an adaptive list of Nmap commands to run.

    - Phase 1: Quick TCP SYN scan of top ports
    - Phase 2: If open ports found, do service/version and default scripts
    - Fallback: If no TCP ports open, try a light UDP top-ports scan
    """
    plan: List[Dict[str, str]] = []
    # Output to stdout using -oN - so we capture clean text
    phase1 = f"nmap -Pn -T4 -sS --top-ports 200 -oN - {target}"
    plan.append({"phase": "tcp_quick", "command": phase1})
    # Placeholders for conditional phases. We'll decide after phase1 parsing.
    plan.append({"phase": "conditional", "command": "__DECIDE__"})
    return plan


def _derive_follow_up_commands(target: str, open_ports: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Create follow-up Nmap command(s) based on discovered open ports."""
    if open_ports:
        # Build a focused service detection scan against found TCP ports
        tcp_ports = sorted({p["port"] for p in open_ports if p.get("protocol") == "tcp"})
        followups: List[Dict[str, str]] = []
        if tcp_ports:
            port_list = ",".join(tcp_ports)
            svc_scan = f"nmap -Pn -sV -sC -O -p {port_list} -oN - {target}"
            followups.append({"phase": "tcp_service_detection", "command": svc_scan})
        return followups
    # No TCP open ports; try a light UDP scan
    udp = f"nmap -Pn -sU --top-ports 50 -oN - {target}"
    return [{"phase": "udp_top", "command": udp}]


def _sanitize_target_for_filename(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


def run() -> None:
    """CLI entry: runs the Nmap workflow and writes a Markdown report."""

    print("CrewAI Nmap Scanner")
    parser = argparse.ArgumentParser(description="CrewAI-based Nmap scanner")
    parser.add_argument("target", help="Target IP or hostname to scan")
    parser.add_argument("task", nargs="?", default="nmap scan target", help="Task description")
    parser.add_argument("--timeout", type=int, default=600, help="Per-command timeout in seconds")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis and use rule-based only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging and progress output")
    args = parser.parse_args()

    # Setup logging
    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger("nmap_cli")

    target = args.target
    task_desc = args.task
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Workspace paths
    project_root = Path(__file__).resolve().parents[2]
    reports_dir = project_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print(_c(f"[nmap-cli] Starting program. Target: {target} | Task: {task_desc}", WHITE))
        print(_c("[nmap-cli] Planning scan strategy...", WHITE))
        if args.no_llm:
            print(_c("[nmap-cli] LLM disabled (--no-llm). Using rule-based analysis.", WHITE))
    logger.info("Planning scan strategy for target: %s", target)
    planned = _default_scan_plan(target)

    runner = CommandRunner(allowed_commands={"nmap"})
    scan_results: List[Dict[str, str]] = []

    # Execute initial quick scan
    phase1 = planned[0]
    if args.verbose:
        print(_c(f"[nmap-cli] Running phase: {phase1['phase']}\n$ {phase1['command']}", WHITE))
    res1 = runner.run(phase1["command"], timeout=args.timeout)
    scan_results.append({"phase": phase1["phase"], **res1})
    if args.verbose:
        print(_c(
            f"[nmap-cli] Phase '{phase1['phase']}' completed: success={res1.get('success')} "
            f"rc={res1.get('returncode')} duration={res1.get('duration'):.2f}s",
            WHITE,
        ))

    # Parse for open ports from the first scan to decide next steps
    open_services_phase1 = parse_open_services(res1.get("stdout", ""))
    if args.verbose:
        print(_c(f"[nmap-cli] Phase '{phase1['phase']}' open services: {len(open_services_phase1)}", WHITE))
    followups = _derive_follow_up_commands(target, open_services_phase1)

    # Replace the conditional placeholder with concrete follow-ups
    planned = [planned[0]] + followups

    for item in followups:
        logger.info("Running follow-up scan phase: %s", item["phase"])
        if args.verbose:
            print(_c(f"[nmap-cli] Running phase: {item['phase']}\n$ {item['command']}", WHITE))
        res = runner.run(item["command"], timeout=args.timeout)
        scan_results.append({"phase": item["phase"], **res})
        if args.verbose:
            print(_c(
                f"[nmap-cli] Phase '{item['phase']}' completed: success={res.get('success')} "
                f"rc={res.get('returncode')} duration={res.get('duration'):.2f}s",
                WHITE,
            ))

    # Aggregate raw outputs and parse findings
    aggregated_raw = aggregate_scan_outputs(scan_results)
    open_services = parse_open_services(aggregated_raw)
    cves_in_output = extract_cves(aggregated_raw)
    matched_cves = correlate_versions_to_cves(open_services)
    if args.verbose:
        print(_c(
            f"[nmap-cli] Parsed services: {len(open_services)} | CVEs in output: {len(cves_in_output)} | "
            f"Inferred CVE matches: {len(matched_cves)}",
            WHITE,
        ))

    # Build analysis text: optionally use the Results Agent (LLM)
    analysis_text = None
    if not args.no_llm:
        try:
            inputs = {
                "target": target,
                "task": task_desc,
                "timestamp": timestamp,
                "open_services": open_services,
                "cves_in_output": cves_in_output,
                "matched_cves": matched_cves,
                "raw_nmap_output": aggregated_raw,
            }
            # Use only the Results Agent task to produce analysis narrative
            analysis = Nmap().crew().kickoff(inputs=inputs)  # type: ignore[call-arg]
            analysis_text = analysis if isinstance(analysis, str) else str(analysis)
            if args.verbose and analysis_text:
                print(_c("[LLM] Results Analyst output:", GREEN))
                print(_c(analysis_text, GREEN))
        except Exception as e:
            logger.warning("LLM analysis failed, falling back to rule-based: %s", e)
            if args.verbose:
                print(_c(f"[nmap-cli] LLM analysis failed: {e}", WHITE))

    # Fallback concise analysis if LLM not available
    if not analysis_text:
        lines = [
            f"Analysis for {target} at {timestamp}",
            "",
            "Key findings:",
        ]
        if open_services:
            for svc in open_services:
                v = svc.get("product_version") or svc.get("version") or ""
                lines.append(
                    f"- {svc['protocol']}/{svc['port']} {svc['service']} {svc.get('product','').strip()} {v}".rstrip()
                )
        else:
            lines.append("- No open services found in performed scans.")

        all_cves = sorted(set(cves_in_output + [c for m in matched_cves for c in m.get("cves", [])]))
        if all_cves:
            lines.append("\nDetected or inferred CVEs:")
            for cve in all_cves:
                lines.append(f"- {cve} (verify applicability)")
        else:
            lines.append("\nNo CVE identifiers were detected in output or matches.")

        analysis_text = "\n".join(lines)

    # Build and write the report
    sanitized = _sanitize_target_for_filename(target)
    filename = f"nmap_report_{sanitized}_{timestamp}.md"
    report_md = build_markdown_report(
        target=target,
        timestamp=timestamp,
        open_services=open_services,
        analysis_text=analysis_text,
        cves_in_output=cves_in_output,
        matched_cves=matched_cves,
        raw_output=aggregated_raw,
        scan_results=scan_results,
    )
    report_path = write_report(reports_dir, filename, report_md)
    print(_c(f"SUCCESS: Report written to {report_path}", WHITE))


def train() -> None:
    # Keep standard crewAI commands available for completeness
    print("Training is not implemented for this workflow.")


def replay() -> None:
    print("Replay is not implemented for this workflow.")


def test() -> None:
    print("Test command is not implemented for this workflow.")

if __name__ == "__main__":
    run()