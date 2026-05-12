"""
Multi-stage reconnaissance tool for domains and IP addresses.
Produces structured JSON results, a Markdown report, and a timestamped audit log.
"""

import argparse
import json
import logging
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Audit logger factory
# ---------------------------------------------------------------------------

def _setup_audit_logger(output_dir: Path) -> logging.Logger:
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(output_dir / "audit.log")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


# ---------------------------------------------------------------------------
# Shell command runner
# ---------------------------------------------------------------------------

def _run(cmd: list[str], audit: logging.Logger, timeout: int = 30) -> str:
    audit.info(f"RUN: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        audit.info(f"OK (exit={result.returncode})")
        return result.stdout
    except subprocess.TimeoutExpired:
        audit.warning(f"TIMEOUT: {' '.join(cmd)}")
        return ""
    except OSError as e:
        audit.error(f"ERROR: {e}")
        return ""


# ---------------------------------------------------------------------------
# Domain mode probes
# ---------------------------------------------------------------------------

def _probe_whois_domain(target: str, audit: logging.Logger) -> dict:
    raw = _run(["whois", target], audit)
    fields = {
        "registrar": r"Registrar:\s*(.+)",
        "registration_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"Registry Expiry Date:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
    }
    return {k: _extract(pattern, raw) for k, pattern in fields.items()}


def _probe_dns(target: str, audit: logging.Logger) -> dict:
    record_types = ["A", "MX", "NS", "TXT"]
    records = {}
    for rtype in record_types:
        out = _run(["dig", "+short", rtype, target], audit)
        records[rtype] = [line.strip() for line in out.splitlines() if line.strip()]
    return records


def _probe_http_headers(target: str, audit: logging.Logger) -> dict:
    raw = _run(["curl", "-sI", "--max-time", "10", f"http://{target}"], audit)
    headers_of_interest = [
        "server", "x-powered-by", "content-security-policy",
        "strict-transport-security", "x-frame-options",
    ]
    result = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            k = key.strip().lower()
            if k in headers_of_interest:
                result[k] = value.strip()
    return result


# ---------------------------------------------------------------------------
# IP mode probes
# ---------------------------------------------------------------------------

def _probe_nmap(target: str, audit: logging.Logger) -> list[dict]:
    xml_path = "/tmp/recon_nmap.xml"
    _run(["sudo", "nmap", "--top-ports", "100", "-sV", "--open", "-oX", xml_path, target], audit, timeout=120)

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        audit.error("Failed to parse nmap XML output")
        return []

    ports = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        ports.append({
            "port": int(port.get("portid", 0)),
            "service": service.get("name", "") if service is not None else "",
            "version": f"{service.get('product', '')} {service.get('version', '')}".strip() if service is not None else "",
        })
    return ports


def _probe_reverse_dns(target: str, audit: logging.Logger) -> list[str]:
    out = _run(["dig", "+short", "-x", target], audit)
    return [line.strip() for line in out.splitlines() if line.strip()]


def _probe_whois_ip(target: str, audit: logging.Logger) -> dict:
    raw = _run(["whois", target], audit)
    return {
        "organization": _extract(r"(?:OrgName|org-name|owner):\s*(.+)", raw),
        "country": _extract(r"(?:Country|country):\s*(.+)", raw),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract(pattern: str, text: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _generate_markdown(results: dict, mode: str, output_dir: Path) -> None:
    target = results.get("target", "")
    lines = [f"# Reconnaissance Report: {target}\n", f"**Mode:** {mode}  \n**Generated:** {datetime.now().isoformat()}\n"]

    if mode == "domain":
        whois = results.get("whois", {})
        lines += ["## WHOIS\n", "| Field | Value |", "|---|---|"]
        for k, v in whois.items():
            lines.append(f"| {k} | {v or 'N/A'} |")

        dns = results.get("dns", {})
        lines += ["\n## DNS Records\n"]
        for rtype, records in dns.items():
            lines.append(f"**{rtype}:** {', '.join(records) if records else 'none'}")

        headers = results.get("http_headers", {})
        lines += ["\n## HTTP Headers\n", "| Header | Value |", "|---|---|"]
        for k, v in headers.items():
            lines.append(f"| {k} | {v} |")

        security_headers = {"content-security-policy", "strict-transport-security", "x-frame-options"}
        missing = security_headers - set(headers.keys())
        if missing:
            lines += ["\n### Missing Security Headers\n"]
            for h in missing:
                lines.append(f"- `{h}` — **not present**")

    else:
        lines += ["## Open Ports\n", "| Port | Service | Version |", "|---|---|---|"]
        for p in results.get("open_ports", []):
            lines.append(f"| {p['port']} | {p['service']} | {p['version'] or 'N/A'} |")

        rdns = results.get("reverse_dns", [])
        lines += [f"\n## Reverse DNS\n{', '.join(rdns) if rdns else 'No PTR records found'}\n"]

        whois = results.get("whois", {})
        lines += ["\n## IP Ownership\n", f"- **Organization:** {whois.get('organization', 'N/A')}", f"- **Country:** {whois.get('country', 'N/A')}"]

    (output_dir / "report.md").write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Multi-stage reconnaissance tool")
    parser.add_argument("target", help="Domain name or IP address")
    parser.add_argument("--mode", choices=["domain", "ip"], help="Scan mode (auto-detected if omitted)")
    parser.add_argument("--output", default=None, help="Output directory (default: ./recon_<target>_<timestamp>/)")
    parser.add_argument("--verbose", action="store_true", help="Print progress to stderr")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    mode = args.mode or ("ip" if _is_ip(args.target) else "domain")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace(".", "_")
    output_dir = Path(args.output) if args.output else Path(f"recon_{safe_target}_{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    audit = _setup_audit_logger(output_dir)
    audit.info(f"START recon — target={args.target} mode={mode}")

    def log(msg: str) -> None:
        if args.verbose:
            print(f"[*] {msg}", file=sys.stderr)
        audit.info(msg)

    results: dict = {"target": args.target, "mode": mode, "timestamp": timestamp}

    if mode == "domain":
        log("Running WHOIS...")
        results["whois"] = _probe_whois_domain(args.target, audit)

        log("Querying DNS records...")
        results["dns"] = _probe_dns(args.target, audit)

        log("Fetching HTTP headers...")
        results["http_headers"] = _probe_http_headers(args.target, audit)

    else:
        log("Running nmap scan...")
        results["open_ports"] = _probe_nmap(args.target, audit)

        log("Running reverse DNS lookup...")
        results["reverse_dns"] = _probe_reverse_dns(args.target, audit)

        log("Running WHOIS on IP...")
        results["whois"] = _probe_whois_ip(args.target, audit)

    (output_dir / "results.json").write_text(json.dumps(results, indent=2))
    log("Generating Markdown report...")
    _generate_markdown(results, mode, output_dir)

    audit.info(f"END recon — outputs in {output_dir}/")
    print(f"[+] Done. Outputs saved to: {output_dir}/")


if __name__ == "__main__":
    main()
