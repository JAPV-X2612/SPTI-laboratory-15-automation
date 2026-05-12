"""Parse nmap XML output and enrich hosts with SSH host key information."""

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_path: str) -> list[dict]:
    root = ET.parse(xml_path).getroot()
    hosts = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip = addr_el.get("addr", "")
        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        open_ports = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            open_ports.append({
                "port": int(port.get("portid", 0)),
                "service": service.get("name", "") if service is not None else "",
                "version": _build_version_string(service),
            })

        if open_ports:
            hosts.append({"ip": ip, "hostname": hostname, "open_ports": open_ports})

    return hosts


def _build_version_string(service_el) -> str:
    if service_el is None:
        return ""
    product = service_el.get("product", "")
    version = service_el.get("version", "")
    return f"{product} {version}".strip()


# ---------------------------------------------------------------------------
# SSH enrichment
# ---------------------------------------------------------------------------

def enrich_ssh_key(host: dict) -> dict:
    """Add SSH host key type if port 22 is open."""
    ssh_ports = [p for p in host["open_ports"] if p["port"] == 22]
    if not ssh_ports:
        return host

    ip = host["ip"]
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", "3", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        key_type = _parse_ssh_keyscan(result.stdout)
    except subprocess.TimeoutExpired:
        key_type = "timeout"
    except OSError:
        key_type = "error"

    return {**host, "ssh_host_key_type": key_type}


def _parse_ssh_keyscan(output: str) -> str:
    for line in output.splitlines():
        parts = line.split()
        # Format: <ip> <key-type> <key-data>
        if len(parts) >= 2 and not line.startswith("#"):
            return parts[1]
    return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse nmap XML and enrich with SSH key info")
    parser.add_argument("--input", default="scan.xml", help="nmap XML file (default: scan.xml)")
    parser.add_argument("--output", default="hosts.json", help="JSON output file (default: hosts.json)")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if not Path(args.input).exists():
        print(f"[!] Input file not found: {args.input}")
        raise SystemExit(1)

    hosts = parse_nmap_xml(args.input)
    enriched = [enrich_ssh_key(h) for h in hosts]

    Path(args.output).write_text(json.dumps(enriched, indent=2))
    print(f"[+] {len(enriched)} hosts written to {args.output}")

    for h in enriched:
        key = h.get("ssh_host_key_type", "N/A")
        ports = [p["port"] for p in h["open_ports"]]
        print(f"    {h['ip']} — ports: {ports} — ssh key: {key}")


if __name__ == "__main__":
    main()
