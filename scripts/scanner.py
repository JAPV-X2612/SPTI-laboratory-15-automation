"""Concurrent TCP port scanner with CLI interface."""

import argparse
import asyncio
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# ---------------------------------------------------------------------------
# Core scanning primitives
# ---------------------------------------------------------------------------

def _tcp_connect(host: str, port: int, timeout: float) -> int | None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None


def sequential_scan(host: str, ports: list[int], timeout: float) -> tuple[list[int], float]:
    start = time.perf_counter()
    open_ports = [p for p in ports if _tcp_connect(host, p, timeout) is not None]
    return sorted(open_ports), time.perf_counter() - start


def threaded_scan(host: str, ports: list[int], timeout: float, workers: int) -> tuple[list[int], float]:
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(lambda p: _tcp_connect(host, p, timeout), ports)
    open_ports = sorted(p for p in results if p is not None)
    return open_ports, time.perf_counter() - start


# ---------------------------------------------------------------------------
# Async scanning
# ---------------------------------------------------------------------------

async def _async_tcp_connect(host: str, port: int, timeout: float) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _async_scan(host: str, ports: list[int], timeout: float, rate: int) -> tuple[list[int], float]:
    semaphore = asyncio.Semaphore(rate)
    start = time.perf_counter()

    async def limited(port: int) -> int | None:
        async with semaphore:
            return await _async_tcp_connect(host, port, timeout)

    results = await asyncio.gather(*[limited(p) for p in ports])
    return sorted(p for p in results if p is not None), time.perf_counter() - start


def async_scan(host: str, ports: list[int], timeout: float, rate: int) -> tuple[list[int], float]:
    return asyncio.run(_async_scan(host, ports, timeout, rate))


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def parse_ports(port_spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' into a list of ints."""
    ports = []
    for part in port_spec.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Concurrent TCP port scanner")
    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("--ports", default="1-1024", help="Port range or list (default: 1-1024)")
    parser.add_argument("--rate", type=int, default=200, help="Max concurrent connections (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--output", default="-", help="JSON output file path (default: stdout)")
    parser.add_argument(
        "--mode",
        choices=["sequential", "threaded", "async"],
        default="async",
        help="Scan mode (default: async)",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = build_parser().parse_args()
    ports = parse_ports(args.ports)

    match args.mode:
        case "sequential":
            open_ports, elapsed = sequential_scan(args.target, ports, args.timeout)
        case "threaded":
            open_ports, elapsed = threaded_scan(args.target, ports, args.timeout, args.rate)
        case "async":
            open_ports, elapsed = async_scan(args.target, ports, args.timeout, args.rate)

    result = {
        "target": args.target,
        "mode": args.mode,
        "rate": args.rate,
        "scan_time_seconds": round(elapsed, 3),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": open_ports,
    }

    output = json.dumps(result, indent=2)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
