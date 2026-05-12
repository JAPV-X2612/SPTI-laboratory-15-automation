"""SSH authentication log analyzer for brute-force detection."""

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

_FAIL_PATTERN = re.compile(r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
_SUCCESS_PATTERN = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze(log_path: str, threshold: int = 10) -> dict:
    fail_by_ip: dict[str, int] = defaultdict(int)
    targeted_users: Counter = Counter()
    total_failures = 0
    total_successes = 0

    for line in Path(log_path).open():
        if m := _FAIL_PATTERN.search(line):
            user, ip = m.group(1), m.group(2)
            fail_by_ip[ip] += 1
            targeted_users[user] += 1
            total_failures += 1
        elif _SUCCESS_PATTERN.search(line):
            total_successes += 1

    brute_force_ips = sorted(
        [(ip, count) for ip, count in fail_by_ip.items() if count >= threshold],
        key=lambda x: x[1],
        reverse=True,
    )

    ratio = total_failures / total_successes if total_successes else float("inf")

    return {
        "brute_force_ips": brute_force_ips,
        "targeted_users": targeted_users.most_common(),
        "total_failures": total_failures,
        "total_successes": total_successes,
        "fail_to_success_ratio": round(ratio, 2),
    }


def print_report(result: dict) -> None:
    print("\n=== Brute-force IPs (>= threshold) ===")
    for ip, count in result["brute_force_ips"]:
        print(f"  {ip:<20} {count} attempts")

    print("\n=== Targeted Usernames ===")
    for user, count in result["targeted_users"]:
        print(f"  {user:<15} {count} attempts")

    print(f"\n=== Login Statistics ===")
    print(f"  Failures  : {result['total_failures']}")
    print(f"  Successes : {result['total_successes']}")
    print(f"  Fail ratio: {result['fail_to_success_ratio']}:1")


def main() -> None:
    log_path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    if not Path(log_path).exists():
        print(f"[!] File not found: {log_path}")
        raise SystemExit(1)

    result = analyze(log_path, threshold)
    print_report(result)


if __name__ == "__main__":
    main()
