"""Web access log analyzer with attack pattern detection and anomaly detection."""

import re
import statistics
from collections import Counter
from pathlib import Path

_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<day>\d{2}/\w+/\d{4}):(?P<hour>\d{2}):\d{2}:\d{2}[^\]]*\] '
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \S+'
)

_ATTACK_PATTERN = re.compile(
    r"(union.*select|insert.*into|drop\s+table"      # SQLi
    r"|\.\./|\.\.\\"                                 # Path traversal
    r"|<script"                                        # XSS
    r"|cmd=|exec=|shell=|/cgi-bin/.*\?)",             # Command injection
    re.IGNORECASE,
)


def analyze(log_path: str) -> dict:
    ip_counter: Counter = Counter()
    status_counter: Counter = Counter()
    hourly_counter: Counter = Counter()
    suspicious: list[dict] = []

    for line in Path(log_path).open():
        m = _LOG_PATTERN.match(line)
        if not m:
            continue

        ip = m.group("ip")
        path = m.group("path")
        status = m.group("status")
        hour_key = f"{m.group('day')}-{m.group('hour')}h"

        ip_counter[ip] += 1
        status_counter[status] += 1
        hourly_counter[hour_key] += 1

        if _ATTACK_PATTERN.search(path):
            suspicious.append({"ip": ip, "path": path, "status": status})

    anomalies = _detect_anomalies(hourly_counter)

    return {
        "suspicious_requests": suspicious,
        "top_ips": ip_counter.most_common(5),
        "status_distribution": dict(status_counter),
        "anomalous_hours": anomalies,
    }


def _detect_anomalies(hourly: Counter, sigma_threshold: float = 3.0) -> list[str]:
    counts = list(hourly.values())
    if len(counts) < 2:
        return []

    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts)

    if stdev == 0:
        return []

    threshold = mean + sigma_threshold * stdev
    anomalies = []

    for hour, count in hourly.items():
        if count > threshold:
            z = (count - mean) / stdev
            anomalies.append(f"{hour}: {count} requests (z={z:.1f}σ, threshold={sigma_threshold}σ)")

    return sorted(anomalies)


def print_report(result: dict) -> None:
    print("\n=== Attack Pattern Matches ===")
    for r in result["suspicious_requests"]:
        print(f"  [{r['status']}] {r['ip']} -> {r['path']}")

    print(f"\n=== Top 5 IPs by Request Volume ===")
    for ip, count in result["top_ips"]:
        print(f"  {ip:<20} {count} requests")

    print(f"\n=== HTTP Status Distribution ===")
    for status, count in sorted(result["status_distribution"].items()):
        print(f"  {status}: {count}")

    print(f"\n=== Anomalous Hours (3σ rule) ===")
    if result["anomalous_hours"]:
        for entry in result["anomalous_hours"]:
            print(f"  [ANOMALY] {entry}")
    else:
        print("  No anomalies detected.")


def generate_markdown_report(auth_result: dict, web_result: dict, output_path: str = "report.md") -> None:
    lines = [
        "# Security Log Analysis Report\n",
        "## 1. SSH Brute-Force Detection\n",
        "### Suspicious IPs\n",
        "| IP Address | Failed Attempts |",
        "|---|---|",
    ]
    for ip, count in auth_result["brute_force_ips"]:
        lines.append(f"| {ip} | {count} |")

    lines += [
        "\n### Targeted Usernames\n",
        "| Username | Attempts |",
        "|---|---|",
    ]
    for user, count in auth_result["targeted_users"]:
        lines.append(f"| {user} | {count} |")

    lines += [
        f"\n**Fail-to-success ratio:** {auth_result['fail_to_success_ratio']}:1\n",
        "## 2. Web Access Log Analysis\n",
        "### Attack Pattern Matches\n",
        "| IP | Path | Status |",
        "|---|---|---|",
    ]
    for r in web_result["suspicious_requests"]:
        lines.append(f"| {r['ip']} | `{r['path']}` | {r['status']} |")

    lines += [
        "\n### Top 5 IPs\n",
        "| IP | Requests |",
        "|---|---|",
    ]
    for ip, count in web_result["top_ips"]:
        lines.append(f"| {ip} | {count} |")

    lines += ["\n### HTTP Status Distribution\n", "| Status | Count |", "|---|---|"]
    for status, count in sorted(web_result["status_distribution"].items()):
        lines.append(f"| {status} | {count} |")

    lines += ["\n### Traffic Anomalies (3σ Rule)\n"]
    for entry in web_result["anomalous_hours"]:
        lines.append(f"- **[ANOMALY]** {entry}")

    Path(output_path).write_text("\n".join(lines))
    print(f"\n[+] Combined report saved to {output_path}")


if __name__ == "__main__":
    # Import here to avoid circular dependency when used as module
    import sys
    from auth_analysis import analyze as auth_analyze

    auth_log = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    web_log = sys.argv[2] if len(sys.argv) > 2 else "access.log"

    auth_result = auth_analyze(auth_log)
    web_result = analyze(web_log)

    print_report(web_result)
    generate_markdown_report(auth_result, web_result, "report.md")
