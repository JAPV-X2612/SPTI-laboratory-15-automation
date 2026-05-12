# Security Log Analysis Report

## 1. SSH Brute-Force Detection

### Suspicious IPs

| IP Address | Failed Attempts |
|---|---|
| 185.220.101.5 | 266 |
| 45.33.32.156 | 181 |
| 10.0.0.1 | 21 |
| 10.0.0.2 | 17 |
| 192.168.1.50 | 15 |

### Targeted Usernames

| Username | Attempts |
|---|---|
| root | 149 |
| daniel | 125 |
| admin | 123 |
| ubuntu | 103 |

**Fail-to-success ratio:** 25.0:1

## 2. Web Access Log Analysis

### Attack Pattern Matches

| IP | Path | Status |
|---|---|---|
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 192.168.1.50 | `/admin/../../../etc/passwd` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 200 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 185.220.101.5 | `/search?q=<script>alert(1)</script>` | 403 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 500 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 500 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 185.220.101.5 | `/search?q=<script>alert(1)</script>` | 200 |
| 185.220.101.5 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 45.33.32.156 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 66.249.66.1 | `/admin/../../../etc/passwd` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 185.220.101.5 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 45.33.32.156 | `/search?q=<script>alert(1)</script>` | 500 |
| 10.0.0.1 | `/admin/../../../etc/passwd` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 500 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 200 |
| 10.0.0.1 | `/search?q=<script>alert(1)</script>` | 403 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 10.0.0.1 | `/cgi-bin/test.cgi?cmd=id` | 403 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |
| 45.33.32.156 | `/admin/../../../etc/passwd` | 500 |
| 66.249.66.1 | `/search?q=<script>alert(1)</script>` | 200 |

### Top 5 IPs

| IP | Requests |
|---|---|
| 10.0.0.1 | 1753 |
| 66.249.66.1 | 588 |
| 45.33.32.156 | 317 |
| 185.220.101.5 | 287 |
| 192.168.1.50 | 192 |

### HTTP Status Distribution

| Status | Count |
|---|---|
| 200 | 3049 |
| 403 | 45 |
| 500 | 43 |

### Traffic Anomalies (3σ Rule)

- **[ANOMALY]** 11/May/2026-03h: 939 requests (z=4.7σ, threshold=3.0σ)