# log-triage-tool

**Turn a 10,000-line `auth.log` into a one-page answer to "did anything bad happen?"**

`logtriage.py` parses SSH authentication logs, runs five high-signal detections, and produces a triage report an analyst can act on immediately — each finding ranked by severity and backed by the exact log lines that prove it. Pure Python standard library: no dependencies, no network calls, runs anywhere Python 3 does.

Built by [Breachnode](https://github.com/Breachnode) — an independent cybersecurity threat researcher (hobbyist, self-directed) sharing practical security tools and knowledge.

## The detections

| # | Detection | Severity | What it catches |
|---|-----------|----------|-----------------|
| 1 | `breach_success` | **Critical** | A successful login from an IP that was just brute-forcing — the attacker stopped failing because they got in |
| 2 | `known_bad_ip` | Critical / High | Any auth event from an IOC-blocklisted IP (critical if a login succeeded) |
| 3 | `brute_force` | High | ≥5 failed logins from one IP inside 10 minutes (sliding window) |
| 4 | `rapid_ip_switching` | Medium | One account logging in from multiple IPs inside 30 minutes |
| 5 | `off_hours_success` | Low | Successful logins between 00:00 and 05:00 |

Every threshold and window is a command-line flag — tuning detection to an environment is the job, so nothing is hard-coded.

## Quick start

```bash
git clone https://github.com/Breachnode/log-triage-tool.git
cd log-triage-tool

# Run it against the bundled sample log (planted attacks included):
python3 logtriage.py sample_logs/auth.log --iocs iocs.txt --year 2026

# Your own log:
python3 logtriage.py /var/log/auth.log --iocs your-blocklist.txt --out report.md

# Machine-readable output for piping into other tooling:
python3 logtriage.py auth.log --format json --out report.json

# Run the tests:
python3 -m unittest discover tests
```

## Sample output

Against the bundled sample log (28 auth events buried in cron/sudo noise), the tool fires 9 findings. The top of the report:

```
| # | Severity | Type               | Summary                                                                 |
|---|----------|--------------------|-------------------------------------------------------------------------|
| 1 | CRITICAL | breach_success     | Successful login as 'deploy' from 198.51.100.99 after 6 failed attempts |
| 2 | CRITICAL | known_bad_ip       | 3 auth events from blocklisted 192.0.2.44 — including a SUCCESSFUL login |
| 3 | HIGH     | brute_force        | 8 failed logins from 203.0.113.66 within 10 min (root, admin, oracle)   |
| 4 | HIGH     | brute_force        | 6 failed logins from 198.51.100.99 within 10 min (deploy)               |
| 5 | HIGH     | known_bad_ip       | 1 auth event from blocklisted 45.148.10.7                               |
| 6 | MEDIUM   | rapid_ip_switching | 'jsmith' logged in from 2 IPs within 30 min                              |
| 7-9 | LOW    | off_hours_success  | Successful logins at 01:15, 02:47, 04:30                                |
```

Each finding's evidence section quotes the raw log lines, so a reviewer never has to take the tool's word for anything.

## Design notes

- **Detectors are independent functions** over one parsed event stream — adding a detection never touches the parser or the other detectors.
- **Brute force uses a two-pointer sliding window**, not fixed clock buckets, so an attack straddling a bucket boundary still fires.
- **Severity is analyst-first, not count-first:** a single success after failures outranks a hundred failures that never got in.
- **Evidence over assertion:** every finding carries its source lines into the report.

## Roadmap

- Sigma rule export for the same detections
- JSON / CEF input in addition to syslog format
- Optional GeoIP enrichment for the switching detection
- Splunk HEC / Elastic output for the report

## License

MIT — see [LICENSE](LICENSE).
