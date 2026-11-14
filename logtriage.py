#!/usr/bin/env python3
"""
logtriage.py — SSH authentication log triage tool.

Reads a Linux auth.log (sshd) file, extracts authentication events, runs a
small set of high-signal detections, and writes a triage report in Markdown
(or JSON) that an analyst can act on: what fired, how severe it is, and the
exact log lines that prove it.

Detections
----------
1. brute_force        — >= N failed logins from one source IP inside a window.
2. breach_success     — a successful login from an IP that was brute-forcing
                        shortly before (possible account compromise).
3. known_bad_ip       — any auth event from an IP on an IOC blocklist.
4. rapid_ip_switching — one account with successful logins from several
                        distinct IPs inside a short window.
5. off_hours_success  — a successful login in the small hours (00:00-05:00
                        by default).

Pure Python standard library. No dependencies, no network calls.

Usage
-----
    python3 logtriage.py /var/log/auth.log
    python3 logtriage.py sample_logs/auth.log --iocs iocs.txt
    python3 logtriage.py auth.log --format json --out report.json
    python3 logtriage.py auth.log --brute-threshold 8 --brute-window 5

Author: Barry Harris (Breachnode)
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

# Matches both:
#   Nov 11 03:12:44 host sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
#   Nov 11 03:14:01 host sshd[1235]: Accepted password for jsmith from 198.51.100.23 port 51235 ssh2
AUTH_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?P<result>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


@dataclass
class AuthEvent:
    ts: datetime
    result: str          # "Failed" or "Accepted"
    user: str
    ip: str
    raw: str             # original log line, kept as evidence

    @property
    def success(self) -> bool:
        return self.result == "Accepted"


def parse_log(path, year):
    """Yield AuthEvent objects from an sshd auth.log file.

    Lines that are not sshd password events are skipped silently — real
    auth.logs are mostly noise (cron, sudo, session opens), and triage
    starts by throwing the noise away.
    """
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = AUTH_RE.match(line.strip())
            if not m:
                continue
            ts = datetime(
                year, MONTHS[m["mon"]], int(m["day"]),
                *map(int, m["time"].split(":")),
            )
            events.append(AuthEvent(
                ts=ts, result=m["result"], user=m["user"],
                ip=m["ip"], raw=line.strip(),
            ))
    events.sort(key=lambda e: e.ts)
    return events


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    kind: str
    severity: str
    summary: str
    evidence: list = field(default_factory=list)   # raw log lines

    def sort_key(self):
        return SEVERITY_ORDER[self.severity]


# --------------------------------------------------------------------------
# Detectors — each takes the parsed events and returns Finding objects.
# --------------------------------------------------------------------------

def detect_brute_force(events, threshold, window_minutes):
    """Sliding window: >= threshold failures from one IP inside the window."""
    findings = []
    failures_by_ip = defaultdict(list)
    for e in events:
        if not e.success:
            failures_by_ip[e.ip].append(e)

    window = timedelta(minutes=window_minutes)
    for ip, fails in failures_by_ip.items():
        # Two-pointer sliding window over the sorted failure list.
        start = 0
        worst = []
        for end in range(len(fails)):
            while fails[end].ts - fails[start].ts > window:
                start += 1
            if end - start + 1 > len(worst):
                worst = fails[start:end + 1]
        if len(worst) >= threshold:
            users = sorted({e.user for e in worst})
            findings.append(Finding(
                kind="brute_force", severity="high",
                summary=(f"{len(worst)} failed logins from {ip} within "
                         f"{window_minutes} min (targets: {', '.join(users)})"),
                evidence=[e.raw for e in worst[:5]],
            ))
    return findings


def detect_breach_success(events, threshold, lookback_minutes):
    """A success from an IP that racked up >= threshold failures just before.

    This is the detection that turns a brute-force attempt into a possible
    compromise: the attacker stopped failing because they got in.
    """
    findings = []
    lookback = timedelta(minutes=lookback_minutes)
    failures_by_ip = defaultdict(list)
    for e in events:
        if not e.success:
            failures_by_ip[e.ip].append(e)

    for e in events:
        if not e.success:
            continue
        prior = [f for f in failures_by_ip.get(e.ip, [])
                 if e.ts - lookback <= f.ts < e.ts]
        if len(prior) >= threshold:
            findings.append(Finding(
                kind="breach_success", severity="critical",
                summary=(f"Successful login as '{e.user}' from {e.ip} at "
                         f"{e.ts:%H:%M:%S} after {len(prior)} failed attempts "
                         f"in the prior {lookback_minutes} min — treat as "
                         f"possible account compromise"),
                evidence=[p.raw for p in prior[:3]] + [e.raw],
            ))
    return findings


def detect_known_bad_ip(events, ioc_ips):
    """Any event — success or failure — from a blocklisted IP."""
    findings = []
    hits = [e for e in events if e.ip in ioc_ips]
    by_ip = defaultdict(list)
    for e in hits:
        by_ip[e.ip].append(e)
    for ip, evts in by_ip.items():
        got_in = any(e.success for e in evts)
        findings.append(Finding(
            kind="known_bad_ip",
            severity="critical" if got_in else "high",
            summary=(f"{len(evts)} auth event(s) from blocklisted IP {ip}"
                     + (" — including a SUCCESSFUL login" if got_in else "")),
            evidence=[e.raw for e in evts[:5]],
        ))
    return findings


def detect_rapid_ip_switching(events, window_minutes, min_ips):
    """One account, successful logins from >= min_ips distinct IPs quickly."""
    findings = []
    window = timedelta(minutes=window_minutes)
    successes_by_user = defaultdict(list)
    for e in events:
        if e.success:
            successes_by_user[e.user].append(e)

    for user, evts in successes_by_user.items():
        for i, first in enumerate(evts):
            cluster = [e for e in evts[i:] if e.ts - first.ts <= window]
            ips = {e.ip for e in cluster}
            if len(ips) >= min_ips:
                findings.append(Finding(
                    kind="rapid_ip_switching", severity="medium",
                    summary=(f"Account '{user}' logged in from {len(ips)} "
                             f"different IPs within {window_minutes} min "
                             f"({', '.join(sorted(ips))})"),
                    evidence=[e.raw for e in cluster[:5]],
                ))
                break  # one finding per user is enough for triage
    return findings


def detect_off_hours_success(events, start_hour, end_hour):
    """Successful logins between start_hour and end_hour (local log time)."""
    findings = []
    for e in events:
        if e.success and start_hour <= e.ts.hour < end_hour:
            findings.append(Finding(
                kind="off_hours_success", severity="low",
                summary=(f"Successful login as '{e.user}' from {e.ip} at "
                         f"{e.ts:%H:%M:%S} (off-hours window "
                         f"{start_hour:02d}:00-{end_hour:02d}:00)"),
                evidence=[e.raw],
            ))
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_report(events, findings, source_name):
    findings = sorted(findings, key=lambda f: f.sort_key())
    lines = [
        "# Auth Log Triage Report",
        "",
        f"- Source: `{source_name}`",
        f"- Events parsed: {len(events)} "
        f"({sum(1 for e in events if e.success)} accepted, "
        f"{sum(1 for e in events if not e.success)} failed)",
        f"- Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No detections fired. Nothing to escalate.")
        return "\n".join(lines) + "\n"

    lines.append("| # | Severity | Type | Summary |")
    lines.append("|---|----------|------|---------|")
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f.severity.upper()} | {f.kind} | {f.summary} |")
    lines.append("")
    lines.append("## Evidence")
    for i, f in enumerate(findings, 1):
        lines.append(f"\n### {i}. [{f.severity.upper()}] {f.kind}\n")
        lines.append(f.summary + "\n")
        for raw in f.evidence:
            lines.append(f"    {raw}")
    return "\n".join(lines) + "\n"


def load_iocs(path):
    ips = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line.split()[0])
    return ips


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Triage an sshd auth.log: find the attacks in the noise.")
    p.add_argument("logfile", help="Path to auth.log")
    p.add_argument("--iocs", help="Optional IOC file: one bad IP per line")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="Year for log timestamps (auth.log omits it)")
    p.add_argument("--brute-threshold", type=int, default=5,
                   help="Failures from one IP that count as brute force")
    p.add_argument("--brute-window", type=int, default=10,
                   help="Brute-force window, minutes")
    p.add_argument("--breach-lookback", type=int, default=60,
                   help="How far back (minutes) a success looks for failures")
    p.add_argument("--switch-window", type=int, default=30,
                   help="Rapid IP-switching window, minutes")
    p.add_argument("--off-hours", type=int, nargs=2, default=(0, 5),
                   metavar=("START", "END"),
                   help="Off-hours window for successful logins")
    p.add_argument("--format", choices=("markdown", "json"),
                   default="markdown")
    p.add_argument("--out", help="Write the report here instead of stdout")
    args = p.parse_args(argv)

    try:
        events = parse_log(args.logfile, args.year)
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return 2

    findings = []
    findings += detect_brute_force(events, args.brute_threshold,
                                   args.brute_window)
    findings += detect_breach_success(events, args.brute_threshold,
                                      args.breach_lookback)
    if args.iocs:
        findings += detect_known_bad_ip(events, load_iocs(args.iocs))
    findings += detect_rapid_ip_switching(events, args.switch_window, 2)
    findings += detect_off_hours_success(events, *args.off_hours)
    findings.sort(key=lambda f: f.sort_key())

    if args.format == "json":
        report = json.dumps({
            "source": args.logfile,
            "events_parsed": len(events),
            "findings": [asdict(f) for f in findings],
        }, indent=2) + "\n"
    else:
        report = build_report(events, findings, args.logfile)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Wrote {args.out}: {len(findings)} finding(s) "
              f"from {len(events)} events.")
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
