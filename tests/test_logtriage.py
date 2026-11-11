"""Unit tests for logtriage detectors. Run: python3 -m unittest discover tests"""
import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logtriage import (AuthEvent, parse_log, detect_brute_force,
                       detect_breach_success, detect_known_bad_ip,
                       detect_rapid_ip_switching, detect_off_hours_success)

Y = 2026


def ev(minute, result, user, ip, hour=10):
    return AuthEvent(ts=datetime(Y, 11, 11, hour, minute, 0), result=result,
                     user=user, ip=ip, raw=f"line {user} {ip} {minute}")


class TestParser(unittest.TestCase):
    def test_sample_log_parses_and_skips_noise(self):
        sample = Path(__file__).resolve().parent.parent / "sample_logs" / "auth.log"
        events = parse_log(str(sample), Y)
        # 28 sshd password events in the sample; CRON/sudo/close lines skipped.
        self.assertEqual(len(events), 28)
        self.assertTrue(all(isinstance(e, AuthEvent) for e in events))
        self.assertEqual(events[0].ts, datetime(Y, 11, 11, 1, 15, 43))


class TestBruteForce(unittest.TestCase):
    def test_fires_at_threshold(self):
        events = [ev(m, "Failed", "root", "1.2.3.4") for m in range(0, 12, 2)]
        findings = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "brute_force")

    def test_quiet_below_threshold(self):
        events = [ev(m, "Failed", "root", "1.2.3.4") for m in range(4)]
        self.assertEqual(detect_brute_force(events, 5, 10), [])

    def test_spread_out_failures_do_not_fire(self):
        events = [ev(m, "Failed", "root", "1.2.3.4", hour=h)
                  for h, m in [(8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0)]]
        self.assertEqual(detect_brute_force(events, 5, 10), [])


class TestBreachSuccess(unittest.TestCase):
    def test_success_after_failures_is_critical(self):
        events = [ev(m, "Failed", "deploy", "5.6.7.8") for m in range(5)]
        events.append(ev(6, "Accepted", "deploy", "5.6.7.8"))
        findings = detect_breach_success(events, threshold=5, lookback_minutes=60)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_clean_success_does_not_fire(self):
        events = [ev(0, "Failed", "deploy", "5.6.7.8"),
                  ev(6, "Accepted", "deploy", "9.9.9.9")]
        self.assertEqual(detect_breach_success(events, 5, 60), [])


class TestKnownBadIp(unittest.TestCase):
    def test_ioc_success_is_critical(self):
        events = [ev(0, "Accepted", "backup", "192.0.2.44")]
        findings = detect_known_bad_ip(events, {"192.0.2.44"})
        self.assertEqual(findings[0].severity, "critical")


class TestRapidIpSwitching(unittest.TestCase):
    def test_two_ips_in_window_fire(self):
        events = [ev(5, "Accepted", "barry", "10.0.0.1"),
                  ev(17, "Accepted", "barry", "10.0.0.2")]
        findings = detect_rapid_ip_switching(events, window_minutes=30, min_ips=2)
        self.assertEqual(len(findings), 1)

    def test_same_ip_does_not_fire(self):
        events = [ev(5, "Accepted", "barry", "10.0.0.1"),
                  ev(17, "Accepted", "barry", "10.0.0.1")]
        self.assertEqual(detect_rapid_ip_switching(events, 30, 2), [])


class TestOffHours(unittest.TestCase):
    def test_2am_login_fires(self):
        events = [ev(47, "Accepted", "backup", "10.0.0.9", hour=2)]
        self.assertEqual(len(detect_off_hours_success(events, 0, 5)), 1)

    def test_business_hours_quiet(self):
        events = [ev(47, "Accepted", "backup", "10.0.0.9", hour=14)]
        self.assertEqual(detect_off_hours_success(events, 0, 5), [])


if __name__ == "__main__":
    unittest.main()
