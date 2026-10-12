"""Tests for suspicious authentication detection."""

import unittest
from datetime import datetime, timezone

from src.detector import detect_suspicious_authentication, severity_for_failures


def event(user: str, source_ip: str, status: str, minute: int) -> dict:
    return {
        "timestamp": datetime(2026, 10, 5, 1, minute, tzinfo=timezone.utc),
        "user": user,
        "source_ip": source_ip,
        "status": status,
    }


class TestDetector(unittest.TestCase):
    def test_two_failures_do_not_alert(self) -> None:
        records = [event("user", "192.0.2.1", "FAILED", i) for i in range(2)]
        self.assertEqual(detect_suspicious_authentication(records), [])

    def test_three_failures_are_low_severity(self) -> None:
        records = [event("user", "192.0.2.1", "FAILED", i) for i in range(3)]
        finding = detect_suspicious_authentication(records)[0]
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["risk_score"], 25)

    def test_five_failures_are_medium_severity(self) -> None:
        self.assertEqual(severity_for_failures(5), (50, "MEDIUM"))

    def test_eight_failures_are_high_severity(self) -> None:
        self.assertEqual(severity_for_failures(8), (70, "HIGH"))

    def test_success_after_failures_escalates_risk(self) -> None:
        records = [event("admin", "192.0.2.10", "FAILED", i) for i in range(3)]
        records.append(event("admin", "192.0.2.10", "SUCCESS", 4))
        finding = detect_suspicious_authentication(records)[0]
        self.assertTrue(finding["success_after_failure"])
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["risk_score"], 80)

    def test_three_failures_within_ten_minutes_are_low_severity(self) -> None:
        records = [
            event("user", "192.0.2.1", "FAILED", minute)
            for minute in (0, 4, 9)
        ]

        finding = detect_suspicious_authentication(records)[0]

        self.assertEqual(finding["failed_attempts"], 3)
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["risk_score"], 25)

    def test_three_failures_outside_ten_minutes_do_not_alert(self) -> None:
        records = [
            event("user", "192.0.2.1", "FAILED", minute)
            for minute in (0, 6, 12)
        ]

        self.assertEqual(detect_suspicious_authentication(records), [])

    def test_success_after_three_failures_within_window_escalates(self) -> None:
        records = [
            event("admin", "192.0.2.10", "FAILED", minute)
            for minute in (0, 4, 8)
        ]
        records.append(event("admin", "192.0.2.10", "SUCCESS", 9))

        finding = detect_suspicious_authentication(records)[0]

        self.assertTrue(finding["success_after_failure"])
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["risk_score"], 80)

    def test_success_before_failures_does_not_escalate(self) -> None:
        records = [event("admin", "192.0.2.10", "SUCCESS", 0)]
        records.extend(
            event("admin", "192.0.2.10", "FAILED", minute)
            for minute in (1, 2, 3)
        )

        finding = detect_suspicious_authentication(records)[0]

        self.assertFalse(finding["success_after_failure"])
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["risk_score"], 25)

    def test_out_of_order_events_are_processed_chronologically(self) -> None:
        records = [
            event("admin", "192.0.2.10", "SUCCESS", 9),
            event("admin", "192.0.2.10", "FAILED", 8),
            event("admin", "192.0.2.10", "FAILED", 0),
            event("admin", "192.0.2.10", "FAILED", 4),
        ]

        finding = detect_suspicious_authentication(records)[0]

        self.assertEqual(finding["failed_attempts"], 3)
        self.assertTrue(finding["success_after_failure"])
        self.assertEqual(finding["risk_score"], 80)

    def test_failures_exactly_ten_minutes_apart_share_inclusive_window(self) -> None:
        records = [
            event("user", "192.0.2.1", "FAILED", minute)
            for minute in (0, 5, 10)
        ]

        finding = detect_suspicious_authentication(records)[0]

        self.assertEqual(finding["failed_attempts"], 3)
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["risk_score"], 25)

    def test_zero_window_minutes_rejected(self) -> None:
        with self.assertRaises(ValueError):
            detect_suspicious_authentication([], window_minutes=0)

    def test_negative_window_minutes_rejected(self) -> None:
        with self.assertRaises(ValueError):
            detect_suspicious_authentication([], window_minutes=-1)

    def test_negative_failure_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            severity_for_failures(-1)


if __name__ == "__main__":
    unittest.main()
