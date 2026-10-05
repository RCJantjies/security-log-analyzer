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

    def test_negative_failure_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            severity_for_failures(-1)


if __name__ == "__main__":
    unittest.main()
