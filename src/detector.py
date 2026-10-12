"""Detect suspicious authentication patterns using explainable rules."""

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any


def severity_for_failures(failed_attempts: int) -> tuple[int, str]:
    """Return a simple risk score and severity for repeated failures.

    Thresholds are illustrative portfolio rules, not industry standards.
    """
    if failed_attempts < 0:
        raise ValueError("Failed attempts cannot be negative.")
    if failed_attempts >= 8:
        return 70, "HIGH"
    if failed_attempts >= 5:
        return 50, "MEDIUM"
    if failed_attempts >= 3:
        return 25, "LOW"
    return 0, "NONE"


def detect_suspicious_authentication(
    records: list[dict[str, Any]], window_minutes: int = 10
) -> list[dict[str, Any]]:
    """Return authentication findings found within a sliding time window."""
    if window_minutes <= 0:
        raise ValueError("Window minutes must be greater than zero.")

    window = timedelta(minutes=window_minutes)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for record in records:
        grouped[(record["user"], record["source_ip"])].append(record)

    findings: list[dict[str, Any]] = []

    for (user, source_ip), events in grouped.items():
        events = sorted(events, key=lambda event: event["timestamp"])
        failure_times = deque()
        failed_attempts = 0
        success_after_failure = False

        for event in events:
            timestamp = event["timestamp"]
            while failure_times and timestamp - failure_times[0] > window:
                failure_times.popleft()

            if event["status"] == "FAILED":
                failure_times.append(timestamp)
                failed_attempts = max(failed_attempts, len(failure_times))
            elif event["status"] == "SUCCESS" and len(failure_times) >= 3:
                success_after_failure = True

        base_score, severity = severity_for_failures(failed_attempts)
        if base_score == 0:
            continue

        risk_score = base_score
        reasons = [f"{failed_attempts} failed authentication attempts"]

        if success_after_failure:
            risk_score = max(risk_score, 80)
            severity = "HIGH"
            reasons.append("successful login observed after failed attempts")

        findings.append(
            {
                "user": user,
                "source_ip": source_ip,
                "failed_attempts": failed_attempts,
                "success_after_failure": success_after_failure,
                "risk_score": risk_score,
                "severity": severity,
                "reason": "; ".join(reasons),
            }
        )

    return sorted(findings, key=lambda finding: finding["risk_score"], reverse=True)
