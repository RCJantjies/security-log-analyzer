"""Detect suspicious authentication patterns using explainable rules."""

from collections import defaultdict
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


def detect_suspicious_authentication(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate authentication events and return security findings."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for record in records:
        grouped[(record["user"], record["source_ip"])].append(record)

    findings: list[dict[str, Any]] = []

    for (user, source_ip), events in grouped.items():
        events = sorted(events, key=lambda event: event["timestamp"])
        failed_attempts = sum(event["status"] == "FAILED" for event in events)

        base_score, severity = severity_for_failures(failed_attempts)
        if base_score == 0:
            continue

        failure_seen = False
        success_after_failure = False
        for event in events:
            if event["status"] == "FAILED":
                failure_seen = True
            elif event["status"] == "SUCCESS" and failure_seen:
                success_after_failure = True

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
