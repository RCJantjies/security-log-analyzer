"""Format security findings as a terminal exception report."""

from typing import Any


def format_security_report(findings: list[dict[str, Any]]) -> str:
    """Return a readable security exception report."""
    lines = [
        "Security Log Analyzer",
        "-" * 82,
        f"{'User':<15}{'Source IP':<18}{'Failures':>10}{'Risk':>8}{'Severity':>12}",
        "-" * 82,
    ]

    if not findings:
        lines.append("No suspicious authentication patterns detected.")
        return "\n".join(lines)

    for finding in findings:
        lines.append(
            f"{finding['user']:<15}"
            f"{finding['source_ip']:<18}"
            f"{finding['failed_attempts']:>10}"
            f"{finding['risk_score']:>8}"
            f"{finding['severity']:>12}"
        )
        lines.append(f"  Reason: {finding['reason']}")

    return "\n".join(lines)
