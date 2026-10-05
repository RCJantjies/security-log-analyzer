"""Run the Security Log Analyzer against the synthetic dataset."""

from pathlib import Path

from src.detector import detect_suspicious_authentication
from src.log_parser import load_authentication_logs
from src.reporter import format_security_report


def main() -> None:
    """Load authentication events and print detected security exceptions."""
    data_path = Path(__file__).parent / "data" / "synthetic_auth_log.csv"
    records = load_authentication_logs(data_path)
    findings = detect_suspicious_authentication(records)
    print(format_security_report(findings))


if __name__ == "__main__":
    main()
