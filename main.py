"""Run the Security Log Analyzer against the synthetic dataset."""

import argparse
from pathlib import Path

from src.detector import detect_suspicious_authentication
from src.log_parser import load_authentication_logs
from src.reporter import format_security_report


def positive_integer(value: str) -> int:
    """Return a positive integer or raise an argparse validation error."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc

    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options for the analyzer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--window-minutes",
        type=positive_integer,
        default=10,
        help="authentication detection window in minutes (default: 10)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Load authentication events and print detected security exceptions."""
    args = parse_args(argv)
    data_path = Path(__file__).parent / "data" / "synthetic_auth_log.csv"
    records = load_authentication_logs(data_path)
    findings = detect_suspicious_authentication(
        records, window_minutes=args.window_minutes
    )
    print(format_security_report(findings))


if __name__ == "__main__":
    main()
