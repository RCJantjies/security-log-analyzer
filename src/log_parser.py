"""Parse and validate authentication log records."""

import csv
from datetime import datetime
from pathlib import Path


VALID_STATUSES = {"SUCCESS", "FAILED"}


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp from an authentication record."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"Invalid timestamp: {value}") from exc


def load_authentication_logs(file_path: str | Path) -> list[dict]:
    """Load and validate authentication records from a CSV file."""
    records: list[dict] = []

    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        required_fields = {"timestamp", "user", "source_ip", "status"}

        if not reader.fieldnames or not required_fields.issubset(reader.fieldnames):
            raise ValueError("CSV file is missing one or more required columns.")

        for row_number, row in enumerate(reader, start=2):
            user = row["user"].strip()
            source_ip = row["source_ip"].strip()
            status = row["status"].strip().upper()

            if not user:
                raise ValueError(f"Empty user at CSV row {row_number}.")
            if not source_ip:
                raise ValueError(f"Empty source IP at CSV row {row_number}.")
            if status not in VALID_STATUSES:
                raise ValueError(
                    f"Unknown authentication status at CSV row {row_number}: {status}"
                )

            records.append(
                {
                    "timestamp": parse_timestamp(row["timestamp"].strip()),
                    "user": user,
                    "source_ip": source_ip,
                    "status": status,
                }
            )

    return records
