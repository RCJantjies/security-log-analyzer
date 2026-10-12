"""Tests for authentication log parsing."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.log_parser import load_authentication_logs, parse_timestamp


class TestLogParser(unittest.TestCase):
    def test_valid_timestamp(self) -> None:
        parsed = parse_timestamp("2026-10-05T01:15:03Z")
        self.assertEqual(parsed.year, 2026)
        self.assertIsNotNone(parsed.tzinfo)

    def test_invalid_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_timestamp("not-a-timestamp")

    def test_z_timestamp_is_parsed_as_utc(self) -> None:
        parsed = parse_timestamp("2026-10-05T01:15:03Z")

        self.assertEqual(parsed, datetime(2026, 10, 5, 1, 15, 3, tzinfo=timezone.utc))
        self.assertIs(parsed.tzinfo, timezone.utc)

    def test_offset_timestamp_is_normalized_to_utc(self) -> None:
        parsed = parse_timestamp("2026-10-05T03:15:03+02:00")

        self.assertEqual(parsed, datetime(2026, 10, 5, 1, 15, 3, tzinfo=timezone.utc))
        self.assertIs(parsed.tzinfo, timezone.utc)

    def test_equivalent_offset_timestamps_represent_same_instant(self) -> None:
        utc_timestamp = parse_timestamp("2026-10-05T01:15:03Z")
        offset_timestamp = parse_timestamp("2026-10-04T21:15:03-04:00")

        self.assertEqual(utc_timestamp, offset_timestamp)

    def test_timestamp_without_timezone_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_timestamp("2026-10-05T01:15:03")

    def test_valid_csv_record(self) -> None:
        content = (
            "timestamp,user,source_ip,status\n"
            "2026-10-05T01:15:03Z,admin,192.0.2.10,FAILED\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.csv"
            path.write_text(content, encoding="utf-8")
            records = load_authentication_logs(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "FAILED")

    def test_unknown_status_rejected(self) -> None:
        content = (
            "timestamp,user,source_ip,status\n"
            "2026-10-05T01:15:03Z,admin,192.0.2.10,UNKNOWN\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.csv"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_authentication_logs(path)

    def test_empty_user_rejected(self) -> None:
        content = (
            "timestamp,user,source_ip,status\n"
            "2026-10-05T01:15:03Z,,192.0.2.10,FAILED\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.csv"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_authentication_logs(path)


if __name__ == "__main__":
    unittest.main()
