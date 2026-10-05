"""Tests for authentication log parsing."""

import tempfile
import unittest
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
