"""Tests for Security Log Analyzer command-line configuration."""

import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

import main


class TestCommandLineInterface(unittest.TestCase):
    @patch("main.format_security_report", return_value="report")
    @patch("main.detect_suspicious_authentication", return_value=[])
    @patch("main.load_authentication_logs", return_value=[])
    def test_default_window_is_ten_minutes(
        self, load_logs, detect_authentication, format_report
    ) -> None:
        with redirect_stdout(StringIO()):
            main.main([])

        detect_authentication.assert_called_once_with([], window_minutes=10)

    @patch("main.format_security_report", return_value="report")
    @patch("main.detect_suspicious_authentication", return_value=[])
    @patch("main.load_authentication_logs", return_value=[])
    def test_custom_positive_window_is_passed_to_detector(
        self, load_logs, detect_authentication, format_report
    ) -> None:
        with redirect_stdout(StringIO()):
            main.main(["--window-minutes", "15"])

        detect_authentication.assert_called_once_with([], window_minutes=15)

    def test_zero_window_is_rejected(self) -> None:
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            main.main(["--window-minutes", "0"])

        self.assertEqual(error.exception.code, 2)
        self.assertIn("must be greater than zero", stderr.getvalue())

    def test_negative_window_is_rejected(self) -> None:
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            main.main(["--window-minutes", "-1"])

        self.assertEqual(error.exception.code, 2)
        self.assertIn("must be greater than zero", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
