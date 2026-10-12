# Security Log Analyzer

**Version 0.2 — portfolio release**

A modular Python tool for analyzing authentication logs, correlating suspicious login activity within configurable time windows, assigning explainable risk scores, and generating prioritized security exception reports.

## Security Problem

Authentication logs can contain indicators of suspicious access behaviour, but manually reviewing individual events is inefficient and makes patterns easy to miss. This project demonstrates a lightweight detection pipeline that converts structured authentication events into prioritized security findings.

Version 0.2 correlates authentication events within a sliding time window instead of counting failures across the entire dataset. This provides a more meaningful view of concentrated login activity while retaining deterministic, explainable behavior.

The application is a portfolio and learning project. It is **not a production intrusion detection system (IDS), SIEM, or substitute for professional security monitoring controls**.

## Features

- Loads authentication events from CSV
- Validates required fields, authentication states, and ISO 8601 timestamps
- Requires timezone-aware timestamps and normalizes them to UTC
- Groups events by user and source IP
- Processes each group chronologically, including out-of-order input
- Correlates failures through a configurable, deque-based sliding window
- Detects successful logins following qualifying repeated failures
- Assigns explainable risk scores and severity levels
- Produces a prioritized terminal security exception report
- Includes automated tests for parsing, detection, and CLI behaviour

## Architecture

```text
CSV authentication events
            |
            v
    Parsing and validation
            |
            v
 Timezone normalization to UTC
            |
            v
 Group by user and source IP
            |
            v
  Chronological processing
            |
            v
Deque-based sliding-window correlation
            |
            v
        Risk scoring
            |
            v
    Exception reporting
```

## Repository Structure

```text
security-log-analyzer/
├── data/
│   └── synthetic_auth_log.csv
├── src/
│   ├── __init__.py
│   ├── log_parser.py
│   ├── detector.py
│   └── reporter.py
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   └── test_main.py
├── main.py
├── README.md
├── .gitignore
└── LICENSE
```

## Detection Rules

Version 0.2 uses deterministic, explainable rules within the configured detection window:

| Pattern | Risk Score | Severity |
| --- | ---: | --- |
| Fewer than 3 failed attempts | 0 | No alert |
| 3–4 failed attempts | 25 | LOW |
| 5–7 failed attempts | 50 | MEDIUM |
| 8 or more failed attempts | 70 | HIGH |
| At least 3 in-window failures followed by success | At least 80 | HIGH |

These thresholds are **illustrative portfolio rules and are not industry-standard security thresholds**. Production detection policies should be based on an organization's environment, threat model, telemetry, and operational requirements.

In each finding, `failed_attempts` is the maximum number of failures observed within a qualifying time window for that user and source-IP pair. It is not the lifetime total across the dataset.

## Technical Design

The detector sorts each user/source-IP group chronologically and uses a `deque` to retain only failure timestamps that remain inside the configured window. As time advances, expired timestamps are removed from the front and new failures are appended to the back. This supports efficient sliding-window updates without repeatedly scanning all earlier events.

For `n` input events, grouping and sorting contribute approximately **O(n log n)** time in the general case. After sorting, sliding-window processing is linear because each failure timestamp is appended and removed at most once. Overall auxiliary storage is approximately **O(n)** for grouped events and active window state. These are high-level bounds; actual behavior depends on how events are distributed across groups.

## Synthetic Dataset and Data Ethics

All authentication events in this repository are synthetic. Example source addresses use documentation address ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.

No real credentials, employer or client logs, production security data, or real user security events are included.

## Requirements

- Python 3.10 or later
- No third-party packages

## Usage

From the repository directory, run the analyzer with the default 10-minute detection window:

```bash
python main.py
```

To select a different positive window length, use `--window-minutes`. For example, this command uses a 15-minute window against the same synthetic dataset:

```bash
python main.py --window-minutes 15
```

Zero and negative window values are rejected by the command-line interface.

Example report:

```text
Security Log Analyzer
----------------------------------------------------------------------------------
User           Source IP           Failures    Risk    Severity
----------------------------------------------------------------------------------
admin          192.0.2.10                 3      80        HIGH
  Reason: 3 failed authentication attempts; successful login observed after failed attempts
operator       198.51.100.25              5      50      MEDIUM
  Reason: 5 failed authentication attempts
```

## Testing

Run the complete automated test suite with:

```bash
python -m unittest discover -s tests
```

The suite covers:

- Parsing and validation
- UTC timestamp normalization and equivalent timezone offsets
- Sliding-window temporal boundaries
- Out-of-order authentication events
- Risk thresholds and severity assignment
- Success-after-failure escalation
- CLI configuration and validation

The current Version 0.2 implementation has been validated with **27 automated tests passing**.

Both supported invocation patterns were also manually validated against the synthetic dataset:

```bash
python main.py
python main.py --window-minutes 15
```

## Design Decisions

The project uses separate modules for parsing, detection, and reporting rather than placing the entire application in one file. This separation of responsibilities makes the pipeline easier to test, reason about, and extend.

Version 0.2 deliberately uses deterministic rules rather than machine learning. This provides an explainable baseline that can later be compared with statistical or ML-based anomaly detection.

## Limitations

- Processes a static CSV dataset rather than live security events
- Uses illustrative fixed risk thresholds
- Does not persist findings in a database
- Does not provide alerting or a graphical dashboard
- Does not perform statistical or machine-learning-based anomaly detection
- Does not currently enrich events with external threat intelligence
- Is not a production IDS or SIEM

## Future Development

Potential future engineering milestones include:

- Configurable policy files
- Structured JSON output
- Security-event visualization
- Statistical anomaly detection
- Safe threat-intelligence enrichment
- ML-based anomaly classification
- AI-assisted incident summarization

Future capabilities will be introduced only when they provide a meaningful engineering increment.

## Project Status

**Version 0.2 — portfolio release**

The command-line application supports configurable time-window correlation, normalized UTC timestamps, explainable scoring, and validated CLI input. All 27 automated tests pass.

## License

Released under the MIT License.
