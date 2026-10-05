# Security Log Analyzer

A modular Python tool for analyzing authentication logs, detecting suspicious login patterns, assigning explainable risk scores, and generating security exception reports.

## Security Problem

Authentication logs can contain indicators of suspicious access behaviour, but manually reviewing individual events is inefficient and makes patterns easy to miss. This project demonstrates a lightweight detection pipeline that converts structured authentication events into prioritized security findings.

The application is a portfolio and learning project. It is **not a production intrusion detection system (IDS), SIEM, or substitute for professional security monitoring controls**.

## Features

- Loads authentication events from CSV
- Validates required fields and ISO 8601 timestamps
- Validates authentication states
- Aggregates events by user and source IP
- Detects repeated failed authentication attempts
- Detects successful logins following repeated failures
- Assigns explainable risk scores and severity levels
- Produces a terminal security exception report
- Includes automated tests for parsing and detection behaviour

## Architecture

```text
Synthetic authentication logs
            |
            v
        Log parser
            |
            v
    Input validation
            |
            v
     Detection engine
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
│   └── test_detector.py
├── main.py
├── README.md
├── .gitignore
└── LICENSE
```

## Detection Rules

Version 0.1 uses deterministic, explainable rules:

| Pattern | Risk Score | Severity |
| --- | ---: | --- |
| Fewer than 3 failed attempts | 0 | NONE |
| 3–4 failed attempts | 25 | LOW |
| 5–7 failed attempts | 50 | MEDIUM |
| 8 or more failed attempts | 70 | HIGH |
| Repeated failures followed by success | At least 80 | HIGH |

These thresholds are **illustrative portfolio rules and are not presented as industry-standard security thresholds**.

## Synthetic Dataset and Data Ethics

All authentication events in this repository are synthetic. Example source addresses use documentation address ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.

No employer, client, user, production-system, credential, or real security-event data is included.

## Requirements

- Python 3.9 or later
- No third-party packages

## Usage

From the repository directory, run:

```bash
python main.py
```

Example:

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

Run:

```bash
python -m unittest discover -s tests
```

The test suite covers timestamp parsing, malformed timestamps, CSV ingestion, invalid authentication states, missing users, detection thresholds, severity assignment, risk scoring, and successful authentication following failures.

Local validation on 5 October 2026 confirmed:

```text
Ran 11 tests
OK
```

## Design Decisions

The project uses separate modules for parsing, detection, and reporting rather than placing the entire application in one file. This separates responsibilities and makes the detection logic easier to test and extend.

Version 0.1 deliberately uses deterministic rules rather than machine learning. This provides an explainable baseline that can later be compared with statistical or ML-based anomaly detection.

## Limitations

- Processes a static CSV dataset rather than live security events
- Correlates by user and source IP but does not yet use configurable time windows
- Uses illustrative fixed thresholds
- Does not enrich IP addresses or integrate threat intelligence
- Does not persist findings in a database
- Does not provide alerting or a graphical dashboard
- Does not perform machine-learning-based anomaly detection

## Future Development

Potential engineering milestones include:

- Time-window-based event correlation
- Configurable detection policies
- Statistical anomaly detection
- Security-event visualization
- Structured JSON reporting
- Threat-intelligence enrichment using safe external services
- ML-based anomaly classification
- AI-assisted incident summarization

Future capabilities will be introduced only when they provide a meaningful engineering increment.

## Project Status

**Version 0.1 — portfolio release**

The command-line application has been functionally validated locally and all 11 automated tests pass.

## License

Released under the MIT License.
