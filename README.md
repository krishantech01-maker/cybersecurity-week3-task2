# SIEM Systems Monitoring & Alert Correlation Engine

## Project Overview
This repository features a simulated Security Information and Event Management (SIEM) engine. It demonstrates how modern platforms ingest raw infrastructure log events, parse fields, match signatures against defined logical rulesets, and generate operational security alerts.

## Directory Structure
- `config/`: Contains `siem_rules.json` specifying malicious string thresholds.
- `src/`: Core Python ingestion script simulating threat detection.
- `logs/`: Holds target activity data records and system alerts output text.
