# Cloud Log Analyzer with Intrusion Detection

A backend system built using FastAPI and SQLAlchemy that analyzes server log files and detects suspicious activities.

## Features

- Detects failed login attempts
- Identifies suspicious IP addresses
- Risk classification (LOW, MEDIUM, HIGH, CRITICAL)
- Severity scoring system
- Attack type detection
- Stores analysis reports in SQLite database

## Tech Stack

- FastAPI
- Python
- SQLAlchemy
- SQLite
- Git & GitHub

## Endpoints

### POST /upload/
Upload a log file for analysis.

### GET /reports/
Retrieve previous analysis reports.
