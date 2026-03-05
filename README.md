# 🛡 Cloud Threat Intelligence System

A cloud-based **Intrusion Detection and Threat Intelligence platform** that analyzes server logs to detect suspicious activities, malicious IP addresses, and potential cyber attacks.

The system processes log files, calculates threat severity, and visualizes analytics through a real-time security dashboard.

---

# 🚀 Features

- Log-based intrusion detection
- Threat severity scoring engine
- Detection of known malicious IP addresses
- Real-time analytics dashboard
- Attack distribution visualization
- Top attacker IP tracking
- Cloud deployment on AWS EC2
- Secure login system for dashboard access

---

# 🧠 How It Works

1. User uploads a server log file.
2. Backend analyzes the logs for:
   - failed login attempts
   - suspicious IP activity
   - known malicious IP addresses
3. A threat severity score is calculated.
4. Data is stored in a database.
5. Dashboard visualizes threat intelligence using charts.

---

# ⚙️ Tech Stack

Backend
- Python
- FastAPI

Frontend
- HTML
- CSS
- JavaScript
- Chart.js

Database
- SQLite

Cloud
- AWS EC2
- Nginx
- Gunicorn

---

# 📊 Dashboard Analytics

The dashboard provides:

- Total logs analyzed
- High/Critical threat alerts
- Average severity score
- Most common attack type
- Risk distribution chart
- Severity trend graph
- Recent log reports
- Top attacking IP addresses

---

# 🛠 Project Architecture
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
