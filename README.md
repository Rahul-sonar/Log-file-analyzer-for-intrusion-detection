# Log File Analyzer for Intrusion Detection

## Overview

This project is a Python-based SOC (Security Operations Center) log analysis tool that analyzes Linux authentication logs and detects suspicious activities such as brute-force attacks and invalid user enumeration attempts.

The tool helps security analysts identify potential threats by processing log files, extracting suspicious IP addresses, assigning risk levels, generating incident reports, and visualizing attack patterns.

---

## Features

- Parse Linux authentication logs
- Detect failed login attempts
- Extract suspicious IP addresses
- Detect brute-force attacks
- Detect invalid user enumeration attempts
- Assign risk levels (LOW, MEDIUM, HIGH)
- Generate incident reports
- Export results to CSV
- Create attack visualization graphs
- Generate threat summary dashboard

---

## Technologies Used

- Python 3
- Pandas
- Matplotlib
- Regular Expressions (Regex)

---

## Project Structure

```
LogFileAnalyzer/
│
├── analyzer.py
├── README.md
│
├── logs/
│   └── auth.log
│
├── reports/
│   ├── incident_report.txt
│   ├── ip_report.csv
│   └── attack_graph.png
│
└── screenshots/
```

---

## Installation

Install required packages:

```bash
pip3 install pandas matplotlib
```

---

## Run the Project

```bash
python3 analyzer.py
```

---

## Sample Output

```
SOC ALERT REPORT

IP: 192.168.1.10
Attempts: 10
Risk: HIGH

IP: 192.168.1.20
Attempts: 6
Risk: MEDIUM

IP: 192.168.1.30
Attempts: 2
Risk: LOW
```

---

## Threat Detection Capabilities

- SSH Brute Force Detection
- Failed Authentication Monitoring
- Invalid User Detection
- Risk Classification
- Security Reporting

---

## Author

Rahul Sonar
