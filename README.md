# Security Log Analyzer & Suspicious Activity Detector

## Project Overview

This is a beginner-level cybersecurity project developed using Python. It reads sample security logs and identifies suspicious login activity.

## Features

* Reads and parses security log files.
* Counts different security events.
* Detects repeated failed login attempts.
* Detects possible scanning events when they are recorded in the logs.
* Generates alerts with timestamps, source IP addresses, event types, and severity.
* Creates a security report with defensive recommendations.

## Technologies Used

* Python
* Visual Studio Code
* Text-based log files

## How to Run

1. Install Python.
2. Keep `log_analyzer.py` and `security_log.txt` in the same folder.
3. Open the folder in Visual Studio Code.
4. Run the following command in the terminal:

`python log_analyzer.py`

5. Check the generated `security_report.txt` file.

## Learning Outcomes

This project helped me understand log parsing, basic detection rules, security alerts, and defensive security concepts.

