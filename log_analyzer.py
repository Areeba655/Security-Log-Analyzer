from collections import defaultdict
from datetime import datetime

LOG_FILE = "security_log.txt"
REPORT_FILE = "security_report.txt"
FAILED_LOGIN_LIMIT = 3

failed_attempts = defaultdict(list)
alerts = []
total_events = 0

print("======================================")
print("   SECURITY LOG ANALYZER")
print("======================================")

try:
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            if len(parts) != 3:
                print("Skipping invalid log entry:", line)
                continue

            timestamp, source_ip, event_type = parts
            total_events += 1

            if event_type == "LOGIN_FAILED":
                failed_attempts[source_ip].append(timestamp)

    for source_ip, timestamps in failed_attempts.items():
        if len(timestamps) >= FAILED_LOGIN_LIMIT:
            alerts.append({
                "timestamp": timestamps[-1],
                "source_ip": source_ip,
                "event_type": "Repeated Failed Logins",
                "severity": "HIGH",
                "count": len(timestamps)
            })

    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("SECURITY LOG ANALYSIS REPORT\n")
        report.write("=" * 40 + "\n")
        report.write(f"Report generated: {datetime.now()}\n")
        report.write(f"Total events analyzed: {total_events}\n")
        report.write(f"Failed login events: {sum(len(v) for v in failed_attempts.values())}\n\n")

        report.write("SECURITY ALERTS\n")
        report.write("-" * 40 + "\n")

        if alerts:
            for alert in alerts:
                message = (
                    f"Timestamp: {alert['timestamp']}\n"
                    f"Source IP: {alert['source_ip']}\n"
                    f"Event: {alert['event_type']}\n"
                    f"Failed attempts: {alert['count']}\n"
                    f"Severity: {alert['severity']}\n\n"
                )
                report.write(message)
        else:
            report.write("No suspicious login patterns detected.\n\n")

        report.write("RECOMMENDED DEFENSIVE ACTIONS\n")
        report.write("-" * 40 + "\n")
        report.write("1. Review repeated failed login attempts.\n")
        report.write("2. Check whether the source IP is authorized.\n")
        report.write("3. Enable multi-factor authentication where possible.\n")
        report.write("4. Use login rate limiting and account lockout policies.\n")
        report.write("5. Continue monitoring security logs.\n")

    print("\nAnalysis completed successfully!")
    print("Total events analyzed:", total_events)
    print("Alerts detected:", len(alerts))

    for alert in alerts:
        print(
            alert["severity"], "|",
            alert["source_ip"], "|",
            alert["event_type"],
            "| Failed attempts:", alert["count"]
        )

    print("\nReport saved to:", REPORT_FILE)

except FileNotFoundError:
    print("ERROR: security_log.txt was not found.")
    print("Keep both files in the same folder.")

input("\nPress Enter to exit...")
