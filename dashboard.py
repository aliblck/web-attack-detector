from flask import Flask, render_template

from parser import parse_log_line
from analyzer import analyze_logs
from detector import (
    detect_high_request_frequency,
    detect_web_brute_force,
    detect_web_enumeration,
    detect_many_404,
)

app = Flask(__name__)

LOG_FILE = "sample_logs/access.log"


def load_logs():
    parsed_logs = []

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            parsed = parse_log_line(line)

            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs


@app.route("/")
def dashboard():
    parsed_logs = load_logs()

    results = analyze_logs(parsed_logs)

    high_request_alerts = detect_high_request_frequency(parsed_logs)
    brute_force_alerts = detect_web_brute_force(parsed_logs)
    enumeration_alerts = detect_web_enumeration(parsed_logs)
    many_404_alerts = detect_many_404(parsed_logs)

    all_alerts = (
        high_request_alerts
        + brute_force_alerts
        + enumeration_alerts
        + many_404_alerts
    )

    suspicious_ips = set()

    for alert in all_alerts:
        suspicious_ips.add(alert["ip"])

    top_ips = results["ip_counts"].most_common(5)

    return render_template(
        "dashboard.html",
        total_requests=results["total_requests"],
        unique_ips=results["unique_ip_count"],
        suspicious_ip_count=len(suspicious_ips),
        alert_count=len(all_alerts),
        top_ips=top_ips,
        status_counts=results["status_counts"],
        alerts=all_alerts,
    )


if __name__ == "__main__":
    app.run(debug=True)