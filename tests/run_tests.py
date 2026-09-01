import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from parser import parse_log_line

from detector import (
    detect_high_request_frequency,
    detect_web_brute_force,
    detect_web_enumeration,
    detect_many_404,
)

TEST_FILES = {
    "Normal traffic": "sample_logs/normal.log",
    "Enumeration": "sample_logs/enumeration.log",
    "Many 404": "sample_logs/many_404.log",
    "Brute force": "sample_logs/bruteforce.log",
    "High request": "sample_logs/high_request.log",
}


def load_logs(filename):
    logs = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)

            if parsed:
                logs.append(parsed)

    return logs


for test_name, filename in TEST_FILES.items():
    logs = load_logs(filename)

    high_request_alerts = detect_high_request_frequency(logs)
    brute_force_alerts = detect_web_brute_force(logs)
    enumeration_alerts = detect_web_enumeration(logs)
    many_404_alerts = detect_many_404(logs)

    count_404 = sum(
        1 for log in logs
        if log["status"] == 404
    )

    print("=" * 60)
    print(test_name)
    print("=" * 60)

    print("Requests           :", len(logs))
    print("404 Count          :", count_404)
    print("Enumeration Alert  :", bool(enumeration_alerts))
    print("Many 404 Alert     :", bool(many_404_alerts))
    print("Brute Force Alert  :", bool(brute_force_alerts))
    print("High Request Alert :", bool(high_request_alerts))