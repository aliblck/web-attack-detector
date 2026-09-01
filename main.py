from parser import parse_log_line 
from analyzer import analyze_logs
from detector import detect_high_request_frequency, detect_web_brute_force
from ioc import build_ioc_report, save_ioc_report

LOG_FILE = "sample_logs/access.log"

parsed_logs = []

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        parsed = parse_log_line(line)

        if parsed:
            parsed_logs.append(parsed)

results = analyze_logs(parsed_logs)

print("=" * 60)
print("WEB ATTACK LOG ANALYZER")
print("=" * 60)

print("Total Requests      :", results["total_requests"])
print("Unique IP Addresses :", results["unique_ip_count"])
print("GET Requests        :", results["get_requests"])
print("POST Requests       :", results["post_requests"])
print("404 Requests        :", results["404_requests"])
print("403 Requests        :", results["403_requests"])
print("5xx Requests        :", results["5xx_requests"])

print()
print("HTTP STATUS CODE ANALYSIS")
print("-" * 60)

important_status_codes = [200, 301, 302, 400, 401, 403, 404, 500]

for code in important_status_codes:
    count = results["status_counts"].get(code, 0)
    print(f"{code} Count : {count}")

print()
print("IP ADDRESS ANALYSIS")
print("-" * 60)

for ip, count in results["ip_counts"].most_common():
    print(f"{ip:<20} {count}")

print()
print("=" * 60)
print("WEB ATTACK DETECTOR")
print("=" * 60)

alerts = detect_high_request_frequency(parsed_logs)

if not alerts:
    print("Suspicious IPs : None")
else:
    print("Suspicious IPs:")

    for alert in alerts:
        print("-" * 60)
        print("IP       :", alert["ip"])
        print("Requests :", alert["requests"])
        print("Window   :", f'{alert["window_seconds"]} seconds')
        print("Status   :", alert["status"])
        print("Reason   :", alert["reason"])

        print()
print("=" * 60)
print("WEB BRUTE FORCE DETECTOR")
print("=" * 60)

brute_force_alerts = detect_web_brute_force(parsed_logs)

if not brute_force_alerts:
    print("Brute Force Alerts : None")
else:
    for alert in brute_force_alerts:
        print("ALERT Possible Web Brute Force")
        print("-" * 60)
        print("Source IP       :", alert["ip"])
        print("Failed Attempts :", alert["failed_attempts"])
        print("Window          :", f'{alert["window_seconds"]} seconds')
        print("Risk            :", alert["risk"])
        print("Reason          :", alert["reason"])


print()
print("=" * 60)
print("IOC REPORT")
print("=" * 60)

ioc_report = build_ioc_report(
    parsed_logs,
    alerts,
    brute_force_alerts
)

save_ioc_report(ioc_report)

print("Suspicious IPs:")
for ip in ioc_report["suspicious_ips"]:
    print(" -", ip)

print("Suspicious URLs:")
for url in ioc_report["suspicious_urls"]:
    print(" -", url)

print("Status Codes:")
for status in ioc_report["status_codes"]:
    print(" -", status)

print()
print("IOC report saved to: ioc_report.json")