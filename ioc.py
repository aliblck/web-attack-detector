import json


def build_ioc_report(parsed_logs, high_request_alerts, brute_force_alerts):
    suspicious_ips = set()
    suspicious_urls = set()
    suspicious_status_codes = set()

    # High request frequency alarmından IP çıkar
    for alert in high_request_alerts:
        suspicious_ips.add(alert["ip"])

    # Brute force alarmından IP çıkar
    for alert in brute_force_alerts:
        suspicious_ips.add(alert["ip"])

    # Şüpheli URL ve status code'ları loglardan çıkar
    for log in parsed_logs:
        if log["ip"] in suspicious_ips:
            url = log["url"]
            status = log["status"]

            if status in [401, 403, 404]:
                suspicious_urls.add(url)
                suspicious_status_codes.add(status)

            # Hassas endpoint'leri de IOC olarak ekle
            suspicious_keywords = [
                "admin",
                "login",
                "backup",
                "secret",
                "phpmyadmin"
            ]

            if any(keyword in url.lower() for keyword in suspicious_keywords):
                suspicious_urls.add(url)

    report = {
        "suspicious_ips": sorted(suspicious_ips),
        "suspicious_urls": sorted(suspicious_urls),
        "status_codes": sorted(suspicious_status_codes),
        "alerts": {
            "high_request_frequency": high_request_alerts,
            "brute_force": brute_force_alerts
        }
    }

    return report


def save_ioc_report(report, filename="ioc_report.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)