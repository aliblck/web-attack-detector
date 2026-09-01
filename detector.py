from collections import defaultdict
from datetime import datetime, timedelta


REQUEST_THRESHOLD = 20
TIME_WINDOW_SECONDS = 10


def parse_timestamp(timestamp):
    return datetime.strptime(
        timestamp,
        "%d/%b/%Y:%H:%M:%S %z"
    )


def detect_high_request_frequency(parsed_logs):
    ip_times = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        # localhost kayıtlarını şimdilik hariç tutuyoruz
        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_times[ip].append(timestamp)

    for ip, times in ip_times.items():
        times.sort()

        left = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
                > timedelta(seconds=TIME_WINDOW_SECONDS)
            ):
                left += 1

            request_count = right - left + 1

            if request_count >= REQUEST_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "requests": request_count,
                    "window_seconds": TIME_WINDOW_SECONDS,
                    "status": "WARNING",
                    "reason": "High request frequency"
                })

                # Aynı olay için tekrar tekrar alarm basmamak için
                break

    return alerts

LOGIN_THRESHOLD = 5
LOGIN_TIME_WINDOW_SECONDS = 60

LOGIN_KEYWORDS = [
    "login",
    "signin",
    "auth"
]


def is_login_request(log):
    url = log["url"].lower()

    return (
        log["method"] == "POST"
        and any(keyword in url for keyword in LOGIN_KEYWORDS)
    )


def detect_web_brute_force(parsed_logs):
    login_attempts = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        if not is_login_request(log):
            continue

        # Basit modelde 401 ve 403 başarısız login kabul ediliyor
        if log["status"] not in [401, 403]:
            continue

        timestamp = parse_timestamp(log["timestamp"])
        login_attempts[ip].append(timestamp)

    for ip, times in login_attempts.items():
        times.sort()
        left = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
                > timedelta(seconds=LOGIN_TIME_WINDOW_SECONDS)
            ):
                left += 1

            failed_count = right - left + 1

            if failed_count >= LOGIN_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "failed_attempts": failed_count,
                    "window_seconds": LOGIN_TIME_WINDOW_SECONDS,
                    "risk": "HIGH",
                    "reason": "Possible Web Brute Force"
                })

                break

    return alerts

ENUMERATION_URL_THRESHOLD = 8
ENUMERATION_WINDOW_SECONDS = 10

MANY_404_THRESHOLD = 10
MANY_404_WINDOW_SECONDS = 60


def detect_web_enumeration(parsed_logs):
    ip_events = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_events[ip].append((timestamp, log["url"]))

    for ip, events in ip_events.items():
        events.sort(key=lambda x: x[0])

        for i in range(len(events)):
            start_time = events[i][0]
            urls = set()

            for j in range(i, len(events)):
                current_time, url = events[j]

                if (
                    current_time - start_time
                    > timedelta(seconds=ENUMERATION_WINDOW_SECONDS)
                ):
                    break

                urls.add(url)

            if len(urls) >= ENUMERATION_URL_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "unique_urls": len(urls),
                    "window_seconds": ENUMERATION_WINDOW_SECONDS,
                    "status": "ALERT",
                    "reason": "Possible Web Enumeration"
                })
                break

    return alerts


def detect_many_404(parsed_logs):
    ip_404_times = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log["status"] != 404:
            continue

        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_404_times[ip].append(timestamp)

    for ip, times in ip_404_times.items():
        times.sort()
        left = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
                > timedelta(seconds=MANY_404_WINDOW_SECONDS)
            ):
                left += 1

            count_404 = right - left + 1

            if count_404 >= MANY_404_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "404_count": count_404,
                    "window_seconds": MANY_404_WINDOW_SECONDS,
                    "status": "WARNING",
                    "reason": "High number of 404 responses"
                })
                break

    return alerts