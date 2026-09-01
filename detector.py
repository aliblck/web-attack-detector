from collections import defaultdict
from datetime import datetime, timedelta


# Yüksek istek frekansı için eşik değerleri
REQUEST_THRESHOLD = 20
TIME_WINDOW_SECONDS = 10


# Apache logundaki tarih/saat bilgisini Python datetime nesnesine çevirir
def parse_timestamp(timestamp):
    return datetime.strptime(
        timestamp,
        "%d/%b/%Y:%H:%M:%S %z"
    )


# Aynı IP adresinden kısa sürede çok sayıda HTTP isteği gelip gelmediğini kontrol eder
def detect_high_request_frequency(parsed_logs):
    ip_times = defaultdict(list)
    alerts = []

    # Her IP adresinin yaptığı isteklerin zamanlarını toplar
    for log in parsed_logs:
        ip = log["ip"]

        # Sunucunun kendi localhost kayıtlarını analize dahil etmiyoruz
        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_times[ip].append(timestamp)

    # Her IP adresini ayrı ayrı analiz eder
    for ip, times in ip_times.items():
        times.sort()

        left = 0

        # Belirlenen zaman penceresi içerisindeki istek sayısını hesaplar
        for right in range(len(times)):
            while (
                times[right] - times[left]
                > timedelta(seconds=TIME_WINDOW_SECONDS)
            ):
                left += 1

            request_count = right - left + 1

            # İstek sayısı eşik değerine ulaşırsa alarm üretir
            if request_count >= REQUEST_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "requests": request_count,
                    "window_seconds": TIME_WINDOW_SECONDS,
                    "status": "WARNING",
                    "reason": "High request frequency"
                })

                # Aynı IP için aynı olayı tekrar tekrar alarm olarak üretmez
                break

    return alerts


# Brute force tespiti için eşik değerleri
LOGIN_THRESHOLD = 5
LOGIN_TIME_WINDOW_SECONDS = 60

# Login işlemiyle ilişkili olabilecek URL kelimeleri
LOGIN_KEYWORDS = [
    "login",
    "signin",
    "auth"
]


# Bir log kaydının login isteği olup olmadığını kontrol eder
def is_login_request(log):
    url = log["url"].lower()

    return (
        log["method"] == "POST"
        and any(keyword in url for keyword in LOGIN_KEYWORDS)
    )


# Kısa sürede çok sayıda başarısız login isteği olup olmadığını kontrol eder
def detect_web_brute_force(parsed_logs):
    login_attempts = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        # Localhost kayıtlarını hariç tutar
        if ip == "127.0.0.1":
            continue

        # Yalnızca login ile ilişkili POST isteklerini inceler
        if not is_login_request(log):
            continue

        # Basit modelde 401 ve 403 durum kodlarını başarısız login kabul ediyoruz
        if log["status"] not in [401, 403]:
            continue

        timestamp = parse_timestamp(log["timestamp"])
        login_attempts[ip].append(timestamp)

    # Her IP adresinin başarısız login zamanlarını inceler
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

            # Başarısız login sayısı eşik değerine ulaşırsa alarm üretir
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


# Web enumeration ve çok sayıda 404 için eşik değerleri
ENUMERATION_URL_THRESHOLD = 8
ENUMERATION_WINDOW_SECONDS = 10

MANY_404_THRESHOLD = 10
MANY_404_WINDOW_SECONDS = 60


# Aynı IP'nin kısa sürede çok sayıda farklı URL isteği yapıp yapmadığını kontrol eder
def detect_web_enumeration(parsed_logs):
    ip_events = defaultdict(list)
    alerts = []

    # Her IP için zaman ve URL bilgisini toplar
    for log in parsed_logs:
        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_events[ip].append((timestamp, log["url"]))

    # Her IP'nin URL çeşitliliğini zaman penceresi içinde analiz eder
    for ip, events in ip_events.items():
        events.sort(key=lambda x: x[0])

        for i in range(len(events)):
            start_time = events[i][0]
            urls = set()

            for j in range(i, len(events)):
                current_time, url = events[j]

                # Zaman penceresi aşılmışsa döngüden çıkar
                if (
                    current_time - start_time
                    > timedelta(seconds=ENUMERATION_WINDOW_SECONDS)
                ):
                    break

                # Aynı URL birden fazla kez gelse bile yalnızca bir kez sayılır
                urls.add(url)

            # Farklı URL sayısı eşik değerine ulaşırsa alarm üretir
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


# Aynı IP adresinin kısa sürede çok sayıda 404 üretip üretmediğini kontrol eder
def detect_many_404(parsed_logs):
    ip_404_times = defaultdict(list)
    alerts = []

    # Yalnızca 404 durum koduna sahip kayıtları toplar
    for log in parsed_logs:
        if log["status"] != 404:
            continue

        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])
        ip_404_times[ip].append(timestamp)

    # Her IP için 404 sayısını zaman penceresi içinde hesaplar
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

            # 404 sayısı eşik değerine ulaşırsa alarm üretir
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