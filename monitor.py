import os
import time

from parser import parse_log_line

LOG_FILE = "sample_logs/access.log"


def monitor_log():
    print("=" * 60)
    print("REAL-TIME WEB LOG MONITOR")
    print("=" * 60)
    print("Monitoring:", LOG_FILE)
    print("Yeni log kayitlari bekleniyor...")
    print("Durdurmak icin CTRL+C")
    print()

    # Program başladığında dosyanın son konumunu al
    position = os.path.getsize(LOG_FILE)

    while True:
        current_size = os.path.getsize(LOG_FILE)

        # Dosyaya yeni veri eklenmişse
        if current_size > position:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                file.seek(position)
                new_data = file.read()
                position = file.tell()

            for line in new_data.splitlines():

                log = parse_log_line(line)

                if not log:
                    continue

                print(
                    f'[NEW REQUEST] '
                    f'IP: {log["ip"]} | '
                    f'Method: {log["method"]} | '
                    f'URL: {log["url"]} | '
                    f'Status: {log["status"]}'
                )

                # Şüpheli istek kontrolü
                suspicious = False
                reasons = []

                # Şüpheli HTTP durum kodları
                if log["status"] in [401, 403, 404]:
                    suspicious = True
                    reasons.append(f'Status {log["status"]}')

                # Hassas URL kelimeleri
                suspicious_keywords = [
                    "admin",
                    "login",
                    "backup",
                    "secret"
                ]

                if any(
                    keyword in log["url"].lower()
                    for keyword in suspicious_keywords
                ):
                    suspicious = True
                    reasons.append("Sensitive URL")

                # Alarm oluştur
                if suspicious:
                    print("SECURITY ALERT")
                    print("Source IP :", log["ip"])
                    print("Reason    :", ", ".join(reasons))
                    print("-" * 60)

        time.sleep(0.5)


if __name__ == "__main__":
    try:
        monitor_log()

    except KeyboardInterrupt:
        print("\nLog monitoring stopped.")