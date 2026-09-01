import os
import sys

# Proje ana klasörünü Python modül arama yoluna ekler
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from parser import parse_log_line

from detector import (
    detect_high_request_frequency,
    detect_web_brute_force,
    detect_web_enumeration,
    detect_many_404,
)

# Testlerde kullanılacak log dosyaları
TEST_FILES = {
    "Normal trafik": "sample_logs/normal.log",
    "Web enumeration": "sample_logs/enumeration.log",
    "Çok sayıda 404": "sample_logs/many_404.log",
    "Brute force": "sample_logs/bruteforce.log",
    "Yüksek istek sayısı": "sample_logs/high_request.log",
}


# Verilen log dosyasını okuyup satırları ayrıştırır
def load_logs(filename):
    logs = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)

            # Satır doğru şekilde ayrıştırıldıysa listeye ekle
            if parsed:
                logs.append(parsed)

    return logs


# Tüm test dosyalarını sırayla analiz eder
for test_name, filename in TEST_FILES.items():
    logs = load_logs(filename)

    # Detection kurallarını çalıştır
    high_request_alerts = detect_high_request_frequency(logs)
    brute_force_alerts = detect_web_brute_force(logs)
    enumeration_alerts = detect_web_enumeration(logs)
    many_404_alerts = detect_many_404(logs)

    # Log dosyasındaki toplam 404 sayısını hesapla
    count_404 = sum(
        1 for log in logs
        if log["status"] == 404
    )

    print("=" * 60)
    print(test_name)
    print("=" * 60)

    print("Toplam istek             :", len(logs))
    print("404 sayısı               :", count_404)
    print("Enumeration alarmı       :", bool(enumeration_alerts))
    print("Çoklu 404 alarmı         :", bool(many_404_alerts))
    print("Brute force alarmı       :", bool(brute_force_alerts))
    print("Yüksek istek alarmı      :", bool(high_request_alerts))