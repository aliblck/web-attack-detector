import json


# Analiz sonuçlarından IOC (Indicator of Compromise) raporu oluşturur
def build_ioc_report(parsed_logs, high_request_alerts, brute_force_alerts):

    # IOC olarak tutulacak bilgileri tekrar etmeyecek şekilde saklar
    suspicious_ips = set()
    suspicious_urls = set()
    suspicious_status_codes = set()

    # Yüksek istek frekansı alarmı oluşturan IP adreslerini ekler
    for alert in high_request_alerts:
        suspicious_ips.add(alert["ip"])

    # Brute force alarmı oluşturan IP adreslerini ekler
    for alert in brute_force_alerts:
        suspicious_ips.add(alert["ip"])

    # Şüpheli IP adreslerine ait log kayıtlarını inceler
    for log in parsed_logs:

        if log["ip"] in suspicious_ips:
            url = log["url"]
            status = log["status"]

            # 401, 403 ve 404 durum koduna sahip URL'leri
            # şüpheli IOC bilgileri arasına ekler
            if status in [401, 403, 404]:
                suspicious_urls.add(url)
                suspicious_status_codes.add(status)

            # Hassas veya saldırganların sıklıkla arayabileceği
            # endpoint kelimelerini kontrol eder
            suspicious_keywords = [
                "admin",
                "login",
                "backup",
                "secret",
                "phpmyadmin"
            ]

            # URL içerisinde şüpheli kelimelerden biri varsa
            # URL'yi IOC listesine ekler
            if any(
                keyword in url.lower()
                for keyword in suspicious_keywords
            ):
                suspicious_urls.add(url)

    # Elde edilen IOC bilgilerini rapor haline getirir
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


# Oluşturulan IOC raporunu JSON dosyasına kaydeder
def save_ioc_report(report, filename="ioc_report.json"):

    with open(filename, "w", encoding="utf-8") as file:

        # indent=4 ile JSON dosyasını daha okunabilir biçimde kaydeder
        # ensure_ascii=False Türkçe karakterlerin düzgün yazılmasını sağlar
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )