from parser import parse_log_line
from analyzer import analyze_logs
from detector import detect_high_request_frequency, detect_web_brute_force
from ioc import build_ioc_report, save_ioc_report


# Analiz edilecek Apache access.log dosyası
LOG_FILE = "sample_logs/access.log"

# Ayrıştırılmış log kayıtlarını tutacak liste
parsed_logs = []


# Log dosyasını satır satır oku
with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:

        # Her log satırını parser.py ile ayrıştır
        parsed = parse_log_line(line)

        # Satır başarıyla ayrıştırıldıysa listeye ekle
        if parsed:
            parsed_logs.append(parsed)


# Log kayıtlarının temel istatistiklerini analiz et
results = analyze_logs(parsed_logs)


# ------------------------------------------------------------
# TEMEL LOG ANALİZİ
# ------------------------------------------------------------

print("=" * 60)
print("WEB SALDIRI LOG ANALİZ ARACI")
print("=" * 60)

print("Toplam İstek        :", results["total_requests"])
print("Benzersiz IP Sayısı :", results["unique_ip_count"])
print("GET İstekleri       :", results["get_requests"])
print("POST İstekleri      :", results["post_requests"])
print("404 İstekleri       :", results["404_requests"])
print("403 İstekleri       :", results["403_requests"])
print("5xx İstekleri       :", results["5xx_requests"])


# ------------------------------------------------------------
# HTTP DURUM KODU ANALİZİ
# ------------------------------------------------------------

print()
print("HTTP DURUM KODU ANALİZİ")
print("-" * 60)

# İncelenecek önemli HTTP durum kodları
important_status_codes = [200, 301, 302, 400, 401, 403, 404, 500]

for code in important_status_codes:
    count = results["status_counts"].get(code, 0)

    print(f"{code} Sayısı : {count}")


# ------------------------------------------------------------
# IP ADRESİ ANALİZİ
# ------------------------------------------------------------

print()
print("IP ADRESİ ANALİZİ")
print("-" * 60)

# En çok istek gönderen IP adreslerini listeler
for ip, count in results["ip_counts"].most_common():
    print(f"{ip:<20} {count}")


# ------------------------------------------------------------
# YÜKSEK İSTEK FREKANSI TESPİTİ
# ------------------------------------------------------------

print()
print("=" * 60)
print("WEB SALDIRI TESPİTİ")
print("=" * 60)

# Aynı IP'den kısa sürede yüksek sayıda istek olup olmadığını kontrol eder
alerts = detect_high_request_frequency(parsed_logs)

if not alerts:
    print("Şüpheli IP : Yok")

else:
    print("Şüpheli IP Adresleri:")

    for alert in alerts:
        print("-" * 60)
        print("IP            :", alert["ip"])
        print("İstek Sayısı  :", alert["requests"])
        print(
            "Zaman Aralığı :",
            f'{alert["window_seconds"]} saniye'
        )
        print("Durum         :", alert["status"])
        print("Neden         :", alert["reason"])


# ------------------------------------------------------------
# WEB BRUTE FORCE TESPİTİ
# ------------------------------------------------------------

print()
print("=" * 60)
print("WEB BRUTE FORCE TESPİTİ")
print("=" * 60)

# Kısa sürede çok sayıda başarısız login isteğini kontrol eder
brute_force_alerts = detect_web_brute_force(parsed_logs)

if not brute_force_alerts:
    print("Brute Force Alarmı : Yok")

else:
    for alert in brute_force_alerts:

        print("ALARM: Olası Web Brute Force")
        print("-" * 60)
        print("Kaynak IP          :", alert["ip"])
        print(
            "Başarısız Deneme   :",
            alert["failed_attempts"]
        )
        print(
            "Zaman Aralığı      :",
            f'{alert["window_seconds"]} saniye'
        )
        print("Risk               :", alert["risk"])
        print("Neden              :", alert["reason"])


# ------------------------------------------------------------
# IOC RAPORU
# ------------------------------------------------------------

print()
print("=" * 60)
print("IOC RAPORU")
print("=" * 60)

# Detection sonuçlarından IOC raporu oluştur
ioc_report = build_ioc_report(
    parsed_logs,
    alerts,
    brute_force_alerts
)

# IOC raporunu JSON dosyasına kaydet
save_ioc_report(ioc_report)


# Şüpheli IP adreslerini göster
print("Şüpheli IP Adresleri:")

for ip in ioc_report["suspicious_ips"]:
    print(" -", ip)


# Şüpheli URL'leri göster
print("Şüpheli URL'ler:")

for url in ioc_report["suspicious_urls"]:
    print(" -", url)


# Şüpheli olaylarla ilişkili HTTP durum kodlarını göster
print("Durum Kodları:")

for status in ioc_report["status_codes"]:
    print(" -", status)


print()
print("IOC raporu kaydedildi: ioc_report.json")