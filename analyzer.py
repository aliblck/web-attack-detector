from collections import Counter


# Ayrıştırılmış log kayıtlarından temel istatistikleri çıkarır
def analyze_logs(parsed_logs):

    # Toplam HTTP istek sayısını hesaplar
    total_requests = len(parsed_logs)

    # Benzersiz IP adreslerini ve çeşitli değerlerin sayılarını tutar
    unique_ips = set()
    method_counts = Counter()
    status_counts = Counter()
    ip_counts = Counter()

    # Her log kaydını tek tek analiz eder
    for log in parsed_logs:
        ip = log["ip"]
        method = log["method"]
        status = log["status"]

        # Kaynak IP adresini benzersiz IP listesine ekler
        unique_ips.add(ip)

        # HTTP method sayılarını hesaplar (GET, POST vb.)
        method_counts[method] += 1

        # HTTP durum kodlarının sayılarını hesaplar
        status_counts[status] += 1

        # Her IP adresinin kaç istek yaptığını hesaplar
        ip_counts[ip] += 1

    # 500-599 arasındaki tüm sunucu hata kodlarını toplar
    five_xx_count = sum(
        count
        for status, count in status_counts.items()
        if 500 <= status <= 599
    )

    # Hesaplanan analiz sonuçlarını diğer dosyalarda
    # kullanılmak üzere sözlük (dictionary) olarak döndürür
    return {
        "total_requests": total_requests,
        "unique_ip_count": len(unique_ips),
        "get_requests": method_counts["GET"],
        "post_requests": method_counts["POST"],
        "404_requests": status_counts[404],
        "403_requests": status_counts[403],
        "5xx_requests": five_xx_count,
        "status_counts": status_counts,
        "ip_counts": ip_counts,
    }