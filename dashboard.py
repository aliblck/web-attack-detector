from flask import Flask, render_template

from parser import parse_log_line
from analyzer import analyze_logs
from detector import (
    detect_high_request_frequency,
    detect_web_brute_force,
    detect_web_enumeration,
    detect_many_404,
)

# Flask web uygulamasını oluşturur
app = Flask(__name__)

# Dashboard üzerinde analiz edilecek log dosyasının yolu
LOG_FILE = "sample_logs/access.log"


# Log dosyasını okuyup her satırı parser yardımıyla ayrıştırır
def load_logs():
    parsed_logs = []

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            parsed = parse_log_line(line)

            # Satır başarıyla ayrıştırıldıysa listeye ekler
            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs


# Ana dashboard sayfasını oluşturur
@app.route("/")
def dashboard():

    # Log kayıtlarını yükler
    parsed_logs = load_logs()

    # Temel log istatistiklerini hesaplar
    results = analyze_logs(parsed_logs)

    # Detection kurallarını çalıştırır
    high_request_alerts = detect_high_request_frequency(parsed_logs)
    brute_force_alerts = detect_web_brute_force(parsed_logs)
    enumeration_alerts = detect_web_enumeration(parsed_logs)
    many_404_alerts = detect_many_404(parsed_logs)

    # Tüm güvenlik alarmlarını tek listede birleştirir
    all_alerts = (
        high_request_alerts
        + brute_force_alerts
        + enumeration_alerts
        + many_404_alerts
    )

    # Alarm üreten benzersiz IP adreslerini tutar
    suspicious_ips = set()

    for alert in all_alerts:
        suspicious_ips.add(alert["ip"])

    # En fazla HTTP isteği gönderen ilk 5 IP adresini seçer
    top_ips = results["ip_counts"].most_common(5)

    # Hesaplanan verileri dashboard.html dosyasına gönderir
    return render_template(
        "dashboard.html",
        total_requests=results["total_requests"],
        unique_ips=results["unique_ip_count"],
        suspicious_ip_count=len(suspicious_ips),
        alert_count=len(all_alerts),
        top_ips=top_ips,
        status_counts=results["status_counts"],
        alerts=all_alerts,
    )


# Bu dosya doğrudan çalıştırılırsa Flask web sunucusunu başlatır
if __name__ == "__main__":
    app.run(debug=True)