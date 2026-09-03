import os
import ipaddress

from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from parser import parse_log_line
from analyzer import analyze_logs
from detector import (
    detect_high_request_frequency,
    detect_web_brute_force,
    detect_web_enumeration,
    detect_many_404,
)


# Flask uygulamasını oluşturur
app = Flask(__name__)


# ------------------------------------------------------------
# DOSYA AYARLARI
# ------------------------------------------------------------

# Varsayılan olarak analiz edilecek log dosyası
DEFAULT_LOG_FILE = "sample_logs/access.log"

# Metasploitable üzerinden gelen gerçek zamanlı logların tutulduğu dosya
LIVE_LOG_FILE = "sample_logs/live_access.log"

# Dashboard üzerinden yüklenen log dosyalarının tutulacağı klasör
UPLOAD_FOLDER = "uploads"

# Kabul edilen dosya uzantıları
ALLOWED_EXTENSIONS = {"log", "txt"}

# Upload klasörü yoksa oluşturur
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Canlı log dosyası henüz oluşmadıysa boş olarak oluşturur
if not os.path.exists(LIVE_LOG_FILE):
    with open(LIVE_LOG_FILE, "w", encoding="utf-8"):
        pass


# Şu anda genel log analizinde kullanılan aktif dosya
CURRENT_LOG_FILE = DEFAULT_LOG_FILE
CURRENT_LOG_NAME = "access.log"


# ------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# ------------------------------------------------------------

# Dosya uzantısının uygun olup olmadığını kontrol eder
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# Belirtilen log dosyasını okuyup parser ile ayrıştırır
def load_logs(filename):
    parsed_logs = []

    # Dosya yoksa boş liste döndürür
    if not os.path.exists(filename):
        return parsed_logs

    with open(
        filename,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line in file:
            parsed = parse_log_line(line)

            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs


# Verilen log kayıtları üzerinde tüm detection kurallarını çalıştırır
def detect_all(parsed_logs):

    high_request_alerts = detect_high_request_frequency(parsed_logs)
    brute_force_alerts = detect_web_brute_force(parsed_logs)
    enumeration_alerts = detect_web_enumeration(parsed_logs)
    many_404_alerts = detect_many_404(parsed_logs)

    all_alerts = (
        high_request_alerts
        + brute_force_alerts
        + enumeration_alerts
        + many_404_alerts
    )

    return all_alerts


# ------------------------------------------------------------
# IP ADRESİ ANALİZİ
# ------------------------------------------------------------

# Kullanıcının girdiği IP adresini seçili log üzerinde analiz eder
def analyze_ip(parsed_logs, target_ip):

    # Sadece girilen IP adresine ait log kayıtlarını seçer
    ip_logs = [
        log for log in parsed_logs
        if log["ip"] == target_ip
    ]

    # IP log içerisinde bulunamazsa
    if not ip_logs:
        return {
            "found": False,
            "ip": target_ip
        }

    # IP'nin toplam istek sayısı
    total_requests = len(ip_logs)

    # 404 cevaplarının sayısı
    count_404 = sum(
        1 for log in ip_logs
        if log["status"] == 404
    )

    # 403 cevaplarının sayısı
    count_403 = sum(
        1 for log in ip_logs
        if log["status"] == 403
    )

    # POST isteklerinin sayısı
    post_requests = sum(
        1 for log in ip_logs
        if log["method"] == "POST"
    )

    # Erişilen farklı URL sayısı
    unique_urls = len(
        set(log["url"] for log in ip_logs)
    )

    # Sadece bu IP'ye ait loglarda saldırı tespiti yapar
    all_alerts = detect_all(ip_logs)

    # Alarm varsa IP şüpheli kabul edilir
    suspicious = bool(all_alerts)

    # Varsayılan risk seviyesi
    risk = "DÜŞÜK"

    if suspicious:
        risk = "ORTA"

        # Herhangi bir yüksek riskli alarm varsa
        # genel IP risk seviyesini YÜKSEK yapar
        if any(
            alert.get("risk") == "YÜKSEK"
            for alert in all_alerts
        ):
            risk = "YÜKSEK"

    return {
        "found": True,
        "ip": target_ip,
        "total_requests": total_requests,
        "404_count": count_404,
        "403_count": count_403,
        "post_requests": post_requests,
        "unique_urls": unique_urls,
        "suspicious": suspicious,
        "risk": risk,
        "alerts": all_alerts,
    }


# ------------------------------------------------------------
# GENEL LOG ANALİZİ
# ------------------------------------------------------------

# Seçilen log dosyasını analiz edip dashboard'u oluşturur
def analyze_and_render(
    filename,
    selected_file=None,
    ip_result=None
):

    parsed_logs = load_logs(filename)

    # Temel log istatistiklerini hesaplar
    results = analyze_logs(parsed_logs)

    # Tüm saldırı tespit kurallarını çalıştırır
    all_alerts = detect_all(parsed_logs)

    # Alarm oluşturan benzersiz IP adreslerini toplar
    suspicious_ips = set()

    for alert in all_alerts:
        suspicious_ips.add(alert["ip"])

    # En aktif ilk 5 IP adresini belirler
    top_ips = results["ip_counts"].most_common(5)

    return render_template(
        "dashboard.html",
        total_requests=results["total_requests"],
        unique_ips=results["unique_ip_count"],
        suspicious_ip_count=len(suspicious_ips),
        alert_count=len(all_alerts),
        top_ips=top_ips,
        status_counts=results["status_counts"],
        alerts=all_alerts,
        selected_file=selected_file,
        ip_result=ip_result,
    )


# ------------------------------------------------------------
# ANA DASHBOARD
# ------------------------------------------------------------

@app.route("/")
def dashboard():

    return analyze_and_render(
        CURRENT_LOG_FILE,
        selected_file=CURRENT_LOG_NAME
    )


# ------------------------------------------------------------
# LOG DOSYASI YÜKLEME
# ------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload_log():

    global CURRENT_LOG_FILE
    global CURRENT_LOG_NAME

    if "log_file" not in request.files:
        return "Log dosyası seçilmedi.", 400

    file = request.files["log_file"]

    if file.filename == "":
        return "Log dosyası seçilmedi.", 400

    if not allowed_file(file.filename):
        return "Sadece .log veya .txt dosyaları yüklenebilir.", 400

    # Dosya adını güvenli hale getirir
    filename = secure_filename(file.filename)

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    # Dosyayı uploads klasörüne kaydeder
    file.save(file_path)

    # Seçilen logu genel analiz için aktif log yapar
    CURRENT_LOG_FILE = file_path
    CURRENT_LOG_NAME = filename

    return analyze_and_render(
        CURRENT_LOG_FILE,
        selected_file=CURRENT_LOG_NAME
    )


# ------------------------------------------------------------
# IP ANALİZ ROUTE'U
# ------------------------------------------------------------

@app.route("/analyze-ip", methods=["POST"])
def analyze_ip_route():

    target_ip = request.form.get(
        "ip_address",
        ""
    ).strip()

    # Girilen değerin geçerli bir IP adresi olup olmadığını kontrol eder
    try:
        ipaddress.ip_address(target_ip)

    except ValueError:
        return "Geçerli bir IP adresi giriniz.", 400

    parsed_logs = load_logs(CURRENT_LOG_FILE)

    ip_result = analyze_ip(
        parsed_logs,
        target_ip
    )

    return analyze_and_render(
        CURRENT_LOG_FILE,
        selected_file=CURRENT_LOG_NAME,
        ip_result=ip_result
    )


# ------------------------------------------------------------
# GERÇEK ZAMANLI CANLI İZLEME
# ------------------------------------------------------------

@app.route("/live")
def live_monitor():

    # Canlı log dosyasını okur
    parsed_logs = load_logs(LIVE_LOG_FILE)

    # Son 30 kaydı seçer ve gerçek indekslerini saklar
    start_index = max(0, len(parsed_logs) - 30)

    latest_logs = [
        {
            "index": index,
            "log": parsed_logs[index]
        }
        for index in range(start_index, len(parsed_logs))
    ]

    # Canlı loglar üzerinde saldırı tespiti yapar
    all_alerts = detect_all(parsed_logs)

    # Şüpheli IP adreslerini belirler
    suspicious_ips = set()

    for alert in all_alerts:
        suspicious_ips.add(alert["ip"])

    # Canlı log istatistiklerini hesaplar
    live_results = analyze_logs(parsed_logs)

    # Sonuçları live.html sayfasına gönderir
    return render_template(
        "live.html",
        latest_logs=latest_logs,
        alerts=all_alerts,
        selected_file="live_access.log",
        total_requests=live_results["total_requests"],
        unique_ips=live_results["unique_ip_count"],
        suspicious_ip_count=len(suspicious_ips),
        alert_count=len(all_alerts),
    )
# ------------------------------------------------------------
# CANLI LOG DETAY İNCELEME
# ------------------------------------------------------------

@app.route("/live/detail/<int:index>")
def live_log_detail(index):

    # Canlı log dosyasını okur
    parsed_logs = load_logs(LIVE_LOG_FILE)

    # Geçerli bir kayıt numarası mı kontrol eder
    if index < 0 or index >= len(parsed_logs):
        return "Log kaydı bulunamadı.", 404

    # Seçilen log kaydını alır
    selected_log = parsed_logs[index]

    # Aynı IP adresine ait tüm canlı log kayıtlarını seçer
    ip_logs = [
        log for log in parsed_logs
        if log["ip"] == selected_log["ip"]
    ]

    # Bu IP adresi için tüm detection kurallarını çalıştırır
    related_alerts = detect_all(ip_logs)

    # Varsayılan değerlendirme
    suspicious = False
    risk = "DÜŞÜK"

    # Eğer bu IP için alarm varsa şüpheli kabul edilir
    if related_alerts:
        suspicious = True
        risk = "ORTA"

        # Herhangi bir yüksek riskli alarm varsa
        # genel risk seviyesi YÜKSEK olur
        if any(
            alert.get("risk") == "YÜKSEK"
            for alert in related_alerts
        ):
            risk = "YÜKSEK"

    return render_template(
        "live_detail.html",
        log=selected_log,
        suspicious=suspicious,
        risk=risk,
        alerts=related_alerts,
    )


# UYGULAMAYI BAŞLAT

if __name__ == "__main__":
    app.run(debug=True)
