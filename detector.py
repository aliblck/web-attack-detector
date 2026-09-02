from collections import defaultdict
from datetime import datetime, timedelta


# ------------------------------------------------------------
# YÜKSEK İSTEK FREKANSI TESPİTİ
# ------------------------------------------------------------

# Aynı IP'den 10 saniye içinde 20 veya daha fazla istek gelirse alarm üretilecek
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

    # Her IP adresinin istek zamanlarını tutar
    ip_times = defaultdict(list)

    # Üretilen güvenlik alarmlarını tutar
    alerts = []

    # Tüm log kayıtlarını tek tek inceler
    for log in parsed_logs:
        ip = log["ip"]

        # Sunucunun kendi localhost kayıtlarını analize dahil etmiyoruz
        if ip == "127.0.0.1":
            continue

        # Logun zaman bilgisini datetime formatına çevirir
        timestamp = parse_timestamp(log["timestamp"])

        # İlgili IP adresinin zaman listesine ekler
        ip_times[ip].append(timestamp)

    # Her IP adresini ayrı ayrı analiz eder
    for ip, times in ip_times.items():

        # Zamanları küçükten büyüğe sıralar
        times.sort()

        left = 0

        # Belirlenen zaman aralığında kaç istek olduğunu hesaplar
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

                    # Dashboard üzerinde gösterilecek saldırı türü
                    "attack_type": "Yüksek İstek Frekansı",

                    # Risk seviyesi
                    "risk": "ORTA",

                    # Tespit edilen istek sayısı
                    "requests": request_count,

                    # Kullanılan zaman penceresi
                    "window_seconds": TIME_WINDOW_SECONDS,

                    # Alarm durumu
                    "status": "UYARI",

                    # Alarmın neden oluştuğunu açıklar
                    "reason": "Kısa sürede çok sayıda HTTP isteği tespit edildi.",

                    # Kullanıcıya daha ayrıntılı açıklama verir
                    "detail": (
                        f"{TIME_WINDOW_SECONDS} saniye içerisinde "
                        f"{request_count} HTTP isteği gönderildi."
                    )
                })

                # Aynı IP için aynı alarmı tekrar tekrar oluşturmamak için çıkar
                break

    return alerts


# ------------------------------------------------------------
# WEB BRUTE FORCE TESPİTİ
# ------------------------------------------------------------

# 60 saniye içerisinde 5 başarısız giriş olursa alarm üretilecek
LOGIN_THRESHOLD = 5
LOGIN_TIME_WINDOW_SECONDS = 60


# Login işlemi ile ilişkili olabilecek URL kelimeleri
LOGIN_KEYWORDS = [
    "login",
    "signin",
    "auth"
]


# Bir log kaydının login isteği olup olmadığını kontrol eder
def is_login_request(log):

    # URL'yi küçük harfe dönüştürür
    url = log["url"].lower()

    return (
        # Login işlemlerinde POST isteği beklenir
        log["method"] == "POST"

        # URL içerisinde login, signin veya auth kelimelerinden biri var mı kontrol edilir
        and any(keyword in url for keyword in LOGIN_KEYWORDS)
    )


# Kısa sürede çok sayıda başarısız login isteğini tespit eder
def detect_web_brute_force(parsed_logs):

    # Her IP'nin başarısız login denemelerinin zamanlarını tutar
    login_attempts = defaultdict(list)

    # Alarm listesini oluşturur
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        # Localhost kayıtlarını hariç tutar
        if ip == "127.0.0.1":
            continue

        # Login isteği değilse bu kaydı atlar
        if not is_login_request(log):
            continue

        # 401 ve 403 durum kodlarını başarısız login olarak kabul ediyoruz
        if log["status"] not in [401, 403]:
            continue

        timestamp = parse_timestamp(log["timestamp"])
        login_attempts[ip].append(timestamp)

    # Her IP adresinin başarısız login girişimlerini analiz eder
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

            # Başarısız giriş sayısı eşik değerine ulaşırsa alarm üretir
            if failed_count >= LOGIN_THRESHOLD:

                alerts.append({
                    "ip": ip,

                    "attack_type": "Web Brute Force",

                    "risk": "YÜKSEK",

                    "failed_attempts": failed_count,

                    "window_seconds": LOGIN_TIME_WINDOW_SECONDS,

                    "status": "ALARM",

                    "reason": "Kısa sürede tekrarlanan başarısız giriş denemeleri tespit edildi.",

                    "detail": (
                        f"{LOGIN_TIME_WINDOW_SECONDS} saniye içerisinde "
                        f"{failed_count} başarısız giriş denemesi yapıldı."
                    )
                })

                break

    return alerts


# ------------------------------------------------------------
# WEB ENUMERATION TESPİTİ
# ------------------------------------------------------------

# 10 saniye içinde 8 veya daha fazla farklı URL sorgulanırsa alarm üretilecek
ENUMERATION_URL_THRESHOLD = 8
ENUMERATION_WINDOW_SECONDS = 10


# Aynı IP adresinin kısa sürede çok sayıda farklı URL'ye erişip erişmediğini kontrol eder
def detect_web_enumeration(parsed_logs):

    # Her IP için zaman ve URL bilgilerini tutar
    ip_events = defaultdict(list)

    # Alarm listesini oluşturur
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])

        # İlgili IP için zaman ve URL bilgisini birlikte saklar
        ip_events[ip].append(
            (timestamp, log["url"])
        )

    # Her IP adresini ayrı ayrı analiz eder
    for ip, events in ip_events.items():

        # Olayları zamana göre sıralar
        events.sort(key=lambda x: x[0])

        for i in range(len(events)):

            # Analizin başlangıç zamanını belirler
            start_time = events[i][0]

            # Aynı URL'nin tekrarlarını tek saymak için set kullanılır
            urls = set()

            for j in range(i, len(events)):
                current_time, url = events[j]

                # Zaman penceresi aşılırsa döngü sonlandırılır
                if (
                    current_time - start_time
                    > timedelta(seconds=ENUMERATION_WINDOW_SECONDS)
                ):
                    break

                # Farklı URL'leri sete ekler
                urls.add(url)

            # Farklı URL sayısı eşik değerine ulaşırsa alarm üretir
            if len(urls) >= ENUMERATION_URL_THRESHOLD:

                alerts.append({
                    "ip": ip,

                    "attack_type": "Web Enumeration",

                    "risk": "YÜKSEK",

                    "unique_urls": len(urls),

                    "window_seconds": ENUMERATION_WINDOW_SECONDS,

                    "status": "ALARM",

                    "reason": "Kısa sürede çok sayıda farklı URL isteği tespit edildi.",

                    "detail": (
                        f"{ENUMERATION_WINDOW_SECONDS} saniye içerisinde "
                        f"{len(urls)} farklı URL sorgulandı."
                    )
                })

                break

    return alerts


# ------------------------------------------------------------
# ÇOK SAYIDA 404 TESPİTİ
# ------------------------------------------------------------

# 60 saniye içerisinde 10 veya daha fazla 404 cevabı oluşursa alarm üretilecek
MANY_404_THRESHOLD = 10
MANY_404_WINDOW_SECONDS = 60


# Aynı IP adresinin kısa sürede çok sayıda 404 üretip üretmediğini kontrol eder
def detect_many_404(parsed_logs):

    # Her IP adresinin 404 aldığı zamanları tutar
    ip_404_times = defaultdict(list)

    # Alarm listesini oluşturur
    alerts = []

    for log in parsed_logs:

        # Yalnızca 404 durum koduna sahip kayıtları inceler
        if log["status"] != 404:
            continue

        ip = log["ip"]

        if ip == "127.0.0.1":
            continue

        timestamp = parse_timestamp(log["timestamp"])

        # IP'nin 404 zamanını kaydeder
        ip_404_times[ip].append(timestamp)

    # Her IP adresini ayrı ayrı analiz eder
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

                    "attack_type": "404 Tabanlı Kaynak Keşfi",

                    "risk": "ORTA",

                    "404_count": count_404,

                    "window_seconds": MANY_404_WINDOW_SECONDS,

                    "status": "UYARI",

                    "reason": "Kısa sürede çok sayıda 404 Not Found cevabı oluştu.",

                    "detail": (
                        f"{MANY_404_WINDOW_SECONDS} saniye içerisinde "
                        f"{count_404} adet 404 cevabı üretildi."
                    )
                })

                break

    return alerts