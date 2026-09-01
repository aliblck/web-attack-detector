import os
import time

from parser import parse_log_line

# Gerçek zamanlı olarak takip edilecek log dosyası
LOG_FILE = "sample_logs/access.log"


# Log dosyasını sürekli takip eden fonksiyon
def monitor_log():

    print("=" * 60)
    print("GERÇEK ZAMANLI WEB LOG İZLEME")
    print("=" * 60)
    print("İzlenen dosya:", LOG_FILE)
    print("Yeni log kayıtları bekleniyor...")
    print("Durdurmak için CTRL+C")
    print()

    # Program başladığında log dosyasının mevcut boyutunu alır.
    # Böylece eski kayıtları tekrar okumaz, yalnızca yeni eklenenleri takip eder.
    position = os.path.getsize(LOG_FILE)

    # Program durdurulana kadar log dosyasını sürekli kontrol eder
    while True:

        # Dosyanın güncel boyutunu kontrol eder
        current_size = os.path.getsize(LOG_FILE)

        # Dosyanın boyutu büyümüşse yeni log kaydı eklenmiştir
        if current_size > position:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                # Daha önce okunan son konuma gider
                file.seek(position)

                # Yeni eklenen verileri okur
                new_data = file.read()

                # Yeni dosya konumunu kaydeder
                position = file.tell()

            # Yeni eklenen her log satırını ayrı ayrı inceler
            for line in new_data.splitlines():

                # Log satırını parser.py yardımıyla ayrıştırır
                log = parse_log_line(line)

                # Satır ayrıştırılamadıysa atlar
                if not log:
                    continue

                # Yeni HTTP isteğinin temel bilgilerini ekrana yazdırır
                print(
                    f'[YENİ İSTEK] '
                    f'IP: {log["ip"]} | '
                    f'Metot: {log["method"]} | '
                    f'URL: {log["url"]} | '
                    f'Durum Kodu: {log["status"]}'
                )

                # İsteğin şüpheli olup olmadığını belirlemek için
                # başlangıç değerlerini oluşturur
                suspicious = False
                reasons = []

                # 401, 403 ve 404 durum kodlarını şüpheli kabul eder
                if log["status"] in [401, 403, 404]:
                    suspicious = True
                    reasons.append(
                        f'Durum kodu {log["status"]}'
                    )

                # Hassas olabilecek URL kelimeleri
                suspicious_keywords = [
                    "admin",
                    "login",
                    "backup",
                    "secret"
                ]

                # URL içerisinde şüpheli kelimelerden biri geçiyor mu kontrol eder
                if any(
                    keyword in log["url"].lower()
                    for keyword in suspicious_keywords
                ):
                    suspicious = True
                    reasons.append("Hassas URL")

                # Şüpheli davranış tespit edilmişse güvenlik alarmı üretir
                if suspicious:
                    print("GÜVENLİK ALARMI")
                    print("Kaynak IP :", log["ip"])
                    print("Neden     :", ", ".join(reasons))
                    print("-" * 60)

        # İşlemciyi sürekli meşgul etmemek için yarım saniye bekler
        time.sleep(0.5)


# monitor.py doğrudan çalıştırıldığında izlemeyi başlatır
if __name__ == "__main__":
    try:
        monitor_log()

    # Kullanıcı CTRL+C yaptığında programı düzgün şekilde sonlandırır
    except KeyboardInterrupt:
        print("\nLog izleme durduruldu.")