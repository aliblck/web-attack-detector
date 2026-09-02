import os
import subprocess


# ------------------------------------------------------------
# METASPLOITABLE BAĞLANTI AYARLARI
# ------------------------------------------------------------

SSH_HOST = "192.168.14.129"
SSH_USER = "msfadmin"

# Metasploitable üzerindeki gerçek Apache access log
REMOTE_LOG_FILE = "/var/log/apache2/access.log"

# Windows tarafında dashboard'un okuyacağı canlı log
LOCAL_LOG_FILE = "sample_logs/live_access.log"


# ------------------------------------------------------------
# CANLI LOG OKUMA
# ------------------------------------------------------------

def start_live_log_reader():

    print("=" * 60)
    print("METASPLOITABLE CANLI LOG BAĞLANTISI")
    print("=" * 60)

    print("Hedef IP       :", SSH_HOST)
    print("Uzak Log       :", REMOTE_LOG_FILE)
    print("Yerel Log      :", LOCAL_LOG_FILE)
    print()

    # sample_logs klasörü yoksa oluşturur
    os.makedirs(
        os.path.dirname(LOCAL_LOG_FILE),
        exist_ok=True
    )

    # Önceki canlı test kayıtlarını temizler.
    # Böylece program her açıldığında sıfırdan yeni canlı oturum başlar.
    with open(
        LOCAL_LOG_FILE,
        "w",
        encoding="utf-8"
    ):
        pass

    print("Eski canlı kayıtlar temizlendi.")
    print()

    # Windows OpenSSH istemcisi kullanılır
    command = [
        "ssh",

        # Metasploitable eski ssh-rsa host key kullandığı için
        "-oHostKeyAlgorithms=+ssh-rsa",

        f"{SSH_USER}@{SSH_HOST}",

        # -n 0:
        # Eski logları göstermez.
        # Sadece bu andan sonra oluşan yeni kayıtları takip eder.
        f"tail -n 0 -f {REMOTE_LOG_FILE}"
    ]

    print("SSH bağlantısı başlatılıyor...")
    print("Parola istendiğinde Metasploitable parolasını giriniz.")
    print()

    process = None

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            encoding="utf-8",
            errors="ignore",
            bufsize=1
        )

        print("Canlı Apache logları bekleniyor...")
        print("Durdurmak için CTRL+C")
        print()

        # Dashboard'un okuyacağı yerel dosyayı açar
        with open(
            LOCAL_LOG_FILE,
            "a",
            encoding="utf-8",
            buffering=1
        ) as local_file:

            # SSH üzerinden gelen her yeni satırı okur
            for line in process.stdout:

                line = line.strip()

                if not line:
                    continue

                # Apache'nin kendi internal dummy connection
                # kayıtlarını canlı güvenlik analizinden çıkarıyoruz.
                if line.startswith("127.0.0.1"):
                    continue

                # Terminalde gösterir
                print("[YENİ CANLI LOG]", line)

                # Dosyaya kaydeder
                local_file.write(line + "\n")
                local_file.flush()

                print("[DOSYAYA KAYDEDİLDİ]")

    except KeyboardInterrupt:

        print()
        print("Canlı log izleme durduruldu.")

    except Exception as error:

        print()
        print("CANLI LOG BAĞLANTI HATASI")
        print("Hata:", error)

    finally:

        if process is not None:
            process.terminate()

        print("Canlı log bağlantısı kapatıldı.")


if __name__ == "__main__":
    start_live_log_reader()