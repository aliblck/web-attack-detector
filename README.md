# Web Attack Log Analyzer

Web Attack Log Analyzer, Apache/Nginx access log dosyalarını analiz ederek temel HTTP istatistikleri çıkaran ve şüpheli web aktivitelerini tespit eden basit bir Blue Team güvenlik projesidir.

## Özellikler

- Apache access log parsing
- Total request analizi
- Unique IP analizi
- GET / POST request sayımı
- HTTP status code analizi
- High request frequency detection
- Web enumeration detection
- Multiple 404 detection
- Web brute force detection
- IOC üretimi
- JSON IOC raporu
- Test senaryoları
- Gerçek zamanlı log izleme
- Flask tabanlı web dashboard

## Proje Yapısı

```text
web-attack-detector/
├── main.py
├── parser.py
├── analyzer.py
├── detector.py
├── ioc.py
├── monitor.py
├── dashboard.py
├── ioc_report.json
├── requirements.txt
├── README.md
├── sample_logs/
├── tests/
├── reports/
└── templates/