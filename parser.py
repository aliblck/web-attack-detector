import re


# Apache access.log satırlarının yapısını tanımlayan düzenli ifade (Regex)
# Bu yapı sayesinde log satırındaki IP, tarih, HTTP metodu,
# URL, durum kodu, User-Agent gibi bilgiler ayrı ayrı çıkarılır.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


# Tek bir Apache log satırını ayrıştırır
def parse_log_line(line):

    # Log satırının yukarıdaki Regex yapısına uyup uymadığını kontrol eder
    match = LOG_PATTERN.match(line)

    # Satır beklenen Apache log formatına uymuyorsa None döndürür
    if not match:
        return None

    # Regex tarafından yakalanan bilgileri sözlük (dictionary) haline getirir
    data = match.groupdict()

    # HTTP durum kodunu metin yerine tam sayıya dönüştürür
    # Örneğin "404" -> 404
    data["status"] = int(data["status"])

    # Apache bazı durumlarda response boyutunu "-" olarak gösterebilir.
    # Böyle bir durumda boyutu 0 kabul eder.
    if data["size"] == "-":
        data["size"] = 0

    # Sayısal bir değer varsa tam sayıya dönüştürür
    else:
        data["size"] = int(data["size"])

    # Ayrıştırılmış log bilgilerini diğer modüllere gönderir
    return data