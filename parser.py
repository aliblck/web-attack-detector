import re

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


def parse_log_line(line):
    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    data["status"] = int(data["status"])

    if data["size"] == "-":
        data["size"] = 0
    else:
        data["size"] = int(data["size"])

    return data