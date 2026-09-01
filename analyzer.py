from collections import Counter


def analyze_logs(parsed_logs):
    total_requests = len(parsed_logs)

    unique_ips = set()
    method_counts = Counter()
    status_counts = Counter()
    ip_counts = Counter()

    for log in parsed_logs:
        ip = log["ip"]
        method = log["method"]
        status = log["status"]

        unique_ips.add(ip)
        method_counts[method] += 1
        status_counts[status] += 1
        ip_counts[ip] += 1

    five_xx_count = sum(
        count
        for status, count in status_counts.items()
        if 500 <= status <= 599
    )

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