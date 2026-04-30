SERVICE_BY_PORT = {
    21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 139: "SMB", 445: "SMB",
}

def run(ip, port):
    service = SERVICE_BY_PORT.get(port)
    if service:
        return f"[INFO] {service} appears open on {ip}:{port}"
    return None
