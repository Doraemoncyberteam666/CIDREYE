import socket


def run(ip, port):
    if port not in (80, 8080, 443, 8443):
        return None
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                data = s.recv(256)
                if b"HTTP/" in data:
                    return f"[INFO] HTTP service responded on {ip}:{port}"
            else:
                return f"[INFO] HTTPS service appears open on {ip}:{port}"
    except OSError:
        return None
    return None
