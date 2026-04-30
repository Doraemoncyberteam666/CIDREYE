import socket

def run(ip, port):
    if port != 3306:
        return None
    try:
        with socket.create_connection((ip, 3306), timeout=3) as s:
            banner = s.recv(256)
            if banner:
                return f"[INFO] MySQL/MariaDB handshake exposed on {ip}:3306"
    except Exception:
        return None
    return None
