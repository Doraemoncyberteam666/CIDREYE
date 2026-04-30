import socket


def run(ip, port):
    if port != 6379:
        return None
    try:
        with socket.create_connection((ip, 6379), timeout=3) as s:
            s.sendall(b"PING\r\n")
            data = s.recv(128)
            if b"+PONG" in data:
                return f"[HIGH] Redis responds to unauthenticated PING on {ip}:6379"
    except OSError:
        return None
    return None
