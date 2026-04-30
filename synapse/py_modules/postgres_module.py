import socket
import struct

def run(ip, port):
    if port != 5432:
        return None
    try:
        with socket.create_connection((ip, 5432), timeout=3) as s:
            msg = struct.pack('!I', 8) + struct.pack('!I', 80877103)
            s.sendall(msg)
            resp = s.recv(1)
            if resp in (b'S', b'N'):
                return f"[INFO] PostgreSQL server responded to SSLRequest on {ip}:5432"
    except Exception:
        return None
    return None
