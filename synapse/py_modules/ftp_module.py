import ftplib

def run(ip, port):
    if port != 21:
        return None
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login()
        ftp.quit()
        return f"[CRITICAL] Anonymous FTP access allowed on {ip}"
    except Exception:
        return None
