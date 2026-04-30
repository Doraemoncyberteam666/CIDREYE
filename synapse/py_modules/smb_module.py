def run(ip, port):
    try:
        import smbclient
    except Exception:
        return None
    if port not in (139, 445):
        return None
    for smb_port in (445, 139):
        try:
            smbclient.ClientConfig(username="guest", password="")
            shares = smbclient.list_shares(ip, port=smb_port, timeout=5)
            if shares:
                return f"[HIGH] Anonymous SMB shares found on {ip}: {', '.join([s.name for s in shares])}"
        except Exception:
            pass
    return None
