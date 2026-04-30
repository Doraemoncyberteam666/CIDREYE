import paramiko

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("ubnt", "ubnt"),
]

def run(ip, port):
    if port != 22:
        return None
    for user, pwd in DEFAULT_CREDS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username=user, password=pwd, timeout=3, allow_agent=False, look_for_keys=False)
            client.close()
            return f"[CRITICAL] Default SSH credentials ({user}:{pwd}) found on {ip}"
        except paramiko.AuthenticationException:
            pass
        except Exception:
            break
    return None
