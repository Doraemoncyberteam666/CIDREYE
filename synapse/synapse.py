import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

import yaml

from py_modules import run_modules

DEFAULT_OUTPUT_FILE = "synapse_results.jsonl"
DEFAULT_COMMON_PORTS = "21,22,80,443,3306,5432,6379,139,445,8080,8443"
WEB_PORTS = {80, 81, 443, 591, 593, 8000, 8080, 8081, 8443, 8888, 3000, 5000, 7001}


def send_telegram(token, chat_id, text):
    if not text or not text.strip():
        print("[*] Skipping Telegram notification: empty message body.")
        return True

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except Exception as e:
        print(f"[-] Telegram error: {e}")
        return False


def load_config(config_path):
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _has_web_ports(ports: str) -> bool:
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_i, end_i = map(int, part.split("-", 1))
            except ValueError:
                continue
            if any(start_i <= p <= end_i for p in WEB_PORTS):
                return True
        else:
            try:
                if int(part) in WEB_PORTS:
                    return True
            except ValueError:
                continue
    return False


def _config_has_nuclei_tags(cfg):
    if cfg.get("nuclei_tags"):
        return True
    nuclei_cfg = cfg.get("nuclei", {})
    return bool(nuclei_cfg.get("tags"))


def run_synapse(binary_path, target, ports, output_file=DEFAULT_OUTPUT_FILE, extra_args=None, auto_cve_tag=True):
    cmd = [binary_path, "-t", target, "-p", ports, "-o", output_file, "--json", "--quiet"]
    if extra_args:
        cmd.extend(extra_args)
    if auto_cve_tag and _has_web_ports(ports) and not any(arg.startswith("--nuclei-tags") for arg in (extra_args or [])):
        cmd.extend(["--nuclei-tags", "cve"])

    if os.path.exists(output_file):
        os.remove(output_file)

    print(f"[*] Running SYNapse: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        print(f"[-] SYNapse failed: {result.stderr}")

    results = []
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return results


def main():
    parser = argparse.ArgumentParser(description="SYNapse Python Wrapper")
    parser.add_argument("-t", "--target", help="Target IP or CIDR")
    parser.add_argument("-p", "--ports", help="Ports to scan")
    parser.add_argument("-o", "--output", help="Output JSONL file")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML (default: config.yaml)")
    parser.add_argument("--telegram-token", help="Legacy wrapper telegram token")
    parser.add_argument("--telegram-chat", help="Legacy wrapper telegram chat ID")
    parser.add_argument("--telegram-chat-id", help="Telegram chat ID alias")
    args, extra = parser.parse_known_args()

    cfg = load_config(args.config)
    target = args.target or cfg.get("target")
    ports = args.ports or cfg.get("ports", DEFAULT_COMMON_PORTS)
    output = args.output or cfg.get("output", DEFAULT_OUTPUT_FILE)
    auto_cve_tag = cfg.get("auto_cve_tag_for_web", cfg.get("auto_cve_tag_for_http", False)) and not _config_has_nuclei_tags(cfg)

    if not target:
        print("[-] Target is required (via --target or config.yaml target).")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, "synapse")
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        print("[-] SYNapse binary not found or not executable. Please compile it first.")
        sys.exit(1)

    results = run_synapse(binary_path, target, ports, output, extra, auto_cve_tag)
    print(f"[*] Found {len(results)} open ports.")

    enabled_modules = cfg.get("modules", {"ftp": True, "smb": True, "ssh": True, "service_detect": True, "redis": True, "mysql": True, "postgres": True, "http": True})
    findings = run_modules(results, enabled_modules=enabled_modules)

    telegram = cfg.get("telegram", {})
    token = args.telegram_token or telegram.get("bot_token")
    chat = args.telegram_chat or args.telegram_chat_id or telegram.get("chat_id")
    alert_findings = [f for f in findings if f.startswith("[HIGH]") or f.startswith("[CRITICAL]")]
    if alert_findings and token and chat:
        msg = "SYNapse Module Findings:\n" + "\n".join(alert_findings)
        send_telegram(token, chat, msg)


if __name__ == "__main__":
    main()
