from modules import run_modules

import urllib.request
import urllib.parse

def send_telegram(token, chat_id, text):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except Exception as e:
        print(f"[-] Telegram error: {e}")
        return False

import argparse
import subprocess
import json
import os
import sys

def run_synapse(target, ports, output_file="results.json", extra_args=None):
    cmd = ["./synapse", "-t", target, "-p", ports, "-o", output_file, "--json", "--quiet"]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[*] Running SYNapse: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and result.returncode != 1: # synapse returns 1 sometimes if errors occur but finishes. Let's be lenient or check output
        print(f"[-] SYNapse failed: {result.stderr}")

    results = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return results

def main():
    parser = argparse.ArgumentParser(description="SYNapse Python Wrapper")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan")
    parser.add_argument("-o", "--output", default="results.json", help="Output JSON file")
    parser.add_argument("--telegram-token", help="Telegram Bot Token")
    parser.add_argument("--telegram-chat", help="Telegram Chat ID")

    args, extra = parser.parse_known_args()

    if not os.path.exists("./synapse"):
        print("[-] SYNapse binary not found. Please compile it first.")
        sys.exit(1)

    results = run_synapse(args.target, args.ports, args.output, extra)
    print(f"[*] Found {len(results)} open ports.")

    for res in results:
        print(f"  - {res.get('ip')}:{res.get('port')} (State: {res.get('state')})")

    print("[*] Running post-scan modules...")
    findings = run_modules(results)

    if findings and args.telegram_token and args.telegram_chat:
        print("[*] Sending high/critical findings to Telegram...")
        msg = "SYNapse Module Findings:\n" + "\n".join(findings)
        send_telegram(args.telegram_token, args.telegram_chat, msg)

if __name__ == "__main__":
    main()
