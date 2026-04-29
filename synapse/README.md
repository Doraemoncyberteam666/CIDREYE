# SYNapse

A high-performance, non-root, userland TCP scanner built in pure Go. Inspired by masscan, it is designed for rapid and concurrent scanning utilizing only standard OS networking `net.Dial`, without needing raw sockets or `pcap`.

## Features
- **High Concurrency**: Goroutine-based bounded worker pool capable of thousands of concurrent connections.
- **No Root Required**: Built purely on standard TCP dialing, avoiding the need for elevated privileges or raw socket access.
- **Multiple Target Inputs**: Supports single IPs, CIDR ranges, and files containing lists of IPs/CIDRs.
- **Flexible Port Formats**: Single port (`80`), comma-separated lists (`80,443`), ranges (`1-1000`), and built-in aliases for `top100` and `top1000` ports.
- **Target Exclusion**: Exclude specific IPs, CIDRs, or lists from files using `-e` or `--exclude`.
- **Rate Limiting**: Configurable maximum connections per second.
- **Output Formats**: Standard plain text or JSON output, with optional file saving.
- **Optional Banner Grabbing**: Identifies basic banners (e.g., SSH, HTTP) from open ports.
- **Retries**: Specify the number of retries per port scan using the `--retries` flag.
- **Progress Tracking**: Periodic progress updates in the console via the `--progress` flag.
- **Optional Nuclei Pipeline**: Run post-scan nuclei checks using automatic technology detection (`-as`), optional tag filtering, minimum severity filtering, text-file output, and Telegram delivery.

## Installation

```bash
go build -o synapse ./cmd/synapse
```

## Usage

```bash
# Basic scan of a single IP
./synapse -t 192.168.1.1 -p 80,443

# Scan a CIDR range with custom concurrency and timeout
./synapse -t 10.0.0.0/24 -p 1-1000 -c 5000 --timeout 500

# Scan from a file containing targets, save as JSON, and enable banner grabbing
./synapse -t targets.txt -p 22,80 -o results.json --json --banner

# Scan using top1000 ports, excluding specific IPs, with retries and progress tracking
./synapse -t 10.0.0.0/16 -p top1000 -e exclusions.txt --retries 1 --progress

# Run optional nuclei pipeline with technology detection and minimum severity HIGH
./synapse -t 192.168.1.0/24 -p 80,443 --nuclei --nuclei-min-severity high --nuclei-tags cve,rce --nuclei-output nuclei-results.txt
```

### Configuration via YAML

You can also use a YAML configuration file to set defaults:

```yaml
target: "192.168.1.0/24"
ports: "80,443,8080"
exclude: "192.168.1.5"
concurrency: 2000
rate_limit: 5000
timeout_ms: 800
retries: 1
progress: true
json: true
banner: true
nuclei:
  enabled: true
  tags: "cve,rce"
  min_severity: "high"
  output_file: "nuclei-results.txt"
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
```

Run with the config file:
```bash
./synapse -config config.yaml
```

CLI flags take precedence over the YAML configuration.

## Performance Target
SYNapse is tuned for minimal memory allocation and fast throughput. Depending on your system and network configuration, it can handle a massive number of concurrent connections (50k-200k+/sec). You may need to increase your OS file descriptor limits (`ulimit -n`) for optimal performance on large ranges.
