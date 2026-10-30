# TCP SYN Port Scan Detector

A lightweight network intrusion detection system (IDS) written in Python. It reads a packet capture (`.pcap`), summarizes the traffic by protocol, and raises an alert when a source IP sends connection attempts (SYN packets) to many different ports on the same target, which is the signature of a TCP SYN port scan.

Built as a college project in Ubuntu on WSL using `tcpdump` for capture and [Scapy](https://scapy.net/) for analysis.

> **Full write-up:** [`docs/IDS_Project_Report.pdf`](docs/IDS_Project_Report.pdf) explains the code block by block, with the setup commands and test results.

## How it works

A normal client talks to a handful of ports on a server. A scanner probes many ports quickly to find open services. The detector tracks, for every (source IP, destination IP) pair, the set of destination ports that received an initial SYN. When that set reaches a threshold (default: 20), it prints an alert, once per pair.

Key details:

- Only **initial SYN packets** count (SYN set, ACK not set), so server SYN-ACK replies don't cause false alarms.
- Ports are stored in a **set**, so 100 SYNs to port 443 count as one port.
- The threshold is adjustable with `--scan-port-threshold`.



## Setup

Tested on Ubuntu (WSL). 

```bash
sudo apt update
sudo apt install tcpdump python3-pip nmap
pip install -r requirements.txt
```

If pip reports an "externally managed environment", use a virtual environment (`python3 -m venv venv && source venv/bin/activate`) or `sudo apt install python3-scapy`.

## Usage

Analyze a capture:

```bash
python3 pcap_analyzer.py capture.pcap
python3 pcap_analyzer.py capture.pcap --scan-port-threshold 5
```

Capture your own traffic (needs root; find your interface with `ip link`):

```bash
sudo ./scripts/capture.sh eth0 captures/browsing.pcap
# Ctrl+C to stop
```

## Demo and tests

An IDS has to be tested on traffic that *should* trigger it and traffic that *shouldn't*. `tests/make_test_pcap.py` crafts four labeled cases:

| Case | Traffic | Expected |
|------|---------|----------|
| 1 | `10.0.0.5` sends SYNs to 100 different ports | **Alert** |
| 2 | `10.0.0.6` sends SYNs to 10 ports | No alert (below threshold) |
| 3 | `10.0.0.20` sends 50 SYN-ACK packets | No alert (server replies) |
| 4 | `10.0.0.7` sends 50 SYNs, all to port 443 | No alert (normal browsing) |

Run everything:

```bash
bash scripts/run_demo.sh
```

Output at the default threshold (one true positive, three true negatives):

```
ALERT: Possible TCP SYN port scan (20 distinct ports), 10.0.0.5 -> 10.0.0.10
Read 210 packets; analyzed 210 IPv4 packets.
IPv4 protocols: TCP=210
Possible-scan alerts are heuristic, not proof of an attack.
```

With `--scan-port-threshold 5`, the 10-port probe from `10.0.0.6` is flagged too. This shows the core IDS trade-off: a lower threshold catches smaller scans but risks more false positives; a higher one reduces false alarms but can miss quiet scans.

### Test against a real scan

Only scan machines you own.

```bash
# Terminal 1
sudo tcpdump -i lo -w captures/real_scan.pcap

# Terminal 2
sudo nmap -sS -p 1-200 127.0.0.1

# Back in Terminal 1: Ctrl+C, then
python3 pcap_analyzer.py captures/real_scan.pcap
```

## Limitations

- **No time window:** ports are counted across the whole capture, so long captures of normal traffic could false-alarm, while real scans happen in seconds.
- **IPv4 only:** IPv6 packets are skipped.
- **SYN scans only:** no detection of FIN/NULL/Xmas scans, UDP scans, scans of one port across many hosts, or SYN floods.
- **Offline analysis:** reads finished pcaps rather than monitoring live traffic, and loads the whole file into memory.
- **Heuristic:** an alert is a lead to investigate, not proof of an attack.

## Roadmap

- [ ] Time-window detection (N ports within X seconds)
- [ ] SYN flood rule (many SYNs to the same port in a short window)
- [ ] IPv6 support
- [ ] Detection of FIN/NULL/Xmas scans

## Responsible use

Capture and scan only networks and systems you own or have explicit permission to test. Don't commit real packet captures to the repository, as they can contain private traffic (`.gitignore` excludes them).
