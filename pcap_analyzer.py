import argparse
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, rdpcap
from scapy.error import Scapy_Exception

def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number

def main():
    parser = argparse.ArgumentParser(
        description="Summarize a PCAP and flag possible TCP SYN port scans."
    )
    parser.add_argument("pcap", type=Path, help="Path to a .pcap or .pcapng file")
    parser.add_argument(
        "--scan-port-threshold",
        type=positive_int,
        default=20,
        help="Distinct destination ports needed to trigger an alert (default: 20)",
    )
    args = parser.parse_args()

    if not args.pcap.is_file():
        parser.error(f"PCAP file not found: {args.pcap}")

    try:
        packets = rdpcap(str(args.pcap))
    except (OSError, Scapy_Exception) as exc:
        parser.exit(1, f"Could not read PCAP file {args.pcap}: {exc}\n")

    protocol_counts = Counter()
    syn_ports_by_pair = defaultdict(set)
    reported_scans = set()
    ip_count = 0

    for packet in packets:
        if IP not in packet:
            continue

        ip_count += 1
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol_counts["TCP"] += 1
            tcp = packet[TCP]
            flags = int(tcp.flags)

            # Count initial SYN packets, not SYN-ACK responses.
            if flags & 0x02 and not flags & 0x10:
                pair = (source_ip, destination_ip)
                ports = syn_ports_by_pair[pair]
                ports.add(tcp.dport)

                if (
                    len(ports) >= args.scan_port_threshold
                    and pair not in reported_scans
                ):
                    reported_scans.add(pair)
                    print(
                        f"ALERT: Possible TCP SYN port scan "
                        f"({len(ports)} distinct ports), "
                        f"{source_ip} -> {destination_ip}"
                    )

        elif UDP in packet:
            protocol_counts["UDP"] += 1
        elif ICMP in packet:
            protocol_counts["ICMP"] += 1
        else:
            protocol_counts["Other"] += 1

    print(f"Read {len(packets)} packets; analyzed {ip_count} IPv4 packets.")
    if protocol_counts:
        print("IPv4 protocols: " + ", ".join(
            f"{protocol}={count}"
            for protocol, count in sorted(protocol_counts.items())
        ))
    else:
        print("No IPv4 packets found in the capture.")

    print("Possible-scan alerts are heuristic, not proof of an attack.")

if __name__ == "__main__":
    main()