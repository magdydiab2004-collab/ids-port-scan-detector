From scapy.all import Ether, IP, TCP, wrpcap

packets = []

# 1. SHOULD ALERT: 10.0.0.5 SYN-scans ports 1-100 on 10.0.0.10
for port in range(1, 101):
    packets.append(Ether()/IP(src="10.0.0.5", dst="10.0.0.10")/TCP(sport=40000, dport=port, flags="S"))

# 2. should NOT alert: only 10 ports (below threshold of 20)
for port in range(1, 11):
    packets.append(Ether()/IP(src="10.0.0.6", dst="10.0.0.10")/TCP(sport=41000, dport=port, flags="S"))

# 3. should NOT alert: 50 SYN-ACK replies (server answering, not scanning)
for port in range(1000, 1050):
    packets.append(Ether()/IP(src="10.0.0.20", dst="10.0.0.5")/TCP(sport=port, dport=50000, flags="SA"))

# 4. should NOT alert: many SYNs but all to port 443 (normal browsing)
for i in range(50):
    packets.append(Ether()/IP(src="10.0.0.7", dst="10.0.0.30")/TCP(sport=42000 + i, dport=443, flags="S"))

wrpcap("test_traffic.pcap", packets)
print(f"Wrote {len(packets)} packets")
