from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
from collections import Counter
from pathlib import Path

# Locate the PCAP relative to this script
BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_FILE = BASE_DIR / "captures" / "normal-traffic.pcapng"

print("=" * 65)
print("              NETWORK TRAFFIC ANALYSIS")
print("=" * 65)

print(f"\nReading capture: {PCAP_FILE}")

packets = rdpcap(str(PCAP_FILE))

total_packets = len(packets)

print(f"\nTotal packets captured: {total_packets}")

# Counters
protocols = Counter()
source_ips = Counter()
destination_ips = Counter()

tcp_destination_ports = Counter()
udp_destination_ports = Counter()

# Analyze every packet
for packet in packets:

    # ARP
    if ARP in packet:
        protocols["ARP"] += 1

    # IP traffic
    elif IP in packet:

        source_ips[packet[IP].src] += 1
        destination_ips[packet[IP].dst] += 1

        # TCP
        if TCP in packet:
            protocols["TCP"] += 1
            tcp_destination_ports[packet[TCP].dport] += 1

        # UDP
        elif UDP in packet:
            protocols["UDP"] += 1
            udp_destination_ports[packet[UDP].dport] += 1

        # ICMP
        elif ICMP in packet:
            protocols["ICMP"] += 1

        # Other IP protocol
        else:
            protocols["Other/Unclassified"] += 1

    # Non-IP and non-ARP traffic
    else:
        protocols["Other/Unclassified"] += 1


# ---------------------------------------------------------
# Protocol Distribution
# ---------------------------------------------------------

print("\n--- Protocol Distribution ---")

for protocol, count in protocols.most_common():
    print(f"{protocol:20} : {count}")

protocol_total = sum(protocols.values())

print("-" * 45)
print(f"{'Protocol categories total':20} : {protocol_total}")
print(f"{'Total packets':20} : {total_packets}")

if protocol_total == total_packets:
    print("Status: PASS - all packets classified.")
else:
    print("Status: CHECK - packet classification mismatch.")


# ---------------------------------------------------------
# Top Source IP Addresses
# ---------------------------------------------------------

print("\n--- Top Source IP Addresses ---")

for ip, count in source_ips.most_common(10):
    print(f"{ip:20} : {count}")


# ---------------------------------------------------------
# Top Destination IP Addresses
# ---------------------------------------------------------

print("\n--- Top Destination IP Addresses ---")

for ip, count in destination_ips.most_common(10):
    print(f"{ip:20} : {count}")


# ---------------------------------------------------------
# TCP Destination Ports
# ---------------------------------------------------------

print("\n--- Top TCP Destination Ports ---")

for port, count in tcp_destination_ports.most_common(10):
    print(f"Port {port:<10} : {count}")


# ---------------------------------------------------------
# UDP Destination Ports
# ---------------------------------------------------------

print("\n--- Top UDP Destination Ports ---")

for port, count in udp_destination_ports.most_common(10):
    print(f"Port {port:<10} : {count}")


print("\nAnalysis completed successfully.")
print("=" * 65)