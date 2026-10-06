# Network Traffic Analysis for Cybersecurity Monitoring and Threat Detection

## Project Overview

This project demonstrates a beginner-friendly Blue Team workflow for capturing, analyzing, and documenting network traffic using **Wireshark** and a small **Python packet-analysis script**.

The main objective is to understand normal network behavior, identify traffic that deserves investigation, and document findings using packet-level evidence.

## Project Objectives

- Capture real network traffic in an authorized environment.
- Understand common protocols such as DNS, TCP, UDP, ARP, and TLS.
- Use Wireshark display filters to isolate relevant packets.
- Establish a normal traffic baseline.
- Identify potentially unusual traffic patterns without incorrectly labeling normal traffic as malicious.
- Use Python to summarize packet, protocol, IP, and port statistics.
- Produce evidence and security recommendations suitable for a beginner Blue Team/SOC project.

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark | Packet capture and protocol analysis |
| Python 3 | Automated packet statistics |
| Git/GitHub | Project version control and presentation |
| Windows 11 | Analysis workstation |

## Project Workflow

```text
Project Objective
       ↓
Lab Setup
       ↓
Traffic Capture
       ↓
Protocol Analysis
       ↓
Filtering
       ↓
Normal Traffic Baseline
       ↓
Suspicious-Pattern Investigation
       ↓
Evidence & Findings
       ↓
Security Recommendations
       ↓
Final Report
```

## Capture

The main capture used for the baseline analysis is:

```text
captures/normal-traffic.pcapng
```

The capture contains **5,640 packets**.

The Python analysis reported:

```text
UDP                  : 3233
TCP                  : 2080
ARP                  : 237
Other/Unclassified   : 90
```

These protocol categories account for all **5,640 captured packets**.

## Wireshark Filters Used

### DNS

```text
dns
```

Used to inspect DNS queries and responses.

### TCP

```text
tcp
```

Used to inspect TCP communication.

### TCP SYN

```text
tcp.flags.syn == 1
```

Used to examine TCP connection attempts.

### TCP Reset

```text
tcp.flags.reset == 1
```

Used to investigate TCP RST packets.

### ARP

```text
arp
```

Used to inspect local IP-to-MAC address resolution.

### TLS

```text
tls
```

Used to examine encrypted TLS handshakes and application-data traffic.

## Key Findings

### DNS

The capture shows normal DNS queries and responses between the workstation `192.168.1.10` and the local DNS/router address `192.168.1.1`.

Examples include Microsoft connectivity and service domains. Some queries returned `No such name`; this is not sufficient by itself to classify the traffic as malicious.

Detailed analysis: [`analysis/dns-analysis.md`](analysis/dns-analysis.md)

### TCP

The capture contains normal TCP three-way handshakes, HTTPS connections on port `443`, an HTTP connectivity test on port `80`, TLS handshakes, and several TCP reset packets.

The presence of RST packets is treated as an investigation point rather than proof of an attack.

Detailed analysis: [`analysis/tcp-analysis.md`](analysis/tcp-analysis.md)

### ARP

The capture contains normal ARP requests, replies, and ARP probes on the local network.

No ARP spoofing conclusion is made from this baseline capture alone.

Detailed analysis: [`analysis/arp-analysis.md`](analysis/arp-analysis.md)

### Suspicious Traffic

TCP reset packets, repeated connections, unusual destinations, DNS anomalies, or unusual ARP behavior can be useful indicators for further investigation.

The project follows a defensive approach:

```text
Observe → Filter → Investigate → Correlate → Classify → Respond
```

Detailed analysis: [`analysis/suspicious-traffic.md`](analysis/suspicious-traffic.md)

## Python Packet Analyzer

The project includes a Python script:

```text
scripts/packet_analyzer.py
```

It summarizes:

- Total packets
- Protocol distribution
- Top source IP addresses
- Top destination IP addresses
- TCP destination ports
- UDP destination ports

Example output from the current capture:

```text
Total packets captured: 5640

UDP                  : 3233
TCP                  : 2080
ARP                  : 237
Other/Unclassified   : 90
```

The analyzer provides a quick statistical overview before detailed Wireshark investigation.

## Evidence

Recommended screenshots are stored in:

```text
screenshots/
```

Useful evidence includes:

- Overall Wireshark capture
- DNS-filtered traffic
- TCP traffic
- TCP SYN packets
- ARP traffic
- TLS traffic
- TCP RST packets
- Python analyzer output

## Security Recommendations

1. Establish a normal traffic baseline before investigating anomalies.
2. Monitor repeated connection attempts and unusual destination ports.
3. Review DNS requests for unusual domains or high-frequency patterns.
4. Monitor ARP activity for IP/MAC inconsistencies.
5. Correlate network events with endpoint and application logs.
6. Use firewall controls to restrict unnecessary traffic.
7. Preserve packet captures as evidence during investigations.
8. Avoid classifying a packet as malicious based on a single indicator.

## Limitations

This project uses a normal workstation traffic capture. Normal operating-system and application traffic can contain many remote connections, DNS failures, TCP resets, and broadcast/multicast packets.

Therefore, the project does not claim that any observed IP address or packet is malicious without additional evidence.

A future controlled lab capture can be added to demonstrate clearly suspicious traffic, such as authorized reconnaissance against a system owned or explicitly permitted for testing.

## Future Enhancements

- Add automated anomaly scoring.
- Generate HTML/CSV analysis reports.
- Add GeoIP enrichment for investigation.
- Integrate Suricata or Snort alerts.
- Compare normal and suspicious PCAP files automatically.
- Add a dashboard for protocol and IP statistics.
- Integrate the analysis with the Personal Firewall project.

## Conclusion

This project demonstrates a practical introductory Blue Team workflow using packet capture, protocol analysis, filtering, statistical analysis, evidence collection, and security recommendations.

It provides a foundation for further SOC-style monitoring and incident investigation work.

## Author

**D. Sathwik**

B.Tech Computer Science and Engineering (Cyber Security, Blockchain Technology)

## Project Type

**Blue Team / Network Security / Traffic Analysis**
