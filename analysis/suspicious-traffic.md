# Suspicious Traffic Analysis

## Objective

Identify network patterns that deserve investigation and distinguish suspicious indicators from confirmed malicious activity.

## Capture

- **File:** `normal-traffic.pcapng`
- **Local host:** `192.168.1.10`
- **Filters used:** `tcp.flags.reset == 1`, `tcp.flags.syn == 1`, `dns`, `arp`

> **Important:** The current capture represents normal/baseline traffic. The observations below are investigation points and are **not** classified as confirmed attacks.

## Observed Indicators

### 1. TCP Reset Packets

The `tcp.flags.reset == 1` filter shows multiple TCP reset (`RST`) packets involving the local host and remote systems, including connections associated with destination port `443`.

TCP resets can occur for many legitimate reasons, such as closed connections, application behavior, connection timeouts, or interrupted sessions. Therefore, repeated RST packets alone are **not proof of an attack**.

**Blue Team interpretation:**  
Treat repeated or unusual RST patterns as an investigation point and correlate them with timestamps, destination IPs, applications, and other network events.

### 2. Multiple HTTPS Connections

The workstation communicates with multiple remote systems over TCP port `443`.

This is expected on a modern Windows system because browsers, operating-system services, security tools, update services, and other applications commonly communicate with multiple HTTPS endpoints.

**Blue Team interpretation:**  
Multiple HTTPS connections should not be classified as malicious without additional evidence such as unusual destinations, abnormal connection frequency, suspicious domains, endpoint alerts, or other correlated indicators.

### 3. DNS Activity

The capture contains multiple DNS requests, including requests associated with Microsoft-related services and local-network names. Some DNS requests return `No such name` (NXDOMAIN).

Failed DNS lookups can occur because of mistyped names, unavailable services, software discovery mechanisms, or normal application behavior. They are **not inherently malicious**.

**Blue Team interpretation:**  
DNS activity becomes more interesting when combined with indicators such as high-frequency queries, suspicious domains, algorithmically generated domain patterns, unusual query types, or connections to suspicious destinations.

### 4. ARP Activity

The capture contains normal ARP requests, responses, and probes.

ARP traffic is expected on a local Ethernet network because hosts use ARP to resolve IP addresses to MAC addresses and to check local-network connectivity.

**Blue Team interpretation:**  
ARP spoofing should not be concluded from ordinary ARP traffic alone. Stronger evidence would include conflicting IP-to-MAC mappings, unexpected ARP replies, repeated unsolicited ARP announcements, or corroborating alerts from other monitoring sources.

## Blue Team Classification Workflow

Use the following evidence-based workflow:

```text
Observed traffic
       ↓
Identify unusual pattern
       ↓
Collect packet-level evidence
       ↓
Compare with normal baseline
       ↓
Investigate context
       ↓
Correlate with other evidence
       ↓
Classify event
       ↓
Recommend response
```

### Classification Principle

A useful Blue Team classification model is:

| Classification | Meaning |
|---|---|
| **Normal** | Expected network behavior with no meaningful anomaly |
| **Investigation Point** | Pattern is unusual or noteworthy and requires additional context |
| **Suspicious** | Multiple indicators suggest potentially malicious behavior |
| **Confirmed Malicious** | Sufficient evidence or corroborating alerts confirm malicious activity |

For this capture, the TCP RST packets, DNS failures, multiple HTTPS connections, and ARP activity are best treated as **normal or investigation points**, not confirmed malicious events.

## Controlled Lab Demonstration

A separate suspicious-traffic capture can strengthen the project by demonstrating how a Blue Team analyst identifies an abnormal pattern.

Only perform testing against systems that you own or are explicitly authorized to test.

For example, an isolated lab can generate a controlled pattern of repeated connection attempts or a port-scan-like pattern. The purpose is to observe the resulting packets in Wireshark and document the detection process.

```text
Authorized Lab Activity
        ↓
Generate Controlled Traffic
        ↓
Capture Packets
        ↓
Identify Pattern
        ↓
Compare With Normal Baseline
        ↓
Document Detection
```

Do **not** scan, probe, or test external systems without authorization.

### Defensive Detection Heuristic

```text
IF one internal host generates an unusually high number
of connection attempts in a short period
AND the attempts target many ports or hosts
THEN flag the activity for investigation.
```

This is a **detection heuristic**, not a definitive malware classifier. Thresholds should be adapted to the environment and normal baseline.

## Evidence to Record

| Field | Example |
|---|---|
| Timestamp | Wireshark packet timestamp |
| Source IP | `192.168.1.10` |
| Destination IP | Remote IP |
| Protocol | TCP |
| Source Port | Ephemeral port |
| Destination Port | `443` |
| TCP Flags | `RST, ACK` / `SYN` |
| Observation | Repeated connection/reset pattern |
| Classification | Normal / Needs investigation |
| Evidence | Wireshark screenshot + packet number |

When documenting an actual finding, record the exact packet number and timestamp so another analyst can reproduce the observation.

## Recommendations

1. Maintain a baseline of normal network traffic.
2. Monitor repeated or unusually frequent connection attempts.
3. Investigate unexpected destination ports and destinations.
4. Monitor DNS for unusual domain and query patterns.
5. Monitor ARP for unexpected or conflicting IP/MAC mappings.
6. Correlate network events with endpoint and application logs.
7. Use firewall rules to restrict unnecessary network communication.
8. Preserve relevant packet captures as investigation evidence.
9. Record timestamps, packet numbers, IP addresses, ports, and protocol details for important events.
10. Avoid classifying isolated network anomalies as attacks without supporting evidence.

## Final Assessment

The current `normal-traffic.pcapng` capture successfully demonstrates DNS, TCP, TLS, HTTP, ARP, and other network activity and provides a useful normal-traffic baseline.

The observed TCP RST packets, multiple HTTPS connections, failed DNS lookups, and ARP traffic are **not sufficient by themselves to confirm malicious activity**. They are useful examples for demonstrating the Blue Team process of observation, investigation, contextual analysis, and evidence-based classification.

## Conclusion

This analysis demonstrates a beginner-friendly Blue Team workflow:

```text
Capture
  ↓
Filter
  ↓
Analyze
  ↓
Identify Indicators
  ↓
Investigate Context
  ↓
Avoid False Positives
  ↓
Document Evidence
  ↓
Recommend Defensive Action
```

The project currently establishes a normal network baseline. Adding a separate, authorized controlled suspicious-traffic capture as a future enhancement would further demonstrate anomaly detection and investigation skills without misrepresenting normal traffic as malicious.
