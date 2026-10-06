# ARP Traffic Analysis

## Objective
Analyze Address Resolution Protocol traffic and understand IP-to-MAC address resolution on the local network.

## Capture
- File: `normal-traffic.pcapng`
- Filter: `arp`
- Local host: `192.168.1.10`
- Gateway/router: `192.168.1.1`

## ARP Function
ARP maps an IPv4 address to a MAC address on a local Ethernet network. A typical request is:

```text
Who has 192.168.1.X? Tell 192.168.1.1
```

## Observations
The capture contains multiple ARP requests and responses, including requests for addresses such as `192.168.1.12`, `192.168.1.32`, `192.168.1.7`, `192.168.1.33`, and `192.168.1.10`.

The capture also contains ARP probes. ARP probes can be normal during address configuration and conflict detection.

The packet analyzer reported 237 ARP packets.

## Security Relevance
ARP is important to Blue Team monitoring because ARP spoofing/poisoning can be used to redirect local traffic. Useful warning signs include one IP address appearing with multiple MAC addresses, unexpected ARP replies, or frequent changes to the gateway MAC address.

The current capture does not by itself prove ARP spoofing.

## Useful Filters
```text
arp
arp.opcode == 1
arp.opcode == 2
```

## Conclusion
The ARP traffic provides a normal local-network baseline. A stronger spoofing investigation would compare gateway IP/MAC mappings over time or use a controlled lab demonstration.
