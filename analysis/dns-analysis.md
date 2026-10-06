# DNS Traffic Analysis

## Objective
Analyze DNS traffic in Wireshark and understand how the workstation resolves domain names.

## Capture
- File: `normal-traffic.pcapng`
- Local host: `192.168.1.10`
- DNS server/router: `192.168.1.1`
- Filter: `dns`

## Observations
The capture contains DNS queries and responses between `192.168.1.10` and `192.168.1.1`. Examples include `dns.msftncsi.com`, `www.msftconnecttest.com`, `geo.prod.do.dsp.mp.microsoft.com`, `login.live.com`, `mobile.events.data.microsoft.com`, `activity.windows.com`, and `client.wns.windows.com`.

The capture also contains queries such as `wpap.alphionsee.in` that receive `No such name` responses. A failed DNS lookup alone is not evidence of malicious activity.

## Request/Response Flow
```text
192.168.1.10 -> 192.168.1.1   DNS Query
192.168.1.1  -> 192.168.1.10  DNS Response
```

Normal DNS exchanges commonly use UDP port 53.

## Blue Team Relevance
DNS analysis can help analysts identify contacted domains, unusual domain patterns, repeated failed lookups, and possible indicators of compromise when correlated with other events.

## Conclusion
The DNS traffic provides a useful normal baseline. The observed queries are consistent with normal operating-system and application activity. Further investigation should consider context rather than treating individual domains or failed lookups as malicious.
