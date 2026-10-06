# TCP Traffic Analysis

## Objective
Analyze TCP connections, connection establishment, TLS communication, and TCP reset behavior.

## Capture
- File: `normal-traffic.pcapng`
- Local host: `192.168.1.10`
- Filters: `tcp`, `tcp.flags.syn == 1`, `tcp.flags.reset == 1`

## TCP Three-Way Handshake
The capture shows normal TCP connection establishment:

```text
Client -> Server  SYN
Server -> Client  SYN, ACK
Client -> Server  ACK
```

Many connections use destination port `443`, which is commonly used for HTTPS.

## TLS Traffic
The capture contains TLS messages including Client Hello, Server Hello, Certificate, Key Exchange, Encrypted Handshake Message, and Application Data. An observed SNI includes `geo.prod.do.dsp.mp.microsoft.com`; other traffic includes `login.live.com`.

## HTTP Traffic
A small HTTP exchange on port 80 is visible, including `GET /connecttest.txt` followed by `HTTP/1.1 200 OK`, consistent with a connectivity test.

## TCP SYN Analysis
Using `tcp.flags.syn == 1` shows connection attempts from the workstation to remote systems. A typical example is:

```text
192.168.1.10:<ephemeral> -> remote:443  SYN
remote:443 -> 192.168.1.10:<ephemeral>  SYN, ACK
192.168.1.10:<ephemeral> -> remote:443  ACK
```

## TCP Reset Analysis
Using `tcp.flags.reset == 1` shows several `[RST, ACK]` packets. TCP resets can occur for legitimate reasons such as connection termination, refused connections, or interrupted application sessions. RST packets alone do not prove an attack.

## Blue Team Relevance
TCP analysis can identify unexpected connection attempts, repeated SYN packets, unusual ports, repeated resets, and possible reconnaissance patterns when several indicators occur together.

## Conclusion
The capture demonstrates normal TCP, HTTP, and TLS behavior plus some resets. The resets should be treated as investigation points rather than automatically classified as malicious.
