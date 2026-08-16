# Protocol support

Decoding is done by a single-pass, stateless, per-frame decoder (`Tracexy/Core/Protocol`). Every read
is bounds-checked; a truncated or malformed packet yields a partial decode, never a crash. The matrix
below reflects what the decoder actually produces today.

## Link and network layer (L2–L3)

| Protocol | Support |
|---|---|
| Ethernet II | Source/destination MAC, EtherType, dispatch to IPv4 / IPv6 / ARP |
| Loopback / null (BSD) | 4-byte address-family header → IPv4 or IPv6 |
| Tunnel / raw IP (utun, VPN) | Auto-detects bare IPv4/IPv6 or a 4-byte address-family prefix |
| ARP | Operation (request/reply), sender/target MAC and IPv4; surfaced as a session |
| IPv4 | Version, header length, total length, TTL, protocol, addresses, **and option TLVs** |
| IPv6 | Version, traffic class, flow label, next header, hop limit, addresses, **and the extension-header chain** (Hop-by-Hop, Routing, Fragment, AH, Destination Options, Mobility) |
| ICMP / ICMPv6 | Type + code with named types (echo, unreachable, neighbor/router discovery); surfaced as a session |

## Transport layer (L4)

| Protocol | Support |
|---|---|
| TCP | Ports, sequence number, data offset, flags (SYN/ACK/PSH/FIN/RST), **and option TLVs** (MSS, Window Scale, SACK, SACK-permitted, Timestamps) |
| UDP | Source and destination ports |

The TCP acknowledgement number, window, and checksum fields are not surfaced.

## Application layer

Application-layer decode is **naming-level** — enough to identify and label a conversation, not a full
field-by-field parse.

| Protocol | Support | Not covered |
|---|---|---|
| DNS | Question name; answer records A, AAAA, CNAME, NS, PTR, MX, TXT, SRV, SOA (others shown by type); compression pointers; DNS-over-TCP length prefix | Full record-set decode; DNSSEC |
| TLS | Record metadata for all coalesced records in a payload; ClientHello (offered version, cipher-suite count, **SNI**, **ALPN**) and ServerHello (chosen version and cipher); bounded per-direction TCP prefix recovery when the first record is segmented | **No decryption**; no certificate parsing; no application data; no general stream tracking |
| HTTP/1 | **Request-line recognition only** — the first line (method / target / version) plus the `Host` header | Full header set, response/status parsing, bodies, chunked/compressed content |
| STUN | Detected by the magic cookie (port-independent): message type, length, magic cookie, transaction ID, and a bounds-checked walk of the RFC 5389 attribute TLVs — attributes named where known (else an honest hex type), with MAPPED-ADDRESS / XOR-MAPPED-ADDRESS **IPv4** reflexive `address:port` decoded when fully present | IPv6 reflexive addresses (metadata-only); attribute value bodies beyond addresses; ICE negotiation and TURN allocation state |
| QUIC | **Long-header metadata only** — conservatively detected on UDP/443 from a complete clear-text prefix, valid fixed-bit semantics, and bounded connection IDs: packet type (Initial / 0-RTT / Handshake / Retry for v1, raw type otherwise), version (version 0 → Version Negotiation), and the destination/source connection IDs (≤ 20 bytes) | Frames and any encrypted payload; short or malformed headers (stay UDP); 0-RTT/handshake decryption; HTTP/3 |

## Explicitly not implemented

- **No decryption** of TLS or QUIC. Tracexy reads only what is on the wire in the clear.
- **No general TCP connection/reassembly engine.** Session accumulation keeps only a bounded 16 KiB
  prefix per direction until it can classify the first TLS record, HTTP header, or DNS-over-TCP
  message, then releases the bytes. It does not reconstruct long-lived streams or application bodies.
- **No deep HTTP/2** parsing, **no HTTP/3**, and **no WebSocket** decode. (`http2` and `websocket`
  exist as protocol labels for grouping, but the decoder never produces them from bytes.)

For how these decoded values become sessions and correlated actions, see [architecture](architecture.md)
and [usage](usage.md).
