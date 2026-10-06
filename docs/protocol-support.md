# Protocol support

Decoding is done by a single-pass, stateless, per-frame decoder (`Tracexy/Core/Protocol`). Every read
is bounds-checked; a truncated or malformed packet yields a partial decode, never a crash. The matrix
below reflects what the decoder actually produces today.

## Link and network layer (L2–L3)

| Protocol | Support |
|---|---|
| Ethernet II | Source/destination MAC, EtherType, dispatch to IPv4 / IPv6 / ARP; **802.1Q / 802.1ad VLAN tags** (up to two, QinQ) are walked to the encapsulated type and shown with priority and VLAN ID |
| Linux cooked SLL / SLL2 | Fixed header fields and exact byte ranges; bounded sender-address prefix; SLL2 capture-machine interface index; IPv4 / IPv6 / ARP handoff for supported payloads |
| Loopback / null (BSD) | 4-byte address-family header → IPv4 or IPv6 |
| Tunnel / raw IP (utun, VPN) | Auto-detects bare IPv4/IPv6 or a 4-byte address-family prefix |
| ARP | Operation (request/reply), sender/target MAC and IPv4; surfaced as a session |
| IPv4 | Version, header length, total length, fragment flags/offset, TTL, protocol, addresses, **and option TLVs** |
| IPv6 | Version, traffic class, flow label, next header, hop limit, addresses, **and the extension-header chain** (Hop-by-Hop, Routing, Fragment, AH, Destination Options, Mobility) |
| ICMP / ICMPv6 | Type + code with named types (echo, unreachable, neighbor/router discovery); surfaced as a session |

Linux cooked captures use link types 113 and 276. Unsupported payloads retain their complete
cooked header facts without inventing a session. Frame Relay, radiotap and Netlink payloads
are not decoded through the IP handoff. Interface indexes belong to the machine that recorded
the file, and are not mapped to interfaces on this Mac. Bare raw-IP link type 101 dispatches
by the actual IPv4 or IPv6 version.

The transport payload is bounded by the IP-declared length, so link-layer trailers (the zero
padding of sub-60-byte Ethernet frames, an FCS) are never read as TCP or UDP payload. A declared
length of zero (segmentation offload) or one beyond the captured bytes (snapshot truncation)
keeps the captured bytes.

**Fragmented IP datagrams are reassembled**, IPv4 and IPv6, as Wireshark does with reassembly on.
Every fragment stops at the IP layer (the frame list reads "Fragmented IP protocol (proto=UDP 17,
off=1480, ID=2001)"); the frame whose fragment completes the datagram carries a "Reassembled IPv4
Datagram" layer naming the fragment frames, then the transport and application layers decoded from
the rebuilt bytes. Those layers highlight no bytes, since they span several frames. That frame joins
its session, its findings cite it, and opening it from a citation reads its fragments again to show
the datagram. A session export, and Export Frames by session, keep every fragment frame. A datagram
is rebuilt only when every byte up to the end the last fragment declares is present: a missing or
snapshot-truncated fragment, overlapping fragments that disagree, a datagram over 65,535 bytes or 64
fragments, or one still incomplete 30 seconds (capture time) after its first fragment is not rebuilt,
and its fragments stay plain IP frames. At most 256 datagrams wait at once. The classic
pcap link-type word is masked to its low 16 bits, so a libpcap FCS-length hint does not hide the
link type.

## Transport layer (L4)

| Protocol | Support |
|---|---|
| TCP | Ports, sequence number, data offset, flags (SYN/ACK/PSH/FIN/RST), **and option TLVs** (MSS, Window Scale, SACK, SACK-permitted, Timestamps) |
| UDP | Source and destination ports |

The TCP acknowledgement number, window, and checksum fields are not surfaced. A one-byte probe
sent exactly one sequence number behind the expected sequence is classified as a keep-alive, not a
retransmission, and produces no finding.

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
  message, then releases the bytes. This automatic path does not reconstruct long-lived streams
  or application bodies. A separate, explicit **Follow Stream** action reads a stable saved or
  fully stopped capture on demand, with bounded output and visible coverage limits.
- **HTTP/2 is read in Follow Stream only.** A followed TCP stream that opens with the HTTP/2 connection
  preface, or that switches to HTTP/2 with an HTTP/1.1 `Upgrade: h2c`, is read into frames, streams and
  HPACK-decoded headers (see [usage](usage.md)); the automatic session path marks a session `http2` from the
  preface, a `101` agreeing to `h2c`, or a TLS 1.2 ALPN `h2`, and does not read frames.
  HTTP/2 inside encrypted TLS is not read. **No HTTP/3.**
- **WebSocket is read in Follow Stream only.** After an HTTP/1.1 `101` upgrade to `websocket`, a followed
  stream's frames are read into messages (unmasked, reassembled, and inflated when permessage-deflate was
  accepted); the automatic session path only marks the session `websocket` from the Upgrade.

For how these decoded values become sessions and correlated actions, see [architecture](architecture.md)
and [usage](usage.md).
