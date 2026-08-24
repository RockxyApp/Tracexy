import Foundation
@testable import Tracexy

// MARK: - ReplayCorpus

/// A fixed, deterministic replay corpus for N1D.
///
/// **Generated-only provenance.** Every byte in this file — every frame and every
/// capture-file envelope — is synthesised here by repository-owned test code. No
/// `.pcap`/`.pcapng` file, imported/recorded traffic, credential, device identity
/// or process name is committed or read. Addresses come only from the reserved
/// documentation ranges (RFC 5737 IPv4 `192.0.2.0/24`, `198.51.100.0/24`,
/// `203.0.113.0/24`; RFC 3849 IPv6 `2001:db8::/32`) and every hostname uses a
/// reserved example label (RFC 2606 `*.example`). Timestamps are fixed integer
/// seconds from a single frozen epoch, so ordering and every derived duration /
/// latency are reproducible run to run and byte-order to byte-order.
///
/// The corpus is intentionally compact and *current-decoder truthful*: it exercises
/// only what the direct `PacketDecoder` actually recognises today (Ethernet/ARP,
/// IPv4/IPv6, ICMP, TCP/UDP, DNS, TLS incl. a first-record split across TCP
/// segments, HTTP/1 recognition, STUN and conservative QUIC long-header metadata).
/// It makes no HTTP/2, HTTP/3, WebSocket, gRPC or deep-QUIC claim.
enum ReplayCorpus {
    // MARK: Internal

    /// One generated frame: its bytes, its whole-second offset from ``epoch``, and
    /// the intrinsic link type it should be attributed to (used by the mixed-DLT
    /// pcapng corpus; the classic conversation is all Ethernet).
    struct Frame {
        let bytes: [UInt8]
        let offsetSeconds: Int
        let linkType: UInt32

        var timestamp: Date {
            ReplayCorpus.epoch.addingTimeInterval(TimeInterval(offsetSeconds))
        }
    }

    /// Classic-`.pcap` global-header variants, so the same ordered frames can be
    /// written little/big endian and micro/nanosecond and prove they decode to the
    /// identical session semantics.
    enum ClassicVariant: CaseIterable {
        case littleMicro
        case bigMicro
        case littleNano
        case bigNano

        // MARK: Internal

        var isLittle: Bool {
            switch self {
            case .littleMicro,
                 .littleNano: true
            case .bigMicro,
                 .bigNano: false
            }
        }

        var isNano: Bool {
            switch self {
            case .littleNano,
                 .bigNano: true
            case .littleMicro,
                 .bigMicro: false
            }
        }
    }

    // MARK: The TCP connection corpus

    /// One step of the generated TCP connection corpus: a single segment's
    /// endpoints, ports, flags, sequence/acknowledgement numbers, payload length
    /// and capture offset. Payload *content* is deterministic filler — only its
    /// length feeds the sequence fold — so the corpus stays licence-safe.
    struct TCPStep {
        let src: String
        let dst: String
        let srcPort: UInt16
        let dstPort: UInt16
        let flags: UInt8
        let seq: UInt32
        let ack: UInt32
        let payloadLength: Int
        let offset: Int
    }

    // MARK: Fixed provenance

    /// The single frozen capture epoch shared by every frame. Chosen well within
    /// `UInt32` seconds so a classic-`.pcap` record header can hold it in either
    /// byte order.
    static let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: The primary conversation corpus

    /// The fixed, ordered conversation. Frames are in capture order. ARP and ICMP
    /// both use the decoder's address-pair/port-zero session keys. The TLS
    /// ClientHello is deliberately split across two TCP segments of the same
    /// five-tuple as the preceding SYN, to exercise first-record recovery.
    static func conversation() -> [Frame] {
        let clientV4 = "198.51.100.10"
        let dnsServer = "203.0.113.53"
        let tlsServer = "203.0.113.5"
        let httpServer = "203.0.113.6"
        let stunServer = "192.0.2.9"
        let quicServer = "192.0.2.10"

        var frames: [Frame] = []

        // 1. ARP request (address-pair/port-zero session #1).
        frames.append(eth(PacketBuilder.arpRequestFrame(senderIP: clientV4, targetIP: "198.51.100.1"), 1))

        // 2. ICMP echo request (address-pair/port-zero session #2).
        frames.append(eth(PacketBuilder.icmpEchoRequestFrame(src: clientV4, dst: tlsServer), 2))

        // 3/4. DNS query + response over IPv4/UDP → session #3.
        frames.append(eth(
            PacketBuilder.dnsQueryFrame(name: "one.example", src: clientV4, dst: dnsServer, srcPort: 54_000), 3
        ))
        frames.append(eth(
            PacketBuilder.dnsResponseFrame(
                name: "one.example", answers: [tlsServer], src: dnsServer, dst: clientV4, dstPort: 54_000
            ), 4
        ))

        // 5. TCP SYN opens the TLS five-tuple → session #4 (representative, for now).
        frames.append(eth(
            PacketBuilder.tcpSynFrame(src: clientV4, dst: tlsServer, srcPort: 52_344, dstPort: 443), 5
        ))

        // 6/7. TLS ClientHello split across two TCP segments of that same five-tuple.
        let hello = PacketBuilder.tlsClientHello(sni: "secure.example")
        let cut = hello.count / 2
        frames.append(tcpSegment(
            payload: Array(hello[..<cut]), sequence: 1_000, offset: 6,
            src: clientV4, dst: tlsServer, srcPort: 52_344, dstPort: 443
        ))
        frames.append(tcpSegment(
            payload: Array(hello[cut...]), sequence: 1_000 + UInt32(cut), offset: 7,
            src: clientV4, dst: tlsServer, srcPort: 52_344, dstPort: 443
        ))

        // 8. HTTP/1 request in one segment → session #5.
        frames.append(eth(
            PacketBuilder.httpRequestFrame(host: "http.example", path: "/health", src: clientV4, dst: httpServer), 8
        ))

        // 9. STUN binding request on ICE-style ports → session #6.
        frames.append(eth(stunBindingRequest(src: clientV4, dst: stunServer), 9))

        // 10. QUIC Initial long header on UDP/443 → session #7.
        frames.append(eth(quicInitial(src: clientV4, dst: quicServer), 10))

        // 11/12. DNS query + response over IPv6/UDP → session #8.
        frames.append(eth(
            ipv6DNSQuery(name: "six.example", src: v6Client, dst: v6DNSServer), 11
        ))
        frames.append(eth(
            ipv6DNSResponse(name: "six.example", answer: "192.0.2.20", src: v6DNSServer, dst: v6Client), 12
        ))

        return frames
    }

    /// The primary conversation as `CapturedFrame`s (no intrinsic link type, so the
    /// batch/live/file link-type default is what decodes them — exactly the classic
    /// path). Timestamps come straight from the fixed offsets.
    static func conversationCapturedFrames() -> [CapturedFrame] {
        conversation().map { frame in
            CapturedFrame(
                bytes: frame.bytes,
                timestamp: frame.timestamp,
                originalLength: frame.bytes.count
            )
        }
    }

    // MARK: DLT-rule corpora

    /// A classic `.pcap` whose declared link type is Raw IPv4 (`101`) and whose
    /// records carry bare IPv4 packets (no Ethernet header). The frames have no
    /// intrinsic DLT, so the *file default* must decode them — the "source-default
    /// fallback" half of the rule.
    static func rawIPv4ConversationFrames() -> [Frame] {
        let client = "198.51.100.11"
        let server = "203.0.113.9"
        // Strip the 14-byte Ethernet header to leave a Raw-IPv4 frame.
        let dnsQuery = Array(PacketBuilder.dnsQueryFrame(
            name: "raw.example", src: client, dst: server, srcPort: 40_500
        ).dropFirst(14))
        let dnsResponse = Array(PacketBuilder.dnsResponseFrame(
            name: "raw.example", answers: [server], src: server, dst: client, dstPort: 40_500
        ).dropFirst(14))
        return [
            Frame(bytes: dnsQuery, offsetSeconds: 1, linkType: LinkType.raw),
            Frame(bytes: dnsResponse, offsetSeconds: 2, linkType: LinkType.raw),
        ]
    }

    /// `CapturedFrame`s for the Raw-IPv4 conversation, again with no intrinsic link
    /// type so the default (`LinkType.raw`) decodes them.
    static func rawIPv4CapturedFrames() -> [CapturedFrame] {
        rawIPv4ConversationFrames().map { frame in
            CapturedFrame(bytes: frame.bytes, timestamp: frame.timestamp, originalLength: frame.bytes.count)
        }
    }

    /// Two frames of *different* intrinsic link types (Ethernet TLS, then Raw-IPv4
    /// TLS) — the "intrinsic-DLT-wins" half of the rule. Each `CapturedFrame`
    /// carries its own `linkType`, exactly as a mixed-interface pcapng's per-frame
    /// references do, so a batch/live fold matches the saved per-frame decode.
    static func mixedDLTFrames() -> [Frame] {
        let ethFrame = PacketBuilder.tlsClientHelloFrame(
            sni: "eth.example", src: "198.51.100.12", dst: "203.0.113.21", srcPort: 41_001
        )
        let rawFrame = Array(PacketBuilder.tlsClientHelloFrame(
            sni: "raw.example", src: "198.51.100.13", dst: "203.0.113.22", srcPort: 41_002
        ).dropFirst(14))
        return [
            Frame(bytes: ethFrame, offsetSeconds: 1, linkType: LinkType.ethernet),
            Frame(bytes: rawFrame, offsetSeconds: 2, linkType: LinkType.raw),
        ]
    }

    static func mixedDLTCapturedFrames() -> [CapturedFrame] {
        mixedDLTFrames().map { frame in
            CapturedFrame(
                bytes: frame.bytes,
                timestamp: frame.timestamp,
                originalLength: frame.bytes.count,
                linkType: frame.linkType
            )
        }
    }

    /// A generated, licence-safe TCP conversation corpus for connection-fold
    /// equivalence. Across three five-tuples in capture order it exercises a
    /// sequence-validated three-way handshake, payload, a retransmission, an
    /// out-of-order segment that later drains, an orderly bidirectional FIN close,
    /// an RST close, and an observed terminal followed by tuple reuse (a fresh SYN
    /// reopening a closed tuple). Flag bytes: SYN 0x02, SYN+ACK 0x12, ACK 0x10,
    /// PSH+ACK 0x18, FIN+ACK 0x11, RST 0x04.
    static func tcpConnectionSteps() -> [TCPStep] {
        tcpConversationA() + tcpConversationB() + tcpConversationC()
    }

    /// The TCP connection corpus as ordered ``Frame``s (all Ethernet).
    static func tcpConnectionFrames() -> [Frame] {
        tcpConnectionSteps().map { step in
            let payload = [UInt8](repeating: 0xAB, count: max(0, step.payloadLength))
            let segment = tcpSegmentBytes(
                srcPort: step.srcPort, dstPort: step.dstPort,
                seq: step.seq, ack: step.ack, flags: step.flags, payload: payload
            )
            let bytes = PacketBuilder.ethernetIPv4(proto: 6, src: step.src, dst: step.dst, payload: segment)
            return Frame(bytes: bytes, offsetSeconds: step.offset, linkType: LinkType.ethernet)
        }
    }

    /// The TCP connection corpus as `CapturedFrame`s (no intrinsic link type, so the
    /// classic Ethernet default decodes them — the same path batch/live use).
    static func tcpConnectionCapturedFrames() -> [CapturedFrame] {
        tcpConnectionFrames().map { frame in
            CapturedFrame(bytes: frame.bytes, timestamp: frame.timestamp, originalLength: frame.bytes.count)
        }
    }

    // MARK: Classic `.pcap` bytes

    /// Serialise `frames` as a classic `.pcap` in the requested byte order and
    /// timestamp resolution. Micro/nano differ only in the fraction field's scale;
    /// with whole-second offsets the fraction is `0`, so every variant decodes to
    /// the identical instant.
    static func classicPcapBytes(
        _ frames: [Frame],
        variant: ClassicVariant = .littleMicro,
        linkType: UInt32 = LinkType.ethernet
    )
        -> [UInt8]
    {
        var bytes = classicGlobalHeader(variant: variant, linkType: linkType)
        for frame in frames {
            let seconds = UInt32(truncatingIfNeeded: 1_700_000_000 + frame.offsetSeconds)
            let fraction: UInt32 = 0 // whole-second offsets → zero sub-second fraction
            let length = UInt32(frame.bytes.count)
            bytes += word32(seconds, little: variant.isLittle)
            bytes += word32(fraction, little: variant.isLittle)
            bytes += word32(length, little: variant.isLittle)
            bytes += word32(length, little: variant.isLittle)
            bytes += frame.bytes
        }
        return bytes
    }

    /// A classic little-endian microsecond record header, exposed so the robustness
    /// suite can staple a truncated tail onto a well-formed file.
    static func classicRecordHeaderLE(seconds: UInt32, fraction: UInt32, inclLen: UInt32, origLen: UInt32) -> [UInt8] {
        word32(seconds, little: true) + word32(fraction, little: true)
            + word32(inclLen, little: true) + word32(origLen, little: true)
    }

    // MARK: PCAPNG bytes

    /// The primary conversation as a single-section, single-Ethernet-interface
    /// pcapng, so the saved pcapng path is proven equivalent to the classic path.
    static func pcapngConversationBytes(little: Bool = true) -> [UInt8] {
        var file = PcapngFixture.sectionHeader(little: little)
        file += PcapngFixture.interfaceDescription(little: little, linkType: UInt16(LinkType.ethernet))
        for frame in conversation() {
            file += PcapngFixture.enhancedPacket(
                little: little, interfaceID: 0, ticks: microTicks(frame), captured: frame.bytes
            )
        }
        return file
    }

    /// A mixed-interface pcapng: interface 0 is Ethernet, interface 1 is Raw IPv4,
    /// and each frame is decoded under its own interface's link type.
    static func pcapngMixedDLTBytes(little: Bool = true) -> [UInt8] {
        let frames = mixedDLTFrames()
        var file = PcapngFixture.sectionHeader(little: little)
        file += PcapngFixture.interfaceDescription(little: little, linkType: UInt16(LinkType.ethernet))
        file += PcapngFixture.interfaceDescription(little: little, linkType: UInt16(LinkType.raw))
        file += PcapngFixture.enhancedPacket(
            little: little, interfaceID: 0, ticks: microTicks(frames[0]), captured: frames[0].bytes
        )
        file += PcapngFixture.enhancedPacket(
            little: little, interfaceID: 1, ticks: microTicks(frames[1]), captured: frames[1].bytes
        )
        return file
    }

    /// Two sections that switch byte order and reuse interface ID zero, each with
    /// its own Ethernet interface and one DNS frame — exercises the multi-section /
    /// endian-switch / reused-interface-zero path in one file.
    static func pcapngMultiSectionBytes() -> [UInt8] {
        let first = eth(PacketBuilder.dnsQueryFrame(
            name: "sect1.example", src: "198.51.100.14", dst: "203.0.113.31", srcPort: 42_000
        ), 1)
        let second = eth(PacketBuilder.dnsQueryFrame(
            name: "sect2.example", src: "198.51.100.15", dst: "203.0.113.32", srcPort: 42_001
        ), 2)

        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: UInt16(LinkType.ethernet))
        file += PcapngFixture.enhancedPacket(
            little: true,
            interfaceID: 0,
            ticks: microTicks(first),
            captured: first.bytes
        )

        file += PcapngFixture.sectionHeader(little: false)
        file += PcapngFixture.interfaceDescription(little: false, linkType: UInt16(LinkType.ethernet))
        file += PcapngFixture.enhancedPacket(
            little: false, interfaceID: 0, ticks: microTicks(second), captured: second.bytes
        )
        return file
    }

    /// A pcapng whose interface declares nanosecond timestamp resolution
    /// (`if_tsresol = 9`), with ticks scaled accordingly so the decoded instant
    /// still equals the classic path's — proving resolution handling.
    static func pcapngNanoResolutionBytes() -> [UInt8] {
        let frame = eth(PacketBuilder.dnsQueryFrame(
            name: "nano.example", src: "198.51.100.16", dst: "203.0.113.41", srcPort: 43_000
        ), 1)
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: UInt16(LinkType.ethernet), tsresol: 9)
        let nanoTicks = UInt64(1_700_000_000 + frame.offsetSeconds) * 1_000_000_000
        file += PcapngFixture.enhancedPacket(little: true, interfaceID: 0, ticks: nanoTicks, captured: frame.bytes)
        return file
    }

    /// A pcapng using a Simple Packet Block (interface 0 has `snaplen == 0`, the
    /// no-limit value). The SPB carries no timestamp, so the frame is honestly at
    /// the Unix epoch — asserted rather than papered over.
    static func pcapngSimplePacketBytes() -> [UInt8] {
        let frame = eth(PacketBuilder.dnsQueryFrame(
            name: "spb.example", src: "198.51.100.17", dst: "203.0.113.51", srcPort: 44_000
        ), 1)
        var file = PcapngFixture.sectionHeader(little: true)
        file += PcapngFixture.interfaceDescription(little: true, linkType: UInt16(LinkType.ethernet), snapLength: 0)
        file += PcapngFixture.simplePacket(
            little: true, originalLength: UInt32(frame.bytes.count), captured: frame.bytes
        )
        return file
    }

    // MARK: Temp-file helpers

    /// Write `bytes` to a unique temp file, run `body`, then remove it. Temp
    /// captures are created per test and deleted; nothing is committed.
    static func withTemporaryFile(
        _ bytes: [UInt8],
        ext: String = "pcap",
        _ body: (URL) throws -> Void
    )
        throws
    {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("replay-\(UUID().uuidString).\(ext)")
        try Data(bytes).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        try body(url)
    }

    // MARK: Private

    private static let v6Client: [UInt16] = [0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0010]
    private static let v6DNSServer: [UInt16] = [0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0053]

    /// Conversation A: a validated three-way handshake, payload, a retransmission
    /// and an orderly bidirectional FIN close.
    private static func tcpConversationA() -> [TCPStep] {
        let aClient = "198.51.100.30"
        let aServer = "203.0.113.60"
        return [
            TCPStep(
                src: aClient,
                dst: aServer,
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x02,
                seq: 1_000,
                ack: 0,
                payloadLength: 0,
                offset: 1
            ),
            TCPStep(
                src: aServer,
                dst: aClient,
                srcPort: 443,
                dstPort: 50_000,
                flags: 0x12,
                seq: 5_000,
                ack: 1_001,
                payloadLength: 0,
                offset: 2
            ),
            TCPStep(
                src: aClient,
                dst: aServer,
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x10,
                seq: 1_001,
                ack: 5_001,
                payloadLength: 0,
                offset: 3
            ),
            TCPStep(
                src: aClient,
                dst: aServer,
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x18,
                seq: 1_001,
                ack: 5_001,
                payloadLength: 100,
                offset: 4
            ),
            TCPStep(
                src: aClient,
                dst: aServer,
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x18,
                seq: 1_001,
                ack: 5_001,
                payloadLength: 100,
                offset: 5
            ),
            TCPStep(
                src: aServer,
                dst: aClient,
                srcPort: 443,
                dstPort: 50_000,
                flags: 0x18,
                seq: 5_001,
                ack: 1_101,
                payloadLength: 40,
                offset: 6
            ),
            TCPStep(
                src: aClient,
                dst: aServer,
                srcPort: 50_000,
                dstPort: 443,
                flags: 0x11,
                seq: 1_101,
                ack: 5_041,
                payloadLength: 0,
                offset: 7
            ),
            TCPStep(
                src: aServer,
                dst: aClient,
                srcPort: 443,
                dstPort: 50_000,
                flags: 0x11,
                seq: 5_041,
                ack: 1_102,
                payloadLength: 0,
                offset: 8
            ),
        ]
    }

    /// Conversation B: a handshake, an out-of-order buffered segment that later
    /// drains, and an RST close.
    private static func tcpConversationB() -> [TCPStep] {
        let bClient = "198.51.100.31"
        let bServer = "203.0.113.61"
        return [
            TCPStep(
                src: bClient,
                dst: bServer,
                srcPort: 50_001,
                dstPort: 8_080,
                flags: 0x02,
                seq: 2_000,
                ack: 0,
                payloadLength: 0,
                offset: 9
            ),
            TCPStep(
                src: bServer,
                dst: bClient,
                srcPort: 8_080,
                dstPort: 50_001,
                flags: 0x12,
                seq: 6_000,
                ack: 2_001,
                payloadLength: 0,
                offset: 10
            ),
            TCPStep(
                src: bClient,
                dst: bServer,
                srcPort: 50_001,
                dstPort: 8_080,
                flags: 0x10,
                seq: 2_001,
                ack: 6_001,
                payloadLength: 0,
                offset: 11
            ),
            TCPStep(
                src: bClient,
                dst: bServer,
                srcPort: 50_001,
                dstPort: 8_080,
                flags: 0x18,
                seq: 2_101,
                ack: 6_001,
                payloadLength: 50,
                offset: 12
            ),
            TCPStep(
                src: bClient,
                dst: bServer,
                srcPort: 50_001,
                dstPort: 8_080,
                flags: 0x18,
                seq: 2_001,
                ack: 6_001,
                payloadLength: 100,
                offset: 13
            ),
            TCPStep(
                src: bServer,
                dst: bClient,
                srcPort: 8_080,
                dstPort: 50_001,
                flags: 0x04,
                seq: 6_001,
                ack: 0,
                payloadLength: 0,
                offset: 14
            ),
        ]
    }

    /// Conversation C: a SYN, an RST (observed terminal), then a fresh SYN that
    /// reuses the now-terminal tuple.
    private static func tcpConversationC() -> [TCPStep] {
        let cClient = "198.51.100.32"
        let cServer = "203.0.113.62"
        return [
            TCPStep(
                src: cClient,
                dst: cServer,
                srcPort: 50_002,
                dstPort: 443,
                flags: 0x02,
                seq: 3_000,
                ack: 0,
                payloadLength: 0,
                offset: 15
            ),
            TCPStep(
                src: cServer,
                dst: cClient,
                srcPort: 443,
                dstPort: 50_002,
                flags: 0x04,
                seq: 7_000,
                ack: 0,
                payloadLength: 0,
                offset: 16
            ),
            TCPStep(
                src: cClient,
                dst: cServer,
                srcPort: 50_002,
                dstPort: 443,
                flags: 0x02,
                seq: 9_000,
                ack: 0,
                payloadLength: 0,
                offset: 17
            ),
        ]
    }

    /// Wrap already-complete frame bytes as an Ethernet ``Frame`` at `offset`.
    private static func eth(_ bytes: [UInt8], _ offset: Int) -> Frame {
        Frame(bytes: bytes, offsetSeconds: offset, linkType: LinkType.ethernet)
    }

    /// Build an Ethernet+IPv4+TCP segment carrying `payload` at TCP `sequence`, for
    /// modelling a stream split across frames of one five-tuple.
    private static func tcpSegment(
        payload: [UInt8],
        sequence: UInt32,
        offset: Int,
        src: String,
        dst: String,
        srcPort: UInt16,
        dstPort: UInt16
    )
        -> Frame
    {
        let bytes = PacketBuilder.ethernetIPv4(
            proto: 6, src: src, dst: dst,
            payload: PacketBuilder.tcp(
                srcPort: srcPort, dstPort: dstPort, flags: 0x18, payload: payload, sequence: sequence
            )
        )
        return Frame(bytes: bytes, offsetSeconds: offset, linkType: LinkType.ethernet)
    }

    /// A raw 20-byte TCP header (no options) carrying explicit sequence *and*
    /// acknowledgement numbers plus arbitrary flags — the corpus needs valid ack
    /// numbers for handshake validation, which `PacketBuilder.tcp` (ack always 0)
    /// cannot provide. Network byte order; data offset is a fixed five words.
    private static func tcpSegmentBytes(
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        flags: UInt8,
        payload: [UInt8]
    )
        -> [UInt8]
    {
        func big16(_ value: UInt16) -> [UInt8] {
            [UInt8(value >> 8), UInt8(value & 0xFF)]
        }
        func big32(_ value: UInt32) -> [UInt8] {
            [
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF),
            ]
        }
        var header = big16(srcPort) + big16(dstPort)
        header += big32(seq) + big32(ack)
        header += [0x50, flags] // data offset (5 words), flags
        header += [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00] // window, checksum, urgent
        return header + payload
    }

    /// A STUN Binding Request (RFC 5389) wrapped in Ethernet+IPv4+UDP on ICE-style
    /// ports; STUN detection is content-based, so the ports are not well known.
    private static func stunBindingRequest(src: String, dst: String) -> [UInt8] {
        var message: [UInt8] = [0x00, 0x01, 0x00, 0x00] // Binding Request, length 0
        message += [0x21, 0x12, 0xA4, 0x42] // magic cookie
        message += Array(repeating: 0xAB, count: 12) // transaction id
        return PacketBuilder.ethernetIPv4(
            proto: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(srcPort: 54_321, dstPort: 51_820, payload: message)
        )
    }

    /// A QUIC v1 Initial long header (RFC 9000 §17.2) wrapped in Ethernet+IPv4+UDP
    /// on UDP/443, carrying only clear-text header metadata.
    private static func quicInitial(src: String, dst: String) -> [UInt8] {
        var payload: [UInt8] = [0xC0] // long header, Initial
        payload += [0x00, 0x00, 0x00, 0x01] // version 1
        let dcid: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        payload.append(UInt8(dcid.count))
        payload += dcid
        let scid: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
        payload.append(UInt8(scid.count))
        payload += scid
        payload += [0xDE, 0xAD, 0xBE, 0xEF] // opaque (encrypted) tail, never interpreted
        return PacketBuilder.ethernetIPv4(
            proto: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(srcPort: 55_000, dstPort: 443, payload: payload)
        )
    }

    private static func ipv6DNSQuery(name: String, src: [UInt16], dst: [UInt16]) -> [UInt8] {
        PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(srcPort: 45_000, dstPort: 53, payload: PacketBuilder.dnsQuery(name: name))
        )
    }

    private static func ipv6DNSResponse(name: String, answer: String, src: [UInt16], dst: [UInt16]) -> [UInt8] {
        PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: src, dst: dst,
            payload: PacketBuilder.udp(
                srcPort: 53, dstPort: 45_000,
                payload: PacketBuilder.dnsResponse(name: name, answers: [answer])
            )
        )
    }

    /// Microsecond ticks for a pcapng EPB at the default `if_tsresol` (10⁻⁶).
    private static func microTicks(_ frame: Frame) -> UInt64 {
        UInt64(1_700_000_000 + frame.offsetSeconds) * 1_000_000
    }

    private static func classicGlobalHeader(variant: ClassicVariant, linkType: UInt32) -> [UInt8] {
        let little = variant.isLittle
        // The magic is laid down big-endian so a raw read yields the documented
        // constant regardless of the declared order (matching the reader's sniff).
        let rawMagic: UInt32 = switch variant {
        case .bigMicro: 0xA1B2C3D4
        case .littleMicro: 0xD4C3B2A1
        case .bigNano: 0xA1B23C4D
        case .littleNano: 0x4D3CB2A1
        }
        var header: [UInt8] = [
            UInt8((rawMagic >> 24) & 0xFF),
            UInt8((rawMagic >> 16) & 0xFF),
            UInt8((rawMagic >> 8) & 0xFF),
            UInt8(rawMagic & 0xFF),
        ]
        header += word16(2, little: little) + word16(4, little: little)
        header += word32(0, little: little) + word32(0, little: little)
        header += word32(65_535, little: little)
        header += word32(linkType, little: little)
        return header
    }

    private static func word16(_ value: UInt16, little: Bool) -> [UInt8] {
        let bytes = [UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)]
        return little ? bytes : Array(bytes.reversed())
    }

    private static func word32(_ value: UInt32, little: Bool) -> [UInt8] {
        let bytes = [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF),
        ]
        return little ? bytes : Array(bytes.reversed())
    }
}
