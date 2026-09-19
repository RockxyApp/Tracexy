import Foundation
import Testing
@testable import Tracexy

// MARK: - LinuxCookedFixture

/// Programmatic Linux cooked-capture frame builders shared by the decode and
/// import suites.
///
/// **Generated-only provenance.** Every byte is synthesised here. Payloads are
/// ``PacketBuilder`` fixtures with their 14-byte Ethernet header removed, which is
/// exactly the shape a cooked capture carries, and every address comes from the
/// reserved documentation ranges (RFC 5737 IPv4, RFC 3849 IPv6) with reserved
/// example names (RFC 2606). No recorded capture, personal address, device
/// identity or process name is read or committed.
enum LinuxCookedFixture {
    // MARK: Internal

    static let client = "198.51.100.20"
    static let server = "203.0.113.70"
    static let v6Client: [UInt16] = [0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0020]
    static let v6Server: [UInt16] = [0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0x0053]

    /// The eight stored address bytes. This is the capture source's own address —
    /// the header has no second address and never names an Ethernet pair.
    static let address: [UInt8] = [0x02, 0x00, 0x5E, 0x10, 0x00, 0x01, 0x00, 0x00]

    // MARK: Headers

    static func sll(
        packetType: UInt16 = 0,
        hardware: UInt16 = 1,
        addressLength: UInt16 = 6,
        address: [UInt8] = LinuxCookedFixture.address,
        protocolNumber: UInt16,
        payload: [UInt8]
    )
        -> [UInt8]
    {
        var frame = be16(packetType) + be16(hardware) + be16(addressLength)
        frame += stored(address)
        frame += be16(protocolNumber)
        return frame + payload
    }

    static func sll2(
        protocolNumber: UInt16,
        reserved: UInt16 = 0,
        interfaceIndex: UInt32 = 7,
        hardware: UInt16 = 1,
        packetType: UInt8 = 0,
        addressLength: UInt8 = 6,
        address: [UInt8] = LinuxCookedFixture.address,
        payload: [UInt8]
    )
        -> [UInt8]
    {
        var frame = be16(protocolNumber) + be16(reserved) + be32(interfaceIndex) + be16(hardware)
        frame += [packetType, addressLength]
        frame += stored(address)
        return frame + payload
    }

    /// The same logical frame in whichever cooked version is under test.
    static func frame(
        _ version: LinuxCookedHeader.Version, protocolNumber: UInt16, payload: [UInt8]
    )
        -> [UInt8]
    {
        version == .sll
            ? sll(protocolNumber: protocolNumber, payload: payload)
            : sll2(protocolNumber: protocolNumber, payload: payload)
    }

    static func linkType(_ version: LinuxCookedHeader.Version) -> UInt32 {
        version == .sll ? LinkType.linuxSLL : LinkType.linuxSLL2
    }

    // MARK: Payloads (Ethernet header removed)

    static func ipv4HTTPPayload(srcPort: UInt16 = 51_000) -> [UInt8] {
        Array(PacketBuilder.httpRequestFrame(
            host: "sll.example", path: "/health", src: client, dst: server, srcPort: srcPort
        ).dropFirst(14))
    }

    static func ipv4DNSPayload(srcPort: UInt16 = 51_001) -> [UInt8] {
        Array(PacketBuilder.dnsQueryFrame(
            name: "sll.example", src: client, dst: server, srcPort: srcPort
        ).dropFirst(14))
    }

    static func ipv6DNSPayload(srcPort: UInt16 = 51_002) -> [UInt8] {
        Array(PacketBuilder.ethernetIPv6(
            nextHeader: 17, src: v6Client, dst: v6Server,
            payload: PacketBuilder.udp(
                srcPort: srcPort, dstPort: 53, payload: PacketBuilder.dnsQuery(name: "sll6.example")
            )
        ).dropFirst(14))
    }

    static func arpPayload() -> [UInt8] {
        Array(PacketBuilder.arpRequestFrame(senderIP: client, targetIP: "198.51.100.1").dropFirst(14))
    }

    // MARK: Private

    /// Exactly eight stored bytes, whatever the declared length claims.
    private static func stored(_ address: [UInt8]) -> [UInt8] {
        Array((address + Array(repeating: UInt8(0), count: 8)).prefix(8))
    }

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }
}

// MARK: - LinuxCookedDecodeTests

/// Linux cooked capture (SLL / SLL2) decoding: both fixed headers expose their
/// exact fields and byte ranges, recognized payloads reuse the existing
/// IPv4/IPv6/ARP → transport → application decoders unchanged, and anything this
/// build cannot vouch for keeps its header facts without inventing an endpoint,
/// a session or an Ethernet identity.
@Suite("Linux cooked capture decoding")
struct LinuxCookedDecodeTests {
    // MARK: Internal

    // MARK: - Recognized payloads reuse the existing decoders

    @Test(
        "IPv4 payloads reach the existing transport and application decoders",
        arguments: [LinuxCookedHeader.Version.sll, .sll2]
    )
    func ipv4ReusesExistingDecoding(version: LinuxCookedHeader.Version) throws {
        let frame = LinuxCookedFixture.frame(
            version, protocolNumber: 0x0800, payload: LinuxCookedFixture.ipv4HTTPPayload()
        )
        let packet = decode(frame, version: version)

        #expect(packet.layers.map(\.proto) == [.linuxCooked, .ipv4, .tcp, .http])
        #expect(packet.transport == .tcp)
        #expect(packet.appProtocol == .http)
        let tuple = try #require(packet.fiveTuple)
        #expect(tuple.proto == .tcp)
        #expect(packet.sourceEndpoint == IPEndpoint(ip: LinuxCookedFixture.client, port: 51_000))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: LinuxCookedFixture.server, port: 80))
        // The cooked header is outer framing, so it never occupies a protocol-stack
        // slot — exactly as Ethernet does not.
        #expect(packet.protocolStack == [.ipv4, .tcp, .http])
    }

    @Test(
        "IPv6 payloads reach the existing transport and application decoders",
        arguments: [LinuxCookedHeader.Version.sll, .sll2]
    )
    func ipv6ReusesExistingDecoding(version: LinuxCookedHeader.Version) {
        let frame = LinuxCookedFixture.frame(
            version, protocolNumber: 0x86DD, payload: LinuxCookedFixture.ipv6DNSPayload()
        )
        let packet = decode(frame, version: version)

        #expect(packet.layers.map(\.proto) == [.linuxCooked, .ipv6, .udp, .dns])
        #expect(packet.appProtocol == .dns)
        #expect(packet.dnsQuery == "sll6.example")
        #expect(packet.fiveTuple?.proto == .udp)
        #expect(packet.protocolStack == [.ipv6, .udp, .dns])
    }

    @Test(
        "ARP payloads form the same address-pair session the Ethernet path does",
        arguments: [LinuxCookedHeader.Version.sll, .sll2]
    )
    func arpReusesExistingDecoding(version: LinuxCookedHeader.Version) {
        let frame = LinuxCookedFixture.frame(
            version, protocolNumber: 0x0806, payload: LinuxCookedFixture.arpPayload()
        )
        let packet = decode(frame, version: version)

        #expect(packet.layers.map(\.proto) == [.linuxCooked, .arp])
        #expect(packet.appProtocol == .arp)
        #expect(packet.sourceEndpoint == IPEndpoint(ip: LinuxCookedFixture.client, port: 0))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "198.51.100.1", port: 0))

        // Identical to the same ARP message carried over Ethernet, apart from the
        // outer framing layer.
        let overEthernet = PacketDecoder.decode(
            PacketBuffer(PacketBuilder.arpRequestFrame(
                senderIP: LinuxCookedFixture.client, targetIP: "198.51.100.1"
            )),
            linkType: LinkType.ethernet, timestamp: Self.captureTime, originalLength: 42
        )
        #expect(packet.fiveTuple == overEthernet.fiveTuple)
        #expect(packet.layers.last?.fields.map(\.value) == overEthernet.layers.last?.fields.map(\.value))
    }

    // MARK: - Exact header fields and byte ranges

    @Test("The SLL header exposes every field at its exact offset")
    func sllHeaderFieldRanges() throws {
        let payload = LinuxCookedFixture.ipv4DNSPayload()
        let frame = LinuxCookedFixture.sll(
            packetType: 4, hardware: 1, addressLength: 6, protocolNumber: 0x0800, payload: payload
        )
        let packet = decode(frame, version: .sll)
        let header = try #require(packet.layers.first)

        #expect(header.proto == .linuxCooked)
        #expect(header.title == "Linux Cooked Capture")
        #expect(header.summary == "Sent by capture host (4) · IPv4 (0x0800)")
        #expect(header.byteRange == 0 ..< 16)
        try expectField(header, "Packet Type", "Sent by capture host (4)", 0 ..< 2)
        try expectField(header, "Hardware Type", "Ethernet (1)", 2 ..< 4)
        try expectField(header, "Address Length", "6", 4 ..< 6)
        try expectField(header, "Address", "02:00:5e:10:00:01", 6 ..< 12)
        try expectField(header, "Protocol", "IPv4 (0x0800)", 14 ..< 16)
        // No fabricated Ethernet pair or direction relative to this Mac.
        #expect(!header.fields.contains { ["Destination", "Source", "Interface"].contains($0.name) })
        // The handed-on payload cites its real offsets in the frame.
        #expect(packet.layers[1].byteRange?.lowerBound == 16)
    }

    @Test("The SLL2 header exposes every field, including reserved and capture interface, at its exact offset")
    func sll2HeaderFieldRanges() throws {
        let payload = LinuxCookedFixture.ipv4DNSPayload()
        let frame = LinuxCookedFixture.sll2(
            protocolNumber: 0x0800, reserved: 0x1234, interfaceIndex: 0x01020304,
            hardware: 1, packetType: 0, addressLength: 6, payload: payload
        )
        let packet = decode(frame, version: .sll2)
        let header = try #require(packet.layers.first)

        #expect(header.title == "Linux Cooked Capture v2")
        #expect(header.byteRange == 0 ..< 20)
        try expectField(header, "Protocol", "IPv4 (0x0800)", 0 ..< 2)
        try expectField(header, "Reserved", "0x1234", 2 ..< 4)
        // The capture machine's own interface number, kept numeric: it names no
        // interface on this Mac and is not resolved to one.
        try expectField(header, "Capture Interface Index", "16909060", 4 ..< 8)
        try expectField(header, "Hardware Type", "Ethernet (1)", 8 ..< 10)
        try expectField(header, "Packet Type", "To capture host (0)", 10 ..< 11)
        try expectField(header, "Address Length", "6", 11 ..< 12)
        try expectField(header, "Address", "02:00:5e:10:00:01", 12 ..< 18)
        #expect(packet.layers[1].byteRange?.lowerBound == 20)
    }

    @Test("Declared address lengths are reported truthfully and never beyond the stored eight bytes")
    func addressLengthsAreReportedTruthfully() throws {
        let cases: [(length: UInt16, value: String)] = [
            (0, "(none)"),
            (6, "02:00:5e:10:00:01"),
            (8, "02:00:5e:10:00:01:00:00"),
            (12, "02:00:5e:10:00:01:00:00 (first 8 of 12 bytes)"),
            (256, "02:00:5e:10:00:01:00:00 (first 8 of 256 bytes)"),
        ]
        for entry in cases {
            let frame = LinuxCookedFixture.sll(
                addressLength: entry.length, protocolNumber: 0x0800,
                payload: LinuxCookedFixture.ipv4DNSPayload()
            )
            let header = try #require(decode(frame, version: .sll).layers.first)
            try expectField(header, "Address Length", "\(entry.length)")
            let address = try #require(header.fields.first { $0.name == "Address" })
            #expect(address.value == entry.value)
            // A zero-length address cites no bytes rather than an empty range.
            let expectedRange: Range<Int>? = entry.length == 0
                ? nil
                : 6 ..< (6 + min(Int(entry.length), 8))
            #expect(address.byteRange == expectedRange)
        }
    }

    @Test("An SLL2 one-byte address length above the stored eight is still bounded")
    func sll2LongAddressIsBounded() throws {
        let frame = LinuxCookedFixture.sll2(
            protocolNumber: 0x0800, addressLength: 255, payload: LinuxCookedFixture.ipv4DNSPayload()
        )
        let header = try #require(decode(frame, version: .sll2).layers.first)
        try expectField(header, "Address Length", "255", 11 ..< 12)
        try expectField(header, "Address", "02:00:5e:10:00:01:00:00 (first 8 of 255 bytes)", 12 ..< 20)
    }

    // MARK: - Short headers publish nothing

    @Test(
        "Every fixed-header prefix shorter than the complete header publishes no facts",
        arguments: [LinuxCookedHeader.Version.sll, .sll2]
    )
    func shortHeadersPublishNothing(version: LinuxCookedHeader.Version) {
        let complete = LinuxCookedFixture.frame(
            version, protocolNumber: 0x0800, payload: LinuxCookedFixture.ipv4DNSPayload()
        )
        for length in 0 ..< version.headerLength {
            let packet = decode(Array(complete.prefix(length)), version: version)
            #expect(packet.layers.isEmpty, "length \(length) published a layer")
            expectNoSession(packet)
        }
        // One more byte than the fixed header does publish it.
        #expect(!decode(Array(complete.prefix(version.headerLength)), version: version).layers.isEmpty)
    }

    // MARK: - Unsupported protocol / hardware retain facts without a session

    @Test(
        "An unrecognized protocol value keeps the header and invents no session",
        arguments: [0x0000, 0x0805, 0x0807, 0x88CC, 0x86DC]
    )
    func unsupportedProtocolRetainsHeaderOnly(protocolNumber: Int) throws {
        for version in Self.versions {
            let frame = LinuxCookedFixture.frame(
                version, protocolNumber: UInt16(protocolNumber),
                payload: LinuxCookedFixture.ipv4DNSPayload()
            )
            let packet = decode(frame, version: version)
            #expect(packet.layers.map(\.proto) == [.linuxCooked])
            expectNoSession(packet)
            // The number is still shown, honestly, as the value it is.
            let header = try #require(packet.layers.first)
            try expectField(header, "Protocol", String(format: "0x%04x", UInt16(protocolNumber)))
        }
    }

    @Test("A VLAN protocol value is named but still not handed on: cooked framing carries no tag")
    func vlanProtocolIsNamedButNotHandedOn() throws {
        for version in Self.versions {
            let frame = LinuxCookedFixture.frame(
                version, protocolNumber: 0x8100,
                payload: LinuxCookedFixture.ipv4DNSPayload()
            )
            let packet = decode(frame, version: version)
            #expect(packet.layers.map(\.proto) == [.linuxCooked])
            expectNoSession(packet)
            let header = try #require(packet.layers.first)
            try expectField(header, "Protocol", "802.1Q VLAN (0x8100)")
        }
    }

    @Test(
        "Hardware whose payload semantics differ keeps the header and invents no session",
        arguments: [770, 803, 824]
    )
    func excludedHardwareRetainsHeaderOnly(hardware: Int) throws {
        for version in Self.versions {
            // A protocol value that would otherwise be handed straight to IPv4,
            // over a payload that really is IPv4 — only the hardware type stops it.
            let payload = LinuxCookedFixture.ipv4DNSPayload()
            let frame = version == .sll
                ? LinuxCookedFixture.sll(hardware: UInt16(hardware), protocolNumber: 0x0800, payload: payload)
                : LinuxCookedFixture.sll2(protocolNumber: 0x0800, hardware: UInt16(hardware), payload: payload)
            let packet = decode(frame, version: version)

            #expect(packet.layers.map(\.proto) == [.linuxCooked])
            expectNoSession(packet)
            let header = try #require(packet.layers.first)
            // The protocol number is not rendered as an EtherType it may not be.
            try expectField(header, "Protocol", "0x0800")
        }
    }

    @Test(
        "GRE-over-IP hardware with a recognized protocol value is still decoded",
        arguments: [LinuxCookedHeader.Version.sll, .sll2]
    )
    func greHardwareIsNotExcluded(version: LinuxCookedHeader.Version) throws {
        let payload = LinuxCookedFixture.ipv4DNSPayload()
        let frame = version == .sll
            ? LinuxCookedFixture.sll(hardware: 778, protocolNumber: 0x0800, payload: payload)
            : LinuxCookedFixture.sll2(protocolNumber: 0x0800, hardware: 778, payload: payload)
        let packet = decode(frame, version: version)

        #expect(packet.layers.map(\.proto) == [.linuxCooked, .ipv4, .udp, .dns])
        #expect(packet.fiveTuple != nil)
        let header = try #require(packet.layers.first)
        try expectField(header, "Hardware Type", "GRE over IP (778)")
    }

    // MARK: - Malformed payloads invent no session

    @Test("A payload that does not carry the declared network header keeps the frame at its link layer")
    func malformedPayloadInventsNoSession() {
        for version in Self.versions {
            for payload in Self.mislabelledPayloads {
                let frame = LinuxCookedFixture.frame(
                    version, protocolNumber: payload.protocolNumber, payload: payload.bytes
                )
                let packet = decode(frame, version: version)
                #expect(packet.layers.map(\.proto) == [.linuxCooked], "\(payload.label) decoded past the header")
                expectNoSession(packet)
            }
        }
    }

    // MARK: - Raw IP chooses its version

    @Test("Raw IP decodes both families and rejects any other version nibble")
    func rawLinkTypeChoosesTheIPVersion() {
        let v4 = LinuxCookedFixture.ipv4DNSPayload()
        let v4Packet = PacketDecoder.decode(
            PacketBuffer(v4), linkType: LinkType.raw, timestamp: Self.captureTime, originalLength: v4.count
        )
        #expect(v4Packet.layers.map(\.proto) == [.ipv4, .udp, .dns])

        let v6 = LinuxCookedFixture.ipv6DNSPayload()
        let v6Packet = PacketDecoder.decode(
            PacketBuffer(v6), linkType: LinkType.raw, timestamp: Self.captureTime, originalLength: v6.count
        )
        #expect(v6Packet.layers.map(\.proto) == [.ipv6, .udp, .dns])
        #expect(v6Packet.dnsQuery == "sll6.example")

        // Any other leading nibble is not an IP packet, so nothing is published
        // rather than an IPv4 header that was never there.
        for nibble in [UInt8(0x00), 0x50, 0x70, 0xF0] {
            var bytes = v4
            bytes[0] = nibble | (bytes[0] & 0x0F)
            let packet = PacketDecoder.decode(
                PacketBuffer(bytes), linkType: LinkType.raw,
                timestamp: Self.captureTime, originalLength: bytes.count
            )
            #expect(packet.layers.isEmpty, "nibble \(nibble >> 4) published a layer")
            expectNoSession(packet)
        }
    }

    // MARK: - Ethernet framing is untouched

    @Test("Known Ethernet framing decodes exactly as before")
    func ethernetFramingIsUnchanged() throws {
        let frame = PacketBuilder.httpRequestFrame(
            host: "sll.example", path: "/health", src: LinuxCookedFixture.client,
            dst: LinuxCookedFixture.server, srcPort: 51_000
        )
        let packet = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Self.captureTime, originalLength: frame.count
        )
        let ethernet = try #require(packet.layers.first)

        #expect(ethernet.proto == .ethernet)
        #expect(ethernet.title == "Ethernet II")
        #expect(ethernet.byteRange == 0 ..< 14)
        try expectField(ethernet, "Destination", "06:06:06:06:06:06", 0 ..< 6)
        try expectField(ethernet, "Source", "01:02:03:04:05:06", 6 ..< 12)
        try expectField(ethernet, "Type", "IPv4 (0x0800)", 12 ..< 14)
        #expect(packet.layers.map(\.proto) == [.ethernet, .ipv4, .tcp, .http])
        #expect(packet.protocolStack == [.ipv4, .tcp, .http])

        // Everything from the network layer inward is byte-identical to the same
        // payload carried in a cooked frame, only shifted by the framing length.
        let cooked = decode(
            LinuxCookedFixture.sll(protocolNumber: 0x0800, payload: LinuxCookedFixture.ipv4HTTPPayload()),
            version: .sll
        )
        #expect(Array(packet.layers.dropFirst()) == Array(cooked.layers.dropFirst()))
        #expect(packet.fiveTuple == cooked.fiveTuple)
    }

    // MARK: Private

    private static let versions: [LinuxCookedHeader.Version] = [.sll, .sll2]

    /// A fixed instant; decoding never derives anything from it, but a real
    /// capture time keeps these frames indistinguishable from file-read ones.
    private static let captureTime = Date(timeIntervalSince1970: 1_700_000_000)

    /// Payloads whose cooked header names a network protocol the bytes do not
    /// actually carry: too short, wrong version, an impossible IPv4 header length,
    /// or an ARP shape the existing decoder does not read.
    private static var mislabelledPayloads: [(label: String, protocolNumber: UInt16, bytes: [UInt8])] {
        let ipv4 = PacketBuilder.ipv4Header(
            proto: 17, src: LinuxCookedFixture.client, dst: LinuxCookedFixture.server, payloadCount: 0
        )
        let ipv6 = PacketBuilder.ipv6Header(
            nextHeader: 17, payloadCount: 0,
            src: LinuxCookedFixture.v6Client, dst: LinuxCookedFixture.v6Server
        )
        let arp = LinuxCookedFixture.arpPayload()
        var ipv4WrongVersion = ipv4
        ipv4WrongVersion[0] = 0x65 // version 6 claimed as IPv4
        var ipv4ShortIHL = ipv4
        ipv4ShortIHL[0] = 0x44 // IHL 4 words = 16 bytes, below the fixed header
        var ipv4OverlongIHL = ipv4
        ipv4OverlongIHL[0] = 0x4F // IHL 15 words = 60 bytes, past the captured bytes
        var ipv6WrongVersion = ipv6
        ipv6WrongVersion[0] = 0x40
        var arpUnsupportedHardware = arp
        arpUnsupportedHardware[1] = 6 // hardware type 6, not Ethernet
        var arpUnsupportedLengths = arp
        arpUnsupportedLengths[5] = 16 // 16-byte protocol addresses, not IPv4
        return [
            ("IPv4 truncated", 0x0800, Array(ipv4.prefix(19))),
            ("IPv4 empty", 0x0800, []),
            ("IPv4 wrong version", 0x0800, ipv4WrongVersion),
            ("IPv4 header length below 20", 0x0800, ipv4ShortIHL),
            ("IPv4 header length past capture", 0x0800, ipv4OverlongIHL),
            ("IPv6 truncated", 0x86DD, Array(ipv6.prefix(39))),
            ("IPv6 wrong version", 0x86DD, ipv6WrongVersion),
            ("ARP truncated", 0x0806, Array(arp.prefix(27))),
            ("ARP unsupported hardware", 0x0806, arpUnsupportedHardware),
            ("ARP unsupported address lengths", 0x0806, arpUnsupportedLengths),
        ]
    }

    private func decode(_ frame: [UInt8], version: LinuxCookedHeader.Version) -> DecodedPacket {
        PacketDecoder.decode(
            PacketBuffer(frame),
            linkType: LinuxCookedFixture.linkType(version),
            timestamp: Self.captureTime,
            originalLength: frame.count
        )
    }

    /// Assert a named field's rendered value and, when given, its exact absolute
    /// byte range within the frame.
    private func expectField(
        _ layer: DecodedLayer, _ name: String, _ value: String, _ range: Range<Int>? = nil
    )
        throws
    {
        let field = try #require(layer.fields.first { $0.name == name }, "missing field \(name)")
        #expect(field.value == value)
        if let range {
            #expect(field.byteRange == range, "field \(name) cited \(String(describing: field.byteRange))")
        }
    }

    /// No endpoint, tuple, transport or application claim was made.
    private func expectNoSession(_ packet: DecodedPacket) {
        #expect(packet.fiveTuple == nil)
        #expect(packet.sourceEndpoint == nil)
        #expect(packet.destinationEndpoint == nil)
        #expect(packet.transport == nil)
        #expect(packet.appProtocol == nil)
    }
}
