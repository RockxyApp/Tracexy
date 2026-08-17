import Foundation
import Testing
@testable import Tracexy

// MARK: - Helpers

private func decodeFrame(_ frame: [UInt8], linkType: UInt32 = LinkType.ethernet) -> DecodedPacket {
    PacketDecoder.decode(
        PacketBuffer(frame),
        linkType: linkType,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000),
        originalLength: frame.count
    )
}

/// Builds a QUIC long-header prefix (RFC 9000 §17.2): first byte, 32-bit version,
/// destination CID (length-prefixed), source CID (length-prefixed), then opaque
/// (encrypted) bytes the decoder never interprets. CID lengths are written from
/// the supplied arrays so a caller can model both well-formed and over-cap CIDs.
private func quicLongHeader(
    firstByte: UInt8,
    version: UInt32,
    dcid: [UInt8],
    scid: [UInt8],
    dcidLen: UInt8? = nil,
    scidLen: UInt8? = nil,
    payload: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
)
    -> [UInt8]
{
    var bytes: [UInt8] = [firstByte]
    bytes += [
        UInt8((version >> 24) & 0xFF),
        UInt8((version >> 16) & 0xFF),
        UInt8((version >> 8) & 0xFF),
        UInt8(version & 0xFF),
    ]
    bytes.append(dcidLen ?? UInt8(dcid.count))
    bytes += dcid
    bytes.append(scidLen ?? UInt8(scid.count))
    bytes += scid
    bytes += payload
    return bytes
}

/// Wraps a QUIC payload in Ethernet + IPv4 + UDP. Detection is the long-header
/// bit on UDP/443, so the destination port defaults to 443.
private func quicFrame(
    _ payload: [UInt8],
    src: String = "192.168.1.30",
    dst: String = "142.250.72.196",
    srcPort: UInt16 = 55_000,
    dstPort: UInt16 = 443
)
    -> [UInt8]
{
    PacketBuilder.ethernetIPv4(
        proto: 17,
        src: src,
        dst: dst,
        payload: PacketBuilder.udp(srcPort: srcPort, dstPort: dstPort, payload: payload)
    )
}

private extension DecodedPacket {
    func layer(_ kind: ProtocolKind) -> DecodedLayer? {
        layers.first { $0.proto == kind }
    }
}

// MARK: - QUICDecodeTests

/// Clear-text QUIC long-header metadata (RFC 9000 §17.2) on UDP/443 — packet
/// type, version, and the destination/source connection IDs only. The decoder
/// never decrypts or guesses any protected field; short headers and truncated
/// headers stay honest (identification only, or UDP per the existing gate).
@Suite("QUIC decode")
struct QUICDecodeTests {
    @Test("An Initial long header surfaces type, version, and both connection IDs over UDP/443")
    func initialLongHeader() {
        let dcid: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let scid: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
        let frame = quicFrame(quicLongHeader(firstByte: 0xC0, version: 1, dcid: dcid, scid: scid))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .quic)
        #expect(packet.transport == .udp)
        #expect(packet.protocolStack == [.ipv4, .udp, .quic])
        // The UDP five-tuple is untouched by app-layer enrichment.
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.168.1.30", port: 55_000))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "142.250.72.196", port: 443))
        #expect(packet.fiveTuple?.proto == .udp)

        let quic = packet.layer(.quic)
        #expect(quic?.fields.contains(DecodedField(name: "Packet Type", value: "Initial")) == true)
        #expect(quic?.fields.contains(DecodedField(name: "Version", value: "0x00000001")) == true)
        #expect(quic?.fields.contains(DecodedField(name: "Destination CID", value: "0102030405060708")) == true)
        #expect(quic?.fields.contains(DecodedField(name: "Source CID", value: "aabbccdd")) == true)
    }

    @Test("The v1 packet-type bits name 0-RTT, Handshake, and Retry")
    func packetTypeNames() {
        let cases: [(UInt8, String)] = [(0xC0, "Initial"), (0xD0, "0-RTT"), (0xE0, "Handshake"), (0xF0, "Retry")]
        for (firstByte, name) in cases {
            let frame = quicFrame(quicLongHeader(firstByte: firstByte, version: 1, dcid: [0x01, 0x02], scid: [0x03]))
            let packet = decodeFrame(frame)
            #expect(packet.layer(.quic)?.fields.contains(DecodedField(name: "Packet Type", value: name)) == true)
        }
    }

    @Test("A zero-length source connection ID is labelled honestly")
    func zeroLengthSourceCID() {
        let frame = quicFrame(quicLongHeader(firstByte: 0xC0, version: 1, dcid: [0x01, 0x02, 0x03, 0x04], scid: []))
        let packet = decodeFrame(frame)
        #expect(packet.layer(.quic)?.fields.contains(
            DecodedField(name: "Source CID", value: "(zero-length)")
        ) == true)
    }

    @Test("Version 0 is labelled Version Negotiation")
    func versionNegotiation() {
        let frame = quicFrame(quicLongHeader(firstByte: 0x80, version: 0, dcid: [0x01, 0x02], scid: [0x03, 0x04]))
        let packet = decodeFrame(frame)

        let quic = packet.layer(.quic)
        #expect(quic?.summary == "Version Negotiation")
        #expect(quic?.fields.contains(DecodedField(name: "Packet Type", value: "Version Negotiation")) == true)
        #expect(quic?.fields.contains(
            DecodedField(name: "Version", value: "Version Negotiation (0x00000000)")
        ) == true)
    }

    @Test("A non-v1 version renders the raw type rather than assuming the v1 mapping")
    func nonV1VersionRawType() {
        // QUIC v2 (RFC 9369) is 0x6b3343cf and remaps the type codepoints, so the
        // v1 names must not be applied to it.
        let frame = quicFrame(quicLongHeader(firstByte: 0xC0, version: 0x6B3343CF, dcid: [0x01], scid: [0x02]))
        let packet = decodeFrame(frame)

        let quic = packet.layer(.quic)
        #expect(quic?.fields.contains(DecodedField(name: "Packet Type", value: "Long Header (type 0)")) == true)
        #expect(quic?.fields.contains(DecodedField(name: "Version", value: "0x6b3343cf")) == true)
    }

    @Test("A connection ID length over the 20-byte cap stays UDP")
    func oversizedCIDStaysUDP() {
        // A 21-byte DCID exceeds RFC 9000's 20-byte maximum: never trust the parse.
        let dcid = [UInt8](repeating: 0x11, count: 21)
        let frame = quicFrame(quicLongHeader(firstByte: 0xC0, version: 1, dcid: dcid, scid: [0x02]))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("A truncated long header stays UDP rather than becoming a false-positive QUIC session")
    func truncatedHeaderStaysUDP() {
        // Long-header form bit set, but the header is cut before the version field.
        let frame = quicFrame([0xC0, 0x00, 0x00])
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("Truncating a valid QUIC frame to every prefix never crashes")
    func truncatedPrefixesNeverCrash() {
        let frame = quicFrame(quicLongHeader(
            firstByte: 0xC0, version: 1, dcid: [0x01, 0x02, 0x03, 0x04], scid: [0xAA, 0xBB]
        ))
        for length in 0 ..< frame.count {
            _ = decodeFrame(Array(frame.prefix(length)))
        }
        #expect(decodeFrame(frame).appProtocol == .quic)
    }

    @Test("A short-header QUIC packet stays UDP per the existing gate")
    func shortHeaderStaysUDP() {
        // Header form bit clear (0x40) — the decoder never guesses a short header's
        // encrypted fields, so it stays a bare UDP datagram.
        let frame = quicFrame([0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("A long header on a non-443 port stays UDP")
    func longHeaderOffPortStaysUDP() {
        let frame = quicFrame(
            quicLongHeader(firstByte: 0xC0, version: 1, dcid: [0x01, 0x02], scid: [0x03]),
            srcPort: 55_000,
            dstPort: 4_433
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("Ordinary UDP/443 payload without the long-header bit is not mistaken for QUIC")
    func nonQUICUDPStaysUDP() {
        let frame = quicFrame([UInt8](repeating: 0x00, count: 32))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("An arbitrary UDP/443 payload with only the high bit set is not mistaken for QUIC")
    func highBitAloneIsNotQUIC() {
        let frame = quicFrame([0x80, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF])
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }
}
