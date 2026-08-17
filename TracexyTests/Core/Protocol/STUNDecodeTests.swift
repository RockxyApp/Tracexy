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

/// A fixed 20-byte STUN header (RFC 5389) plus optional attribute bytes. `length`
/// is written verbatim so tests can exercise honest and malformed declarations.
private func stunMessage(
    type: UInt16,
    length: UInt16,
    cookie: UInt32 = 0x2112A442,
    transactionID: [UInt8] = Array(repeating: 0xAB, count: 12),
    attributes: [UInt8] = []
)
    -> [UInt8]
{
    var bytes: [UInt8] = [UInt8(type >> 8), UInt8(type & 0xFF), UInt8(length >> 8), UInt8(length & 0xFF)]
    bytes += [
        UInt8((cookie >> 24) & 0xFF),
        UInt8((cookie >> 16) & 0xFF),
        UInt8((cookie >> 8) & 0xFF),
        UInt8(cookie & 0xFF),
    ]
    bytes += transactionID
    bytes += attributes
    return bytes
}

/// One STUN attribute TLV (RFC 5389 §15): 2-byte type, 2-byte value length, the
/// value, and 4-byte-boundary padding. `length` is written from the real value
/// length so a caller can compose a well-formed attribute region.
private func stunAttribute(type: UInt16, value: [UInt8]) -> [UInt8] {
    var bytes: [UInt8] = [UInt8(type >> 8), UInt8(type & 0xFF), UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
    bytes += value
    while bytes.count % 4 != 0 {
        bytes.append(0)
    }
    return bytes
}

/// Wraps a STUN message in Ethernet + IPv4 + UDP on ephemeral ICE-style ports —
/// STUN detection is content-based, so the ports are deliberately not well-known.
private func stunFrame(
    _ message: [UInt8],
    src: String = "192.168.1.20",
    dst: String = "18.184.7.9",
    srcPort: UInt16 = 54_321,
    dstPort: UInt16 = 51_820
)
    -> [UInt8]
{
    PacketBuilder.ethernetIPv4(
        proto: 17,
        src: src,
        dst: dst,
        payload: PacketBuilder.udp(srcPort: srcPort, dstPort: dstPort, payload: message)
    )
}

private extension DecodedPacket {
    func layer(_ kind: ProtocolKind) -> DecodedLayer? {
        layers.first { $0.proto == kind }
    }
}

// MARK: - STUNDecodeTests

@Suite("STUN decode")
struct STUNDecodeTests {
    @Test("Binding Request decodes over the preserved UDP five-tuple")
    func bindingRequest() {
        let frame = stunFrame(stunMessage(type: 0x0001, length: 0))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .stun)
        #expect(packet.transport == .udp)
        #expect(packet.protocolStack == [.ipv4, .udp, .stun])

        // The UDP five-tuple and endpoints are untouched by app-layer enrichment.
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.168.1.20", port: 54_321))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "18.184.7.9", port: 51_820))
        #expect(packet.fiveTuple?.proto == .udp)

        let stun = packet.layer(.stun)
        #expect(stun?.summary == "Binding Request")
        #expect(stun?.fields.contains(DecodedField(name: "Message Type", value: "Binding Request (0x0001)")) == true)
        #expect(stun?.fields.contains(DecodedField(name: "Message Length", value: "0")) == true)
        #expect(stun?.fields.contains(DecodedField(name: "Magic Cookie", value: "0x2112a442")) == true)
        #expect(stun?.fields.contains(
            DecodedField(name: "Transaction ID", value: "abababababababababababab")
        ) == true)
    }

    @Test("Binding Success Response with attributes reports the declared length")
    func bindingSuccessResponse() {
        // 8 bytes of (unparsed) attribute data; declared length must match.
        let attributes = [UInt8](repeating: 0x20, count: 8)
        let frame = stunFrame(stunMessage(type: 0x0101, length: 8, attributes: attributes))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .stun)
        let stun = packet.layer(.stun)
        #expect(stun?.summary == "Binding Success Response")
        #expect(stun?.fields.contains(DecodedField(name: "Message Length", value: "8")) == true)
    }

    @Test("Content detection remains port-independent on a DNS-associated port")
    func stunOnPort53() {
        let frame = stunFrame(stunMessage(type: 0x0001, length: 0), dstPort: 53)
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .stun)
        #expect(packet.protocolStack == [.ipv4, .udp, .stun])
    }

    @Test("An unknown but valid STUN type uses an honest hex fallback")
    func unknownTypeHexFallback() {
        let frame = stunFrame(stunMessage(type: 0x0002, length: 0))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .stun)
        #expect(packet.layer(.stun)?.summary == "0x0002")
    }

    @Test("A wrong magic cookie is not misclassified — the session stays UDP")
    func invalidCookieStaysUDP() {
        let frame = stunFrame(stunMessage(type: 0x0001, length: 0, cookie: 0xDEADBEEF))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("A non-aligned declared length is rejected")
    func nonAlignedLengthStaysUDP() {
        // 2 is not a multiple of 4, so the attribute length is malformed.
        let frame = stunFrame(stunMessage(type: 0x0001, length: 2, attributes: [0x00, 0x00]))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("A declared length exceeding the captured payload is rejected")
    func oversizedLengthStaysUDP() {
        // Claims 100 attribute bytes that are not present in the 20-byte payload.
        let frame = stunFrame(stunMessage(type: 0x0001, length: 100))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("A set leading type bit is rejected")
    func nonZeroLeadingBitsStayUDP() {
        // 0xC001 has both leading type bits set, which STUN forbids.
        let frame = stunFrame(stunMessage(type: 0xC001, length: 0))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
    }

    @Test("Ordinary UDP payload is never mistaken for STUN")
    func nonSTUNUDPStaysUDP() {
        let frame = stunFrame([UInt8](repeating: 0x00, count: 20))
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .udp])
    }

    @Test("Truncating a valid STUN frame to every prefix never crashes or misclassifies")
    func truncatedSTUN() {
        let frame = stunFrame(stunMessage(type: 0x0101, length: 8, attributes: [UInt8](repeating: 0x20, count: 8)))
        for length in 0 ..< frame.count {
            let prefix = Array(frame.prefix(length))
            let packet = decodeFrame(prefix)
            // Any cut into the STUN bytes leaves the declared length unsatisfiable,
            // so a truncated frame must never surface as STUN.
            #expect(packet.appProtocol != .stun)
        }
        // The full frame still decodes as STUN (sanity).
        #expect(decodeFrame(frame).appProtocol == .stun)
    }

    // MARK: Attributes

    @Test("A MAPPED-ADDRESS attribute decodes its IPv4 reflexive address and port")
    func mappedAddressIPv4() {
        // reserved(0) family(IPv4=1) port(3478=0x0D96) address(198.51.100.7)
        let value: [UInt8] = [0x00, 0x01, 0x0D, 0x96, 198, 51, 100, 7]
        let attribute = stunAttribute(type: 0x0001, value: value)
        let frame = stunFrame(stunMessage(type: 0x0101, length: UInt16(attribute.count), attributes: attribute))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .stun)
        #expect(packet.layer(.stun)?.fields.contains(
            DecodedField(name: "Attribute: MAPPED-ADDRESS", value: "198.51.100.7:3478")
        ) == true)
    }

    @Test("An XOR-MAPPED-ADDRESS attribute un-masks its IPv4 address and port")
    func xorMappedAddressIPv4() {
        // 203.0.113.5:50000, XOR-masked with the magic cookie (address) and its
        // high half 0x2112 (port): X-port 0xE242, X-addr EA.12.D5.47.
        let value: [UInt8] = [0x00, 0x01, 0xE2, 0x42, 0xEA, 0x12, 0xD5, 0x47]
        let attribute = stunAttribute(type: 0x0020, value: value)
        let frame = stunFrame(stunMessage(type: 0x0101, length: UInt16(attribute.count), attributes: attribute))
        let packet = decodeFrame(frame)

        #expect(packet.layer(.stun)?.fields.contains(
            DecodedField(name: "Attribute: XOR-MAPPED-ADDRESS", value: "203.0.113.5:50000")
        ) == true)
    }

    @Test("A named non-address attribute surfaces its name and a byte count, and padding is skipped")
    func namedAttributeWithPadding() {
        // SOFTWARE (0x8022) with a 3-byte value → one byte of 4-boundary padding.
        let software = stunAttribute(type: 0x8022, value: [0x61, 0x62, 0x63])
        let mapped = stunAttribute(type: 0x0001, value: [0x00, 0x01, 0x0D, 0x96, 198, 51, 100, 7])
        let attributes = software + mapped
        let frame = stunFrame(stunMessage(type: 0x0101, length: UInt16(attributes.count), attributes: attributes))
        let packet = decodeFrame(frame)

        let stun = packet.layer(.stun)
        #expect(stun?.fields.contains(DecodedField(name: "Attribute: SOFTWARE", value: "3 bytes")) == true)
        // The second attribute is only reachable if the first's padding was skipped.
        #expect(stun?.fields.contains(
            DecodedField(name: "Attribute: MAPPED-ADDRESS", value: "198.51.100.7:3478")
        ) == true)
    }

    @Test("An unknown attribute type uses an honest hex label and a byte count")
    func unknownAttributeHexLabel() {
        let attribute = stunAttribute(type: 0x7F00, value: [0xDE, 0xAD, 0xBE, 0xEF])
        let frame = stunFrame(stunMessage(type: 0x0101, length: UInt16(attribute.count), attributes: attribute))
        let packet = decodeFrame(frame)

        #expect(packet.layer(.stun)?.fields.contains(
            DecodedField(name: "Attribute: 0x7f00", value: "4 bytes")
        ) == true)
    }

    @Test("An IPv6-family MAPPED-ADDRESS stays metadata-only rather than fabricating an address")
    func ipv6MappedAddressStaysMetadataOnly() {
        // Family 0x02 (IPv6) with 16 address bytes — we decode IPv4 only.
        let value: [UInt8] = [0x00, 0x02, 0x0D, 0x96] + [UInt8](repeating: 0x11, count: 16)
        let attribute = stunAttribute(type: 0x0001, value: value)
        let frame = stunFrame(stunMessage(type: 0x0101, length: UInt16(attribute.count), attributes: attribute))
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .stun)
        #expect(packet.layer(.stun)?.fields.contains(
            DecodedField(name: "Attribute: MAPPED-ADDRESS", value: "20 bytes")
        ) == true)
    }

    @Test("An attribute whose declared value overruns the message keeps the record without trapping")
    func overrunningAttributeStopsWalk() {
        // Declared attribute value length 0xFF, but only 4 value bytes are present
        // inside the 8-byte declared attribute region — the walk must stop safely.
        let attributes: [UInt8] = [0x00, 0x06, 0x00, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD]
        let frame = stunFrame(stunMessage(type: 0x0101, length: 8, attributes: attributes))
        let packet = decodeFrame(frame)

        // The header-level record survives; the malformed attribute is not surfaced.
        #expect(packet.appProtocol == .stun)
        let stun = packet.layer(.stun)
        #expect(stun?.fields.contains(DecodedField(name: "Message Length", value: "8")) == true)
        #expect(stun?.fields.contains { $0.name.hasPrefix("Attribute:") } == false)
    }
}
