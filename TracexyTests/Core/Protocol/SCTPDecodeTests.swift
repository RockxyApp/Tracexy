import Foundation
import Testing
@testable import Tracexy

@Suite("SCTP bounded decode")
struct SCTPDecodeTests {
    // MARK: Internal

    @Test("CRC32C matches the published Castagnoli check value")
    func crcVector() {
        #expect(SCTPChecksum.crc32c(Array("123456789".utf8)) == 0xE3069283)
    }

    @Test("SCTP checksum bytes use the RFC transport-level mapping")
    func checksumWireByteOrder() {
        #expect(Array(frame()[42 ..< 46]) == [0x46, 0xC1, 0x2D, 0x3C])
    }

    @Test("a complete DATA chunk exposes endpoints, PPI and a checksum-validation target")
    func dataChunk() {
        let packet = PacketDecoder.decode(
            PacketBuffer(frame()), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: frame().count
        )
        #expect(packet.transport == .sctp)
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.0.2.1", port: 5_000))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "192.0.2.2", port: 5_001))
        #expect(packet.layers.contains(where: { $0.proto == .sctp }))
        #expect(packet.layers.first(where: { $0.proto == .sctp })?.fields.contains(
            DecodedField(name: "DATA PPI", value: "42")
        ) == true)
        #expect(ChecksumValidation.statuses(packet.layers, bytes: frame())[
            "Stream Control Transmission Protocol"
        ] == .correct)
        #expect(packet.decodeStop == nil)
    }

    @Test("checksum validation reports a bad CRC without stopping structural decode")
    func badCRC() {
        var bytes = frame()
        bytes[bytes.count - 4] ^= 1
        let packet = PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: bytes.count
        )
        #expect(packet.transport == .sctp)
        #expect(packet.decodeStop == nil)
        #expect(ChecksumValidation.hasIncorrectChecksum(packet.layers, bytes: bytes))
        if case .incorrect32 = ChecksumValidation.statuses(packet.layers, bytes: bytes)[
            "Stream Control Transmission Protocol"
        ] {} else {
            Issue.record("the changed CRC should be reported as incorrect")
        }
    }

    @Test("a snapshot-truncated SCTP packet keeps complete chunks and leaves CRC unverified")
    func captureCutAtChunkBoundary() {
        var complete = frame()
        let secondChunk = Array(complete[46...])
        complete += secondChunk
        let ipLength = complete.count - 14
        complete[16] = UInt8(ipLength >> 8)
        complete[17] = UInt8(ipLength & 0xFF)
        let sctpLength = complete.count - 34
        complete.replaceSubrange(42 ..< 46, with: [0, 0, 0, 0])
        let checksum = SCTPChecksum.value(Array(complete[34 ..< (34 + sctpLength)]))
        complete.replaceSubrange(42 ..< 46, with: SyntheticIPPacketEnvelope.doubleWord(checksum))
        let truncated = Array(complete[..<(46 + secondChunk.count)])

        let packet = PacketDecoder.decode(
            PacketBuffer(truncated), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: complete.count
        )
        let layer = packet.layers.first(where: { $0.proto == .sctp })
        #expect(packet.transport == .sctp)
        #expect(packet.decodeStop == .cutShort)
        #expect(layer?.summary.contains("1 chunk(s)") == true)
        #expect(ChecksumValidation.statuses(packet.layers, bytes: truncated)[
            "Stream Control Transmission Protocol"
        ] == .unverified)
    }

    @Test("a capture ending at the SCTP common header is cut short, not chunkless-malformed")
    func captureCutAtCommonHeaderBoundary() {
        let complete = frame()
        let truncated = Array(complete[..<46])
        let packet = PacketDecoder.decode(
            PacketBuffer(truncated), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: complete.count
        )

        #expect(packet.transport == .sctp)
        #expect(packet.decodeStop == .cutShort)
        #expect(packet.layers.contains(where: { $0.proto == .sctp }))
        #expect(ChecksumValidation.statuses(packet.layers, bytes: truncated)[
            "Stream Control Transmission Protocol"
        ] == .unverified)
    }

    @Test("an unset IPv4 length does not make a captured SCTP prefix structurally malformed")
    func unsetIPLengthLeavesPartialChunkUnverified() {
        var complete = frame()
        complete[16] = 0
        complete[17] = 0
        let truncated = Array(complete.dropLast(8))
        let packet = PacketDecoder.decode(
            PacketBuffer(truncated), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: complete.count
        )

        #expect(packet.transport == .sctp)
        #expect(packet.decodeStop != .malformed("Invalid SCTP chunk length"))
        #expect(ChecksumValidation.statuses(packet.layers, bytes: truncated)[
            "Stream Control Transmission Protocol"
        ] == .unverified)
    }

    @Test("a structurally valid packet with more than 64 chunks reports bounded omission")
    func chunkRetentionLimit() {
        var bytes = frame()
        let firstChunk = Array(bytes[46...])
        bytes = Array(bytes[..<46]) + Array(repeating: firstChunk, count: 65).flatMap { $0 }
        let ipLength = bytes.count - 14
        bytes[16] = UInt8(ipLength >> 8)
        bytes[17] = UInt8(ipLength & 0xFF)
        bytes.replaceSubrange(42 ..< 46, with: [0, 0, 0, 0])
        let checksum = SCTPChecksum.value(Array(bytes[34...]))
        bytes.replaceSubrange(42 ..< 46, with: SyntheticIPPacketEnvelope.doubleWord(checksum))

        let packet = PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: bytes.count
        )
        let layer = packet.layers.first(where: { $0.proto == .sctp })
        #expect(packet.transport == .sctp)
        #expect(packet.decodeStop == nil)
        #expect(layer?.summary.contains("64 chunk(s)") == true)
        #expect(layer?.fields.contains(DecodedField(
            name: "Chunks Omitted", value: "At least 1 (retention limit: 64)"
        )) == true)
    }

    @Test("a stray byte after 64 chunks is not counted as an omitted chunk")
    func malformedTailAfterRetentionLimit() {
        let template = frame()
        let firstChunk = Array(template[46...])
        var bytes = Array(template[..<46]) + Array(repeating: firstChunk, count: 64).flatMap { $0 } + [0xAA]
        let ipLength = bytes.count - 14
        bytes[16] = UInt8(ipLength >> 8)
        bytes[17] = UInt8(ipLength & 0xFF)
        bytes.replaceSubrange(42 ..< 46, with: [0, 0, 0, 0])
        let checksum = SCTPChecksum.value(Array(bytes[34...]))
        bytes.replaceSubrange(42 ..< 46, with: SyntheticIPPacketEnvelope.doubleWord(checksum))

        let packet = PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: bytes.count
        )
        let layer = packet.layers.first(where: { $0.proto == .sctp })
        #expect(packet.decodeStop == .malformed("SCTP packet ends with an incomplete chunk header"))
        #expect(layer?.fields.contains(where: { $0.name == "Chunks Omitted" }) == false)
    }

    @Test("truncated and invalid chunk lengths stop without reading past the frame")
    func invalidLengths() {
        var bytes = frame()
        let chunkLengthOffset = 14 + 20 + 12 + 2
        bytes[chunkLengthOffset] = 0
        bytes[chunkLengthOffset + 1] = 3
        let packet = PacketDecoder.decode(
            PacketBuffer(bytes), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: bytes.count
        )
        #expect(packet.transport == .sctp)
        #expect(packet.layers.contains(where: { $0.proto == .sctp }))
        #expect(packet.decodeStop == .malformed("Invalid SCTP chunk length"))
    }

    // MARK: Private

    private func frame() -> [UInt8] {
        let source = [UInt8]([192, 0, 2, 1])
        let destination = [UInt8]([192, 0, 2, 2])
        let chunk: [UInt8] = [0, 3, 0, 21, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 42]
            + Array("hello".utf8) + [0, 0, 0]
        var sctp = SyntheticIPPacketEnvelope.word(5_000)
            + SyntheticIPPacketEnvelope.word(5_001)
            + SyntheticIPPacketEnvelope.doubleWord(0x12345678)
            + [0, 0, 0, 0] + chunk
        let checksum = SCTPChecksum.value(sctp)
        sctp.replaceSubrange(8 ..< 12, with: SyntheticIPPacketEnvelope.doubleWord(checksum))
        let ip = SyntheticIPPacketEnvelope.ipHeader(
            source: source, destination: destination,
            transportLength: sctp.count, protocolNumber: 132, ipv6: false
        )
        return SyntheticIPPacketEnvelope.ethernetHeader(inbound: false, ipv6: false) + ip + sctp
    }
}
