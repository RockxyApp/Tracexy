import Foundation

/// Wraps application bytes in an explicitly generated TCP/IP envelope.
/// Sequence numbers are local to this import, starting at zero in each direction;
/// no handshake, acknowledgment, or observed connection state is invented.
nonisolated enum SyntheticTCPPacketBuilder {
    struct Options: Sendable {
        let sourceAddress: String
        let destinationAddress: String
        let sourcePort: Int
        let destinationPort: Int
        let ipv6: Bool
    }

    static func wrap(
        _ frames: [CapturedFrame], options: Options, linkType: UInt32,
        maxFrameBytes: Int, maxTotalFrameBytes: Int
    )
        throws -> [CapturedFrame]
    {
        guard linkType == LinkType.ethernet || linkType == LinkType.raw,
              (1 ... 65_535).contains(options.sourcePort),
              (1 ... 65_535).contains(options.destinationPort),
              let source = SyntheticIPPacketEnvelope.address(options.sourceAddress, ipv6: options.ipv6),
              let destination = SyntheticIPPacketEnvelope.address(options.destinationAddress, ipv6: options.ipv6) else
        {
            throw HexDumpCaptureParser.ParseError.invalidSyntheticTCPOptions
        }
        let overhead = (linkType == LinkType.ethernet ? 14 : 0) + (options.ipv6 ? 40 : 20) + 20
        let maxPayload = options.ipv6 ? 65_535 - 20 : 65_535 - 20 - 20
        var totalBytes = 0
        var outboundSequence: UInt32 = 0
        var inboundSequence: UInt32 = 0
        return try frames.enumerated().map { index, frame in
            let payload = frame.bytes
            guard payload.count <= maxPayload, payload.count <= maxFrameBytes - overhead,
                  totalBytes <= maxTotalFrameBytes - payload.count - overhead else
            {
                throw HexDumpCaptureParser.ParseError.inputTooLarge
            }
            totalBytes += payload.count + overhead
            let inbound = frame.direction == .inbound
            let srcIP = inbound ? destination : source
            let dstIP = inbound ? source : destination
            let srcPort = inbound ? options.destinationPort : options.sourcePort
            let dstPort = inbound ? options.sourcePort : options.destinationPort
            let sequence = inbound ? inboundSequence : outboundSequence
            if inbound {
                inboundSequence += UInt32(payload.count)
            } else {
                outboundSequence += UInt32(payload.count)
            }
            let transportLength = payload.count + 20
            var tcp = SyntheticIPPacketEnvelope.word(srcPort)
                + SyntheticIPPacketEnvelope.word(dstPort)
                + SyntheticIPPacketEnvelope.doubleWord(sequence)
                + [0, 0, 0, 0, 0x50, 0x08, 0xFF, 0xFF, 0, 0, 0, 0]
            let pseudo = SyntheticIPPacketEnvelope.pseudoHeader(
                source: srcIP, destination: dstIP, transportLength: transportLength,
                protocolNumber: 6, ipv6: options.ipv6
            )
            let value = SyntheticIPPacketEnvelope.checksum(pseudo + tcp + payload)
            tcp[16] = UInt8(value >> 8)
            tcp[17] = UInt8(value & 0xFF)
            let ip = SyntheticIPPacketEnvelope.ipHeader(
                source: srcIP, destination: dstIP, transportLength: transportLength,
                protocolNumber: 6, ipv6: options.ipv6
            )
            let ethernet = linkType == LinkType.ethernet
                ? SyntheticIPPacketEnvelope.ethernetHeader(inbound: inbound, ipv6: options.ipv6) : []
            let bytes = ethernet + ip + tcp + payload
            guard bytes.count <= maxFrameBytes else {
                throw HexDumpCaptureParser.ParseError.invalidSyntheticTCP(packet: index + 1)
            }
            return CapturedFrame(
                bytes: bytes, timestamp: frame.timestamp, originalLength: bytes.count,
                linkType: linkType, direction: frame.direction, packetID: frame.packetID
            )
        }
    }
}
