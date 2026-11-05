import Foundation

/// Generates an explicit, inspectable IP/UDP envelope for application bytes.
/// The source bytes remain the complete UDP payload; no payload byte is changed.
nonisolated enum SyntheticUDPPacketBuilder {
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
            throw HexDumpCaptureParser.ParseError.invalidSyntheticUDPOptions
        }
        let overhead = (linkType == LinkType.ethernet ? 14 : 0) + (options.ipv6 ? 40 : 20) + 8
        let maxPayload = options.ipv6 ? 65_535 - 8 : 65_535 - 20 - 8
        var totalBytes = 0
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
            let udpLength = payload.count + 8
            var udp = SyntheticIPPacketEnvelope.word(srcPort)
                + SyntheticIPPacketEnvelope.word(dstPort)
                + SyntheticIPPacketEnvelope.word(udpLength) + [0, 0]
            let pseudo = SyntheticIPPacketEnvelope.pseudoHeader(
                source: srcIP, destination: dstIP, transportLength: udpLength,
                protocolNumber: 17, ipv6: options.ipv6
            )
            let ip = SyntheticIPPacketEnvelope.ipHeader(
                source: srcIP, destination: dstIP, transportLength: udpLength,
                protocolNumber: 17, ipv6: options.ipv6
            )
            let udpChecksum = SyntheticIPPacketEnvelope.checksum(pseudo + udp + payload)
            let transmittedChecksum = udpChecksum == 0 ? UInt16.max : udpChecksum
            udp[6] = UInt8(transmittedChecksum >> 8)
            udp[7] = UInt8(transmittedChecksum & 0xFF)
            let ethernet = linkType == LinkType.ethernet
                ? SyntheticIPPacketEnvelope.ethernetHeader(inbound: inbound, ipv6: options.ipv6) : []
            let bytes = ethernet + ip + udp + payload
            guard bytes.count <= maxFrameBytes else {
                throw HexDumpCaptureParser.ParseError.invalidSyntheticUDP(packet: index + 1)
            }
            return CapturedFrame(
                bytes: bytes, timestamp: frame.timestamp, originalLength: bytes.count,
                linkType: linkType, direction: frame.direction, packetID: frame.packetID
            )
        }
    }
}
