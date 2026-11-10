import Foundation

/// Generates an explicit SCTP/IP envelope for supplied chunk bytes or
/// application bytes. Neither mode claims a real association or handshake.
nonisolated enum SyntheticSCTPPacketBuilder {
    // MARK: Internal

    enum Mode: Sendable {
        /// Source bytes are already complete SCTP chunks.
        case chunks(verificationTag: UInt32)
        /// Source bytes are one application message in a synthetic DATA chunk.
        case data(payloadProtocolIdentifier: UInt32)
    }

    struct Options: Sendable {
        let sourceAddress: String
        let destinationAddress: String
        let sourcePort: Int
        let destinationPort: Int
        let ipv6: Bool
        let mode: Mode
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
            throw HexDumpCaptureParser.ParseError.invalidSyntheticSCTPOptions
        }
        let ipOverhead = options.ipv6 ? 40 : 20
        let ethernetOverhead = linkType == LinkType.ethernet ? 14 : 0
        let maxTransportBytes = options.ipv6 ? 65_535 : 65_535 - 20
        var totalBytes = 0
        var outboundTSN: UInt32 = 0
        var inboundTSN: UInt32 = 0
        return try frames.enumerated().map { index, frame in
            try Task.checkCancellation()
            let inbound = frame.direction == .inbound
            let sourceIP = inbound ? destination : source
            let destinationIP = inbound ? source : destination
            let sourcePort = inbound ? options.destinationPort : options.sourcePort
            let destinationPort = inbound ? options.sourcePort : options.destinationPort
            let tag: UInt32
            let chunks: [UInt8]
            switch options.mode {
            case let .chunks(verificationTag):
                guard validChunks(frame.bytes) else {
                    throw HexDumpCaptureParser.ParseError.invalidSyntheticSCTP(packet: index + 1)
                }
                tag = verificationTag
                chunks = frame.bytes
            case let .data(ppi):
                guard frame.bytes.count <= 65_535 - 16 else {
                    throw HexDumpCaptureParser.ParseError.inputTooLarge
                }
                let tsn = inbound ? inboundTSN : outboundTSN
                if inbound {
                    inboundTSN &+= 1
                } else {
                    outboundTSN &+= 1
                }
                let length = 16 + frame.bytes.count
                let padding = (4 - length % 4) % 4
                chunks = [0, 3] + SyntheticIPPacketEnvelope.word(length)
                    + SyntheticIPPacketEnvelope.doubleWord(tsn)
                    + [0, 0, 0, 0]
                    + SyntheticIPPacketEnvelope.doubleWord(ppi)
                    + frame.bytes + [UInt8](repeating: 0, count: padding)
                tag = 0
            }
            var sctp = SyntheticIPPacketEnvelope.word(sourcePort)
                + SyntheticIPPacketEnvelope.word(destinationPort)
                + SyntheticIPPacketEnvelope.doubleWord(tag)
                + [0, 0, 0, 0] + chunks
            guard sctp.count <= maxTransportBytes else {
                throw HexDumpCaptureParser.ParseError.inputTooLarge
            }
            let checksum = SCTPChecksum.value(sctp)
            sctp.replaceSubrange(8 ..< 12, with: SyntheticIPPacketEnvelope.doubleWord(checksum))
            let ip = SyntheticIPPacketEnvelope.ipHeader(
                source: sourceIP, destination: destinationIP,
                transportLength: sctp.count, protocolNumber: 132, ipv6: options.ipv6
            )
            let ethernet = linkType == LinkType.ethernet
                ? SyntheticIPPacketEnvelope.ethernetHeader(inbound: inbound, ipv6: options.ipv6) : []
            let byteCount = ethernetOverhead + ipOverhead + sctp.count
            guard byteCount <= maxFrameBytes,
                  byteCount <= maxTotalFrameBytes - totalBytes else
            {
                throw HexDumpCaptureParser.ParseError.inputTooLarge
            }
            totalBytes += byteCount
            return CapturedFrame(
                bytes: ethernet + ip + sctp, timestamp: frame.timestamp,
                originalLength: byteCount, linkType: linkType,
                direction: frame.direction, packetID: frame.packetID
            )
        }
    }

    // MARK: Private

    private static func validChunks(_ bytes: [UInt8]) -> Bool {
        var offset = 0
        var count = 0
        while offset < bytes.count {
            guard count < 64, bytes.count - offset >= 4 else {
                return false
            }
            let type = bytes[offset]
            let length = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            guard length >= (type == 0 ? 16 : 4), length <= bytes.count - offset else {
                return false
            }
            count += 1
            let padded = (length + 3) & ~3
            guard padded <= bytes.count - offset || length == bytes.count - offset else {
                return false
            }
            offset += min(padded, bytes.count - offset)
        }
        return count > 0
    }
}
