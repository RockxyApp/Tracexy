import Foundation

// MARK: - SCTPChecksum

/// SCTP's CRC32C covers its common header and all chunks, with the four
/// checksum bytes treated as zero. The result is placed in network byte order.
nonisolated enum SCTPChecksum {
    static func value(_ bytes: [UInt8]) -> UInt32 {
        crc32c(bytes.enumerated().map { index, byte in (8 ..< 12).contains(index) ? 0 : byte }).byteSwapped
    }

    static func crc32c(_ bytes: [UInt8]) -> UInt32 {
        var remainder: UInt32 = .max
        for byte in bytes {
            remainder ^= UInt32(byte)
            for _ in 0 ..< 8 {
                remainder = (remainder >> 1) ^ ((remainder & 1) == 0 ? 0 : 0x82F63B78)
            }
        }
        return ~remainder
    }
}

extension PacketDecoder {
    /// Bounded SCTP common-header and chunk recognition. This exposes wire
    /// facts without claiming association establishment or stream reassembly.
    static func sctp(
        _ buf: PacketBuffer, src: String, dst: String, isComplete: Bool?, into packet: inout DecodedPacket
    )
        throws
    {
        guard buf.length >= 12 else {
            throw PacketError.outOfBounds(offset: 0, need: 12, have: buf.length)
        }
        let sourcePort = try buf.u16(0)
        let destinationPort = try buf.u16(2)
        let verificationTag = try buf.u32(4)
        let checksum = try buf.u32(8)
        func incompleteStop(_ reason: String) -> DecodeStop {
            isComplete == true ? .malformed(reason) : .cutShort
        }
        var fields = [
            ranged("Source Port", "\(sourcePort)", in: buf, at: 0, 2),
            ranged("Destination Port", "\(destinationPort)", in: buf, at: 2, 2),
            ranged("Verification Tag", hex(verificationTag, digits: 8), in: buf, at: 4, 4),
            ranged("CRC32C", hex(checksum, digits: 8), in: buf, at: 8, 4),
        ]
        var offset = 12
        var chunkCount = 0
        var omittedChunks = false
        var chunkTypes: [UInt8] = []
        while offset < buf.length {
            guard buf.length - offset >= 4 else {
                packet.decodeStop = incompleteStop("SCTP packet ends with an incomplete chunk header")
                break
            }
            let chunkType = try buf.u8(offset)
            let chunkLength = try Int(buf.u16(offset + 2))
            guard chunkLength >= 4 else {
                packet.decodeStop = .malformed("Invalid SCTP chunk length")
                break
            }
            fields.append(ranged("Chunk \(chunkCount + 1) Type", "\(chunkType)", in: buf, at: offset, 1))
            fields.append(ranged("Chunk \(chunkCount + 1) Length", "\(chunkLength) bytes", in: buf, at: offset + 2, 2))
            guard chunkLength <= buf.length - offset else {
                packet.decodeStop = incompleteStop("Invalid SCTP chunk length")
                break
            }
            if chunkCount == 64 {
                if chunkType == 0, chunkLength < 16 {
                    packet.decodeStop = .malformed("SCTP DATA chunk is shorter than its fixed header")
                } else {
                    let paddedLength = (chunkLength + 3) & ~3
                    if paddedLength > buf.length - offset, chunkLength != buf.length - offset {
                        packet.decodeStop = incompleteStop("SCTP chunk padding is incomplete")
                    } else {
                        omittedChunks = true
                    }
                }
                break
            }
            if chunkType == 0 {
                guard chunkLength >= 16 else {
                    packet.decodeStop = .malformed("SCTP DATA chunk is shorter than its fixed header")
                    break
                }
                try fields.append(ranged("DATA TSN", "\(buf.u32(offset + 4))", in: buf, at: offset + 4, 4))
                try fields.append(ranged("DATA PPI", "\(buf.u32(offset + 12))", in: buf, at: offset + 12, 4))
            }
            chunkCount += 1
            chunkTypes.append(chunkType)
            let paddedLength = (chunkLength + 3) & ~3
            // The last chunk may omit final padding; its declared length still
            // excludes padding, and no padding byte is treated as a new chunk.
            guard paddedLength <= buf.length - offset || chunkLength == buf.length - offset else {
                packet.decodeStop = incompleteStop("SCTP chunk padding is incomplete")
                break
            }
            offset += min(paddedLength, buf.length - offset)
        }
        if chunkCount == 0, packet.decodeStop == nil, isComplete == true {
            packet.decodeStop = .malformed("SCTP packet has no chunks")
        }
        if isComplete == false, packet.decodeStop == nil {
            packet.decodeStop = .cutShort
        }
        packet.transport = .sctp
        packet.sourceEndpoint = IPEndpoint(ip: src, port: sourcePort)
        packet.destinationEndpoint = IPEndpoint(ip: dst, port: destinationPort)
        // The tuple is what makes an SCTP flow a session rather than a frame that
        // can only be inspected: endpoints, bytes and duration then fold exactly as
        // they do for TCP and UDP. It claims no association — the verification tag
        // identifies one, and a tag is not an endpoint pair — so a path that
        // reuses the same port pair for a new association folds into the same
        // session, like a reused TCP port pair without a SYN.
        packet.fiveTuple = FiveTuple(
            proto: .sctp,
            source: IPEndpoint(ip: src, port: sourcePort),
            destination: IPEndpoint(ip: dst, port: destinationPort)
        )
        packet.sctpFacts = SCTPFacts(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            verificationTag: verificationTag,
            chunkTypes: chunkTypes,
            chunksOmitted: omittedChunks
        )
        if omittedChunks {
            fields.append(DecodedField(name: "Chunks Omitted", value: "At least 1 (retention limit: 64)"))
        }
        packet.layers.append(DecodedLayer(
            proto: .sctp, title: "Stream Control Transmission Protocol",
            summary: "\(sourcePort) → \(destinationPort), \(chunkCount) chunk(s)",
            fields: fields, byteRange: span(buf, buf.length)
        ))
    }
}
