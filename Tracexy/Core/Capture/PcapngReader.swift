import Foundation

// MARK: - PcapngReader

/// Reader for the pcapng (`.pcapng`) capture format — Wireshark's default. Handles
/// the blocks Tracexy needs to rebuild sessions: the Section Header Block (for byte
/// order), Interface Description Blocks (link type + timestamp resolution), and the
/// Enhanced / Simple Packet Blocks (the frames). Both byte orders are supported;
/// per-interface `if_tsresol` is honored (default microseconds).
nonisolated enum PcapngReader {
    // MARK: Internal

    /// Whether a byte blob looks like a pcapng file (starts with a Section Header Block).
    static func isPcapng(_ data: [UInt8]) -> Bool {
        data.count >= 4 && data[0] == 0x0A && data[1] == 0x0D && data[2] == 0x0D && data[3] == 0x0A
    }

    static func read(_ data: [UInt8]) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        let buffer = PacketBuffer(data)
        guard buffer.length >= 12 else {
            throw PacketError.malformed("pcapng: shorter than a block header")
        }
        // Byte-order magic lives at offset 8 of the Section Header Block.
        let magicBE = try buffer.u32(8)
        let little: Bool
        switch magicBE {
        case 0x1A2B3C4D: little = false
        case 0x4D3C2B1A: little = true
        default: throw PacketError.malformed(String(format: "pcapng: bad byte-order magic 0x%08X", magicBE))
        }

        func r16(_ offset: Int) throws -> UInt16 {
            try little ? buffer.u16le(offset) : buffer.u16(offset)
        }
        func r32(_ offset: Int) throws -> UInt32 {
            try little ? buffer.u32le(offset) : buffer.u32(offset)
        }

        var interfaces: [Interface] = []
        var frames: [CapturedFrame] = []
        var offset = 0

        while offset + 12 <= buffer.length {
            let blockType = try r32(offset)
            let totalLength = try Int(r32(offset + 4))
            // A block is at least 12 bytes and 32-bit aligned; stop on anything bogus.
            guard totalLength >= 12, offset + totalLength <= buffer.length, totalLength % 4 == 0 else {
                break
            }
            let body = offset + 8

            switch blockType {
            case 0x00000001: // Interface Description Block
                let linkType = try UInt32(r16(body))
                let tsResolution = try interfaceTimestampResolution(
                    buffer: buffer, r16: r16, optionsStart: body + 8, blockEnd: offset + totalLength - 4
                )
                interfaces.append(Interface(linkType: linkType, ticksPerSecond: tsResolution))

            case 0x00000006: // Enhanced Packet Block
                let interfaceID = try Int(r32(body))
                let tsHigh = try UInt64(r32(body + 4))
                let tsLow = try UInt64(r32(body + 8))
                let capturedLength = try Int(r32(body + 12))
                let originalLength = try Int(r32(body + 16))
                guard capturedLength >= 0, body + 20 + capturedLength <= offset + totalLength else {
                    break
                }
                let payload = try buffer.bytes(body + 20, capturedLength)
                let ticks = (tsHigh << 32) | tsLow
                let perSecond = interfaces.indices.contains(interfaceID)
                    ? interfaces[interfaceID].ticksPerSecond : 1_000_000
                frames.append(CapturedFrame(
                    bytes: payload,
                    timestamp: Date(timeIntervalSince1970: Double(ticks) / Double(perSecond)),
                    originalLength: max(originalLength, capturedLength)
                ))

            case 0x00000003: // Simple Packet Block (no per-packet timestamp)
                let originalLength = try Int(r32(body))
                let available = offset + totalLength - 4 - (body + 4)
                let capturedLength = max(0, min(originalLength, available))
                let payload = try buffer.bytes(body + 4, capturedLength)
                frames.append(CapturedFrame(
                    bytes: payload,
                    timestamp: Date(timeIntervalSince1970: 0),
                    originalLength: max(originalLength, capturedLength)
                ))

            default:
                break // Section Header, Name Resolution, Statistics, etc. — skipped.
            }

            offset += totalLength
        }

        guard let linkType = interfaces.first?.linkType else {
            throw PacketError.malformed("pcapng: no interface description block")
        }
        return (linkType, frames)
    }

    /// Read a pcapng file from a URL.
    static func read(contentsOf url: URL) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        try read([UInt8](Data(contentsOf: url)))
    }

    // MARK: Private

    private struct Interface {
        let linkType: UInt32
        /// Timestamp ticks per second (10^6 for the microsecond default).
        let ticksPerSecond: UInt64
    }

    /// Walk an IDB's options for `if_tsresol` (code 9) and return ticks-per-second.
    private static func interfaceTimestampResolution(
        buffer: PacketBuffer,
        r16: (Int) throws -> UInt16,
        optionsStart: Int,
        blockEnd: Int
    )
        throws -> UInt64
    {
        var cursor = optionsStart
        while cursor + 4 <= blockEnd {
            let code = try r16(cursor)
            let length = try Int(r16(cursor + 2))
            if code == 0 { // opt_endofopt
                break
            }
            if code == 9, length >= 1, cursor + 4 < buffer.length { // if_tsresol
                let raw = try buffer.u8(cursor + 4)
                if raw & 0x80 != 0 {
                    return 1 << UInt64(raw & 0x7F) // power of two
                }
                return pow10(raw & 0x7F)
            }
            cursor += 4 + length + ((4 - length % 4) % 4) // value padded to 32 bits
        }
        return 1_000_000 // default: microseconds
    }

    private static func pow10(_ exponent: UInt8) -> UInt64 {
        var result: UInt64 = 1
        for _ in 0 ..< exponent {
            result &*= 10
        }
        return result
    }
}
