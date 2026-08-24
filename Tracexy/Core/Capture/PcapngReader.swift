import Foundation

// MARK: - PcapngReader

/// Reader for the pcapng (`.pcapng`) capture format — Wireshark's default. Handles
/// the blocks Tracexy needs to rebuild sessions: the Section Header Block (byte
/// order and version), Interface Description Blocks (link type, snap length and
/// timestamp resolution/offset), and the Enhanced / Simple Packet Blocks (the
/// frames). Both byte orders and multiple sections are supported; each Section
/// Header Block may switch byte order and resets the section-local interface table.
///
/// ``read(_:)`` parses a byte array already resident in memory and validates block
/// alignment/minimum lengths, trailers, interface references, timestamp resolution
/// bounds and packet-length bounds. ``read(contentsOf:)`` streams the file one
/// block at a time through ``PcapngStreamReader`` so a large capture is never
/// loaded whole; the two agree on any well-formed supported file.
nonisolated enum PcapngReader {
    // MARK: Internal

    /// Whether a byte blob looks like a pcapng file (starts with a Section Header
    /// Block, whose type bytes are byte-order independent).
    static func isPcapng(_ data: [UInt8]) -> Bool {
        data.count >= 4 && data[0] == 0x0A && data[1] == 0x0D && data[2] == 0x0D && data[3] == 0x0A
    }

    static func read(_ data: [UInt8]) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        let buffer = PacketBuffer(data)
        let fileLength = data.count
        var frames: [CapturedFrame] = []
        var interfaces: [Interface] = []
        var firstLinkType: UInt32?
        var haveSection = false
        var little = false
        var offset = 0

        while offset + blockHeaderPrefix <= fileLength {
            let isSectionHeader = data[offset] == 0x0A && data[offset + 1] == 0x0D
                && data[offset + 2] == 0x0D && data[offset + 3] == 0x0A
            let sectionLittle: Bool
            if isSectionHeader {
                guard offset + 12 <= fileLength else {
                    // An incomplete first section header is malformed; a later one
                    // that runs off the buffer is a tolerant truncated tail.
                    guard haveSection else {
                        throw PacketError.malformed("pcapng: truncated first section header block")
                    }
                    break
                }
                let magic = try buffer.u32(offset + 8)
                switch magic {
                case byteOrderMagicBig: sectionLittle = false
                case byteOrderMagicLittle: sectionLittle = true
                default:
                    throw PacketError.malformed(String(format: "pcapng: bad byte-order magic 0x%08X", magic))
                }
            } else {
                guard haveSection else {
                    throw PacketError.malformed("pcapng: first block is not a section header block")
                }
                sectionLittle = little
            }

            let type = try isSectionHeader
                ? sectionHeaderType
                : (sectionLittle ? buffer.u32le(offset) : buffer.u32(offset))
            let totalLength = try Int(sectionLittle ? buffer.u32le(offset + 4) : buffer.u32(offset + 4))
            let minimum = minimumLength(forType: type)
            guard totalLength % 4 == 0 else {
                throw PacketError.malformed("pcapng: block length \(totalLength) is not 32-bit aligned")
            }
            guard totalLength >= minimum else {
                throw PacketError.malformed("pcapng: block length \(totalLength) below minimum \(minimum)")
            }
            guard let blockEnd = checkedSum(offset, totalLength), blockEnd <= fileLength else {
                guard haveSection else {
                    throw PacketError.malformed("pcapng: truncated first section header block")
                }
                break // a declared block runs past the buffer: tolerant truncated tail.
            }
            let trailer = try Int(sectionLittle ? buffer.u32le(blockEnd - 4) : buffer.u32(blockEnd - 4))
            guard trailer == totalLength else {
                throw PacketError.malformed("pcapng: block trailer \(trailer) does not equal length \(totalLength)")
            }

            switch type {
            case sectionHeaderType:
                let major = try sectionLittle ? buffer.u16le(offset + 12) : buffer.u16(offset + 12)
                guard major == 1 else {
                    throw PacketError.malformed("pcapng: unsupported version \(major)")
                }
                little = sectionLittle
                haveSection = true
                interfaces.removeAll(keepingCapacity: true)

            case interfaceDescriptionType:
                let interface = try readInterface(
                    buffer: buffer, little: sectionLittle, blockStart: offset, blockEnd: blockEnd
                )
                interfaces.append(interface)
                if firstLinkType == nil {
                    firstLinkType = interface.linkType
                }

            case enhancedPacketType:
                try frames.append(readEnhancedPacket(
                    buffer: buffer, little: sectionLittle, blockStart: offset, blockEnd: blockEnd,
                    interfaces: interfaces
                ))

            case simplePacketType:
                try frames.append(readSimplePacket(
                    buffer: buffer, little: sectionLittle, blockStart: offset, blockEnd: blockEnd,
                    interfaces: interfaces
                ))

            default:
                break // Name resolution, statistics, custom, etc. — trailer validated, skipped.
            }

            offset = blockEnd
        }

        guard let linkType = firstLinkType else {
            throw PacketError.malformed("pcapng: no interface description block")
        }
        return (linkType, frames)
    }

    /// Read a pcapng file from a URL by collecting the bounded streaming reader.
    ///
    /// A truncated tail (a partial block header or body) is *not* an error here:
    /// the walk stops and every complete prior frame is returned. Genuinely corrupt
    /// metadata (bad magic/version, misaligned or undersized length, a trailer
    /// mismatch, an undeclared interface, an out-of-range resolution, or an
    /// over-limit payload) still throws a controlled error. It reports the first
    /// declared interface's link type and errors if the file declares no interface.
    static func read(contentsOf url: URL) throws -> (linkType: UInt32, frames: [CapturedFrame]) {
        let reader = try PcapngStreamReader(contentsOf: url)
        var frames: [CapturedFrame] = []
        loop: while true {
            switch try reader.next() {
            case let .frame(event):
                frames.append(CapturedFrame(
                    bytes: event.bytes,
                    timestamp: event.reference.timestamp,
                    originalLength: event.reference.originalLength,
                    linkType: event.reference.linkType
                ))
            case .end:
                break loop
            }
        }
        guard let linkType = reader.firstDeclaredLinkType else {
            throw PacketError.malformed("pcapng: no interface description block")
        }
        return (linkType, frames)
    }

    // MARK: Private

    private struct Interface {
        let linkType: UInt32
        let snapLength: UInt32
        /// Timestamp ticks per second (10^6 for the microsecond default).
        let ticksPerSecond: UInt64
        /// Signed seconds added to every timestamp on this interface.
        let timestampOffsetSeconds: Int64
    }

    private static let blockHeaderPrefix = 8
    private static let sectionHeaderType: UInt32 = 0x0A0D0D0A
    private static let interfaceDescriptionType: UInt32 = 0x00000001
    private static let simplePacketType: UInt32 = 0x00000003
    private static let enhancedPacketType: UInt32 = 0x00000006
    private static let byteOrderMagicBig: UInt32 = 0x1A2B3C4D
    private static let byteOrderMagicLittle: UInt32 = 0x4D3C2B1A

    private static func minimumLength(forType type: UInt32) -> Int {
        switch type {
        case sectionHeaderType: 28
        case interfaceDescriptionType: 20
        case enhancedPacketType: 32
        case simplePacketType: 16
        default: 12
        }
    }

    private static func readInterface(
        buffer: PacketBuffer,
        little: Bool,
        blockStart: Int,
        blockEnd: Int
    )
        throws -> Interface
    {
        let linkType = try UInt32(little ? buffer.u16le(blockStart + 8) : buffer.u16(blockStart + 8))
        let snapLength = try little ? buffer.u32le(blockStart + 12) : buffer.u32(blockStart + 12)
        let resolution = try interfaceOptions(
            buffer: buffer, little: little, optionsStart: blockStart + 16, optionsEnd: blockEnd - 4
        )
        return Interface(
            linkType: linkType,
            snapLength: snapLength,
            ticksPerSecond: resolution.ticksPerSecond,
            timestampOffsetSeconds: resolution.offsetSeconds
        )
    }

    private static func readEnhancedPacket(
        buffer: PacketBuffer,
        little: Bool,
        blockStart: Int,
        blockEnd: Int,
        interfaces: [Interface]
    )
        throws -> CapturedFrame
    {
        let interfaceID = try Int(little ? buffer.u32le(blockStart + 8) : buffer.u32(blockStart + 8))
        let ticksHigh = try UInt64(little ? buffer.u32le(blockStart + 12) : buffer.u32(blockStart + 12))
        let ticksLow = try UInt64(little ? buffer.u32le(blockStart + 16) : buffer.u32(blockStart + 16))
        let capturedLength = try Int(little ? buffer.u32le(blockStart + 20) : buffer.u32(blockStart + 20))
        let originalLength = try Int(little ? buffer.u32le(blockStart + 24) : buffer.u32(blockStart + 24))
        guard interfaces.indices.contains(interfaceID) else {
            throw PacketError.malformed("pcapng: enhanced packet references undeclared interface \(interfaceID)")
        }
        let interface = interfaces[interfaceID]
        guard capturedLength <= CapturedFrame.maxReasonableLength else {
            throw PacketError.malformed("pcapng: captured length \(capturedLength) exceeds limit")
        }
        guard originalLength >= capturedLength else {
            throw PacketError.malformed(
                "pcapng: original length \(originalLength) below captured length \(capturedLength)"
            )
        }
        let payloadStart = blockStart + 28
        guard let paddedEnd = checkedSum(payloadStart, roundUpToWord(capturedLength)), paddedEnd <= blockEnd - 4 else {
            throw PacketError.malformed("pcapng: enhanced packet payload overruns block")
        }
        let payload = try buffer.bytes(payloadStart, capturedLength)
        let timestamp = try packetTimestamp(ticksHigh: ticksHigh, ticksLow: ticksLow, interface: interface)
        return CapturedFrame(
            bytes: payload,
            timestamp: timestamp,
            originalLength: originalLength,
            linkType: interface.linkType
        )
    }

    private static func readSimplePacket(
        buffer: PacketBuffer,
        little: Bool,
        blockStart: Int,
        blockEnd: Int,
        interfaces: [Interface]
    )
        throws -> CapturedFrame
    {
        let originalLength = try Int(little ? buffer.u32le(blockStart + 8) : buffer.u32(blockStart + 8))
        guard let interface = interfaces.first else {
            throw PacketError.malformed("pcapng: simple packet without interface 0")
        }
        let capturedLength = interface.snapLength == 0
            ? originalLength
            : min(originalLength, Int(interface.snapLength))
        guard capturedLength <= CapturedFrame.maxReasonableLength else {
            throw PacketError.malformed("pcapng: captured length \(capturedLength) exceeds limit")
        }
        let payloadStart = blockStart + 12
        guard payloadStart + roundUpToWord(capturedLength) == blockEnd - 4 else {
            throw PacketError.malformed("pcapng: simple packet length mismatch")
        }
        let payload = try buffer.bytes(payloadStart, capturedLength)
        return CapturedFrame(
            bytes: payload,
            timestamp: Date(timeIntervalSince1970: 0),
            originalLength: originalLength,
            linkType: interface.linkType
        )
    }

    /// Walk an IDB's options for `if_tsresol` (9) and `if_tsoffset` (14).
    private static func interfaceOptions(
        buffer: PacketBuffer,
        little: Bool,
        optionsStart: Int,
        optionsEnd: Int
    )
        throws -> (ticksPerSecond: UInt64, offsetSeconds: Int64)
    {
        var ticksPerSecond: UInt64 = 1_000_000
        var offsetSeconds: Int64 = 0
        var cursor = optionsStart
        while cursor + 4 <= optionsEnd {
            let code = try little ? buffer.u16le(cursor) : buffer.u16(cursor)
            let length = try Int(little ? buffer.u16le(cursor + 2) : buffer.u16(cursor + 2))
            cursor += 4
            if code == 0 { // opt_endofopt
                guard length == 0 else {
                    throw PacketError.malformed("pcapng: opt_endofopt length \(length)")
                }
                break
            }
            let padded = roundUpToWord(length)
            guard cursor + padded <= optionsEnd else {
                throw PacketError.malformed("pcapng: interface option length overruns block")
            }
            if code == 9 { // if_tsresol
                guard length == 1 else {
                    throw PacketError.malformed("pcapng: if_tsresol length \(length)")
                }
                ticksPerSecond = try timestampTicksPerSecond(raw: buffer.u8(cursor))
            } else if code == 14 { // if_tsoffset
                guard length == 8 else {
                    throw PacketError.malformed("pcapng: if_tsoffset length \(length)")
                }
                let high: UInt64
                let low: UInt64
                if little {
                    low = try UInt64(buffer.u32le(cursor))
                    high = try UInt64(buffer.u32le(cursor + 4))
                } else {
                    high = try UInt64(buffer.u32(cursor))
                    low = try UInt64(buffer.u32(cursor + 4))
                }
                offsetSeconds = Int64(bitPattern: (high << 32) | low)
            }
            cursor += padded
        }
        return (ticksPerSecond, offsetSeconds)
    }

    private static func packetTimestamp(
        ticksHigh: UInt64,
        ticksLow: UInt64,
        interface: Interface
    )
        throws -> Date
    {
        let ticks = (ticksHigh << 32) | ticksLow
        let seconds = Double(ticks) / Double(interface.ticksPerSecond) + Double(interface.timestampOffsetSeconds)
        guard seconds.isFinite else {
            throw PacketError.malformed("pcapng: non-finite timestamp")
        }
        return Date(timeIntervalSince1970: seconds)
    }

    private static func timestampTicksPerSecond(raw: UInt8) throws -> UInt64 {
        let exponent = raw & 0x7F
        if raw & 0x80 != 0 {
            guard exponent <= 63 else {
                throw PacketError.malformed("pcapng: binary if_tsresol exponent \(exponent) out of range")
            }
            return UInt64(1) << UInt64(exponent)
        }
        guard exponent <= 19 else {
            throw PacketError.malformed("pcapng: decimal if_tsresol exponent \(exponent) out of range")
        }
        var result: UInt64 = 1
        for _ in 0 ..< exponent {
            let (product, overflow) = result.multipliedReportingOverflow(by: 10)
            guard !overflow else {
                throw PacketError.malformed("pcapng: if_tsresol overflow")
            }
            result = product
        }
        return result
    }

    private static func roundUpToWord(_ value: Int) -> Int {
        (value + 3) & ~3
    }

    private static func checkedSum(_ lhs: Int, _ rhs: Int) -> Int? {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? nil : sum
    }
}
