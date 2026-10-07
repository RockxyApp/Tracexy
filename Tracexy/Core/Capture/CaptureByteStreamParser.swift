import Foundation

// MARK: - CaptureByteStreamParser

/// Reads a pcap or pcapng capture as it arrives, in whatever chunks a pipe hands
/// over, and returns each complete frame once all of its bytes are in. The file
/// readers need a seekable file; a pipe can only be read forward, once.
///
/// Classic pcap in either byte order with microsecond or nanosecond timestamps, and
/// pcapng sections with their interfaces' link types and timestamp resolutions
/// (Enhanced and Simple Packet Blocks; every other block is skipped). A length no
/// real capture uses fails the stream rather than buffering without bound.
nonisolated struct CaptureByteStreamParser {
    // MARK: Internal

    /// A frame and the link type of the interface that captured it.
    struct Frame {
        let frame: CapturedFrame
        let linkType: UInt32
    }

    struct Failure: Error, Equatable {
        let message: String
    }

    enum Format: Equatable {
        case pcap(littleEndian: Bool, nanoseconds: Bool, linkType: UInt32)
        case pcapng
    }

    /// The largest record or block accepted: a full snap length plus headroom.
    static let maximumRecordLength = 16 * 1_024 * 1_024

    /// Whether the header has been read.
    private(set) var format: Format?

    /// Adds `bytes` and returns the frames they completed.
    mutating func append(_ bytes: some Collection<UInt8>) throws -> [Frame] {
        buffer.append(contentsOf: bytes)
        var frames: [Frame] = []
        while let frame = try nextFrame() {
            if let frame = frame.value {
                frames.append(frame)
            }
        }
        if head > 65_536 {
            buffer.removeFirst(head)
            head = 0
        }
        return frames
    }

    // MARK: Private

    /// One pcapng interface: its link type and ticks per second.
    private struct Interface {
        let linkType: UInt32
        let ticksPerSecond: UInt64
        let snapLength: UInt32
    }

    /// `nil` when more bytes are needed; `.some(nil)` for a consumed record that
    /// carried no frame.
    private struct Step {
        let value: Frame?
    }

    private var buffer: [UInt8] = []
    private var head = 0
    private var littleEndian = true
    private var interfaces: [Interface] = []

    private var available: Int {
        buffer.count - head
    }

    private mutating func nextFrame() throws -> Step? {
        guard let format else {
            try readHeader()
            return format == nil ? nil : Step(value: nil)
        }
        switch format {
        case let .pcap(little, nanoseconds, linkType):
            return try pcapRecord(littleEndian: little, nanoseconds: nanoseconds, linkType: linkType)
        case .pcapng:
            return try pcapngBlock()
        }
    }

    private mutating func readHeader() throws {
        guard available >= 4 else {
            return
        }
        if Array(buffer[head ..< head + 4]) == [0x0A, 0x0D, 0x0D, 0x0A] {
            format = .pcapng
            return
        }
        guard available >= 24 else {
            return
        }
        let magic = u32(at: head, little: true)
        let (little, nanoseconds): (Bool, Bool) = switch magic {
        case 0xA1B2C3D4: (true, false)
        case 0xD4C3B2A1: (false, false)
        case 0xA1B23C4D: (true, true)
        case 0x4D3CB2A1: (false, true)
        default: throw Failure(message: "The pipe is not sending a pcap or pcapng capture.")
        }
        // The low 28 bits are the link type; the rest carries FCS flags.
        let linkType = u32(at: head + 20, little: little) & 0x0FFFFFFF
        head += 24
        format = .pcap(littleEndian: little, nanoseconds: nanoseconds, linkType: linkType)
    }

    private mutating func pcapRecord(littleEndian little: Bool, nanoseconds: Bool, linkType: UInt32) throws -> Step? {
        guard available >= 16 else {
            return nil
        }
        let seconds = u32(at: head, little: little)
        let fraction = u32(at: head + 4, little: little)
        let captured = Int(u32(at: head + 8, little: little))
        let original = Int(u32(at: head + 12, little: little))
        guard captured <= Self.maximumRecordLength else {
            throw Failure(message: "The pipe sent a \(captured)-byte record, larger than any capture allows.")
        }
        guard available >= 16 + captured else {
            return nil
        }
        let bytes = Array(buffer[head + 16 ..< head + 16 + captured])
        head += 16 + captured
        let time = Double(seconds) + Double(fraction) / (nanoseconds ? 1_000_000_000 : 1_000_000)
        let frame = CapturedFrame(
            bytes: bytes, timestamp: Date(timeIntervalSince1970: time), originalLength: max(original, captured),
            linkType: linkType
        )
        return Step(value: Frame(frame: frame, linkType: linkType))
    }

    private mutating func pcapngBlock() throws -> Step? {
        guard available >= 12 else {
            return nil
        }
        let isSection = Array(buffer[head ..< head + 4]) == [0x0A, 0x0D, 0x0D, 0x0A]
        if isSection {
            switch u32(at: head + 8, little: true) {
            case 0x1A2B3C4D: littleEndian = true
            case 0x4D3C2B1A: littleEndian = false
            default: throw Failure(message: "The pipe sent a pcapng section with an unknown byte order.")
            }
        }
        let type = u32(at: head, little: littleEndian)
        let length = Int(u32(at: head + 4, little: littleEndian))
        guard length >= 12, length % 4 == 0, length <= Self.maximumRecordLength else {
            throw Failure(message: "The pipe sent a pcapng block of an impossible length (\(length) bytes).")
        }
        guard available >= length else {
            return nil
        }
        let body = head + 8 ..< head + length - 4
        defer { head += length }
        switch type {
        case 0x0A0D0D0A:
            interfaces = []
        case 1:
            interfaces.append(interface(in: body))
        case 6:
            return try enhancedPacket(in: body)
        case 3:
            return simplePacket(in: body)
        default:
            break
        }
        return Step(value: nil)
    }

    private func interface(in body: Range<Int>) -> Interface {
        let linkType = UInt32(u16(at: body.lowerBound))
        let snapLength = u32(at: body.lowerBound + 4, little: littleEndian)
        var ticks: UInt64 = 1_000_000
        var offset = body.lowerBound + 8
        while offset + 4 <= body.upperBound {
            let code = u16(at: offset)
            let size = Int(u16(at: offset + 2))
            if code == 0 {
                break
            }
            if code == 9, size >= 1, offset + 4 < body.upperBound {
                let raw = buffer[offset + 4]
                let exponent = UInt64(raw & 0x7F)
                if raw & 0x80 == 0, exponent <= 19 {
                    ticks = (0 ..< exponent).reduce(1) { value, _ in value * 10 }
                } else if raw & 0x80 != 0, exponent <= 63 {
                    ticks = 1 << exponent
                }
            }
            offset += 4 + (size + 3) / 4 * 4
        }
        return Interface(linkType: linkType, ticksPerSecond: ticks, snapLength: snapLength)
    }

    private func enhancedPacket(in body: Range<Int>) throws -> Step {
        guard body.count >= 20 else {
            throw Failure(message: "The pipe sent a truncated packet block.")
        }
        let id = Int(u32(at: body.lowerBound, little: littleEndian))
        guard interfaces.indices.contains(id) else {
            throw Failure(message: "The pipe sent a packet for interface \(id), which it never described.")
        }
        let interface = interfaces[id]
        let high = UInt64(u32(at: body.lowerBound + 4, little: littleEndian))
        let low = UInt64(u32(at: body.lowerBound + 8, little: littleEndian))
        let captured = Int(u32(at: body.lowerBound + 12, little: littleEndian))
        let original = Int(u32(at: body.lowerBound + 16, little: littleEndian))
        let start = body.lowerBound + 20
        guard captured <= body.upperBound - start else {
            throw Failure(message: "The pipe sent a packet longer than its block.")
        }
        let ticks = high << 32 | low
        let time = Double(ticks / interface.ticksPerSecond)
            + Double(ticks % interface.ticksPerSecond) / Double(interface.ticksPerSecond)
        let frame = CapturedFrame(
            bytes: Array(buffer[start ..< start + captured]), timestamp: Date(timeIntervalSince1970: time),
            originalLength: max(original, captured), linkType: interface.linkType
        )
        return Step(value: Frame(frame: frame, linkType: interface.linkType))
    }

    /// A Simple Packet Block: interface 0, no timestamp.
    private func simplePacket(in body: Range<Int>) -> Step {
        guard body.count >= 4, let interface = interfaces.first else {
            return Step(value: nil)
        }
        let original = Int(u32(at: body.lowerBound, little: littleEndian))
        var captured = min(original, body.count - 4)
        if interface.snapLength > 0 {
            captured = min(captured, Int(interface.snapLength))
        }
        let start = body.lowerBound + 4
        let frame = CapturedFrame(
            bytes: Array(buffer[start ..< start + captured]), timestamp: nil, originalLength: original,
            linkType: interface.linkType
        )
        return Step(value: Frame(frame: frame, linkType: interface.linkType))
    }

    private func u32(at offset: Int, little: Bool) -> UInt32 {
        let bytes = buffer[offset ..< offset + 4]
        return little
            ? bytes.reversed().reduce(0) { $0 << 8 | UInt32($1) }
            : bytes.reduce(0) { $0 << 8 | UInt32($1) }
    }

    private func u16(at offset: Int) -> UInt16 {
        littleEndian
            ? UInt16(buffer[offset]) | UInt16(buffer[offset + 1]) << 8
            : UInt16(buffer[offset]) << 8 | UInt16(buffer[offset + 1])
    }
}
