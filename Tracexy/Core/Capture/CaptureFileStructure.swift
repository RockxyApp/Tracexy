import Foundation

// MARK: - CaptureFileBlock

/// One structural unit of a capture file — a pcapng block, or a classic pcap file
/// header or record — as Wireshark's View ▸ Reload as File Format/Capture lists it.
nonisolated struct CaptureFileBlock: Identifiable, Hashable, Sendable {
    let index: Int
    let offset: UInt64
    /// The pcapng block type, or `nil` for a classic pcap header or record.
    let type: UInt32?
    let length: UInt64
    let title: String
    let detail: String

    var id: Int {
        index
    }
}

// MARK: - CaptureFileStructure

/// The blocks of a capture file, read without loading packet data: each block's
/// header and a few fixed fields, then a seek past the rest. Secrets in a
/// Decryption Secrets Block are sized, never read.
nonisolated struct CaptureFileStructure: Equatable, Sendable {
    /// Blocks listed at most; the rest are counted.
    static let maximumListedBlocks = 200_000

    let format: String
    let blocks: [CaptureFileBlock]
    /// Every block, listed or not, by title.
    let countsByTitle: [String: Int]
    let totalBlocks: Int
    /// Why the walk stopped before the end of the file, if it did.
    let stoppedEarly: String?

    static func read(contentsOf url: URL) throws -> CaptureFileStructure {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var walker = try Walker(handle: handle, size: handle.seekToEnd())
        try handle.seek(toOffset: 0)
        return try walker.walk()
    }

    /// pcapng block type names, as the pcapng specification and Wireshark name them.
    static func blockTitle(_ type: UInt32) -> String {
        switch type {
        case 0x0A0D0D0A: "Section Header Block"
        case 1: "Interface Description Block"
        case 2: "Packet Block (obsolete)"
        case 3: "Simple Packet Block"
        case 4: "Name Resolution Block"
        case 5: "Interface Statistics Block"
        case 6: "Enhanced Packet Block"
        case 7: "IRIG Timestamp Block"
        case 8: "ARINC 429 Block"
        case 9: "systemd Journal Export Block"
        case 10: "Decryption Secrets Block"
        case 0x00000BAD,
             0x40000BAD: "Custom Block"
        default: String(format: "Block type 0x%08X", type)
        }
    }

    /// A Decryption Secrets Block's secrets type, by name.
    static func secretsTitle(_ type: UInt32) -> String {
        switch type {
        case 0x544C534B: "TLS key log"
        case 0x57474B4C: "WireGuard key log"
        case 0x5A4E574B: "ZigBee network key"
        case 0x5A41504B: "ZigBee APS key"
        case 0x5353484B: "SSH key log"
        case 0x4F504355: "OPC UA key log"
        default: String(format: "type 0x%08X", type)
        }
    }
}

// MARK: - Walker

nonisolated private struct Walker {
    // MARK: Lifecycle

    init(handle: FileHandle, size: UInt64) {
        self.handle = handle
        self.size = size
    }

    // MARK: Internal

    mutating func walk() throws -> CaptureFileStructure {
        let magic = try read(at: 0, count: 4)
        guard magic.count == 4 else {
            throw PacketError.malformed("The file is too short to be a capture.")
        }
        if magic == [0x0A, 0x0D, 0x0D, 0x0A] {
            return try pcapng()
        }
        return try pcap(magic: magic)
    }

    // MARK: Private

    private let handle: FileHandle
    private let size: UInt64
    private var blocks: [CaptureFileBlock] = []
    private var counts: [String: Int] = [:]
    private var total = 0
    private var interfaces = 0
    private var packets = 0

    private static func u32(_ bytes: [UInt8], _ at: Int, little: Bool) -> UInt32 {
        let slice = bytes[at ..< at + 4]
        return little ? slice.reversed().reduce(0) { $0 << 8 | UInt32($1) } : slice.reduce(0) { $0 << 8 | UInt32($1) }
    }

    private static func u16(_ bytes: [UInt8], _ at: Int, little: Bool) -> UInt16 {
        little ? UInt16(bytes[at]) | UInt16(bytes[at + 1]) << 8 : UInt16(bytes[at]) << 8 | UInt16(bytes[at + 1])
    }

    private mutating func add(offset: UInt64, type: UInt32?, length: UInt64, title: String, detail: String) {
        total += 1
        counts[title, default: 0] += 1
        if blocks.count < CaptureFileStructure.maximumListedBlocks {
            blocks.append(CaptureFileBlock(
                index: total, offset: offset, type: type, length: length, title: title, detail: detail
            ))
        }
    }

    private mutating func finish(_ format: String, stoppedEarly: String?) -> CaptureFileStructure {
        CaptureFileStructure(
            format: format, blocks: blocks, countsByTitle: counts, totalBlocks: total, stoppedEarly: stoppedEarly
        )
    }

    private func read(at offset: UInt64, count: Int) throws -> [UInt8] {
        try handle.seek(toOffset: offset)
        return try [UInt8](handle.read(upToCount: count) ?? Data())
    }

    private mutating func pcap(magic: [UInt8]) throws -> CaptureFileStructure {
        let value = Self.u32(magic, 0, little: true)
        let (little, nanoseconds): (Bool, Bool) = switch value {
        case 0xA1B2C3D4: (true, false)
        case 0xD4C3B2A1: (false, false)
        case 0xA1B23C4D: (true, true)
        case 0x4D3CB2A1: (false, true)
        default: throw PacketError.malformed("The file is neither pcap nor pcapng.")
        }
        let header = try read(at: 0, count: 24)
        guard header.count == 24 else {
            throw PacketError.malformed("The pcap file header is cut short.")
        }
        let linkType = Self.u32(header, 20, little: little) & 0x0FFFFFFF
        add(
            offset: 0, type: nil, length: 24, title: "File Header",
            detail: String(
                localized: """
                pcap \(Self.u16(header, 4, little: little)).\(Self.u16(header, 6, little: little)), \
                \(CaptureInfoFormatting.linkType(linkType)), snap length \(Self.u32(header, 16, little: little)), \
                \(nanoseconds ? "nanosecond" : "microsecond") timestamps
                """
            )
        )
        var offset: UInt64 = 24
        while offset < size {
            let record = try read(at: offset, count: 16)
            guard record.count == 16 else {
                return finish("pcap", stoppedEarly: String(localized: "The last record header is cut short."))
            }
            let captured = UInt64(Self.u32(record, 8, little: little))
            let original = Self.u32(record, 12, little: little)
            guard offset + 16 + captured <= size else {
                return finish("pcap", stoppedEarly: String(localized: "The last record is cut short."))
            }
            packets += 1
            add(
                offset: offset, type: nil, length: 16 + captured, title: "Packet Record",
                detail: String(localized: "Frame \(packets), \(captured) of \(original) bytes captured")
            )
            offset += 16 + captured
        }
        return finish("pcap", stoppedEarly: nil)
    }

    private mutating func pcapng() throws -> CaptureFileStructure {
        var offset: UInt64 = 0
        var little = true
        while offset < size {
            let head = try read(at: offset, count: 12)
            guard head.count == 12 else {
                return finish("pcapng", stoppedEarly: String(localized: "The last block header is cut short."))
            }
            if head[0 ..< 4] == [0x0A, 0x0D, 0x0D, 0x0A] {
                switch Self.u32(head, 8, little: true) {
                case 0x1A2B3C4D: little = true
                case 0x4D3C2B1A: little = false
                default:
                    return finish(
                        "pcapng",
                        stoppedEarly: String(localized: "A section header has an unknown byte order.")
                    )
                }
                interfaces = 0
            }
            let type = Self.u32(head, 0, little: little)
            let length = UInt64(Self.u32(head, 4, little: little))
            guard length >= 12, length % 4 == 0, offset + length <= size else {
                return finish(
                    "pcapng",
                    stoppedEarly: String(localized: "The block at byte \(offset) has an impossible length (\(length)).")
                )
            }
            let body = try read(at: offset + 8, count: Int(min(length - 12, 32)))
            add(
                offset: offset, type: type, length: length, title: CaptureFileStructure.blockTitle(type),
                detail: detail(type: type, body: body, bodyLength: length - 12, little: little)
            )
            offset += length
        }
        return finish("pcapng", stoppedEarly: nil)
    }

    private mutating func detail(type: UInt32, body: [UInt8], bodyLength: UInt64, little: Bool) -> String {
        switch type {
        case 0x0A0D0D0A where body.count >= 8:
            return String(localized: """
            Version \(Self.u16(body, 4, little: little)).\(Self.u16(body, 6, little: little)), \
            \(little ? "little-endian" : "big-endian")
            """)
        case 1 where body.count >= 8:
            interfaces += 1
            let linkType = UInt32(Self.u16(body, 0, little: little))
            return String(localized: """
            Interface \(interfaces - 1), \(CaptureInfoFormatting.linkType(linkType)), snap length \(Self.u32(
                body,
                4,
                little: little
            ))
            """)
        case 6 where body.count >= 20:
            packets += 1
            return String(localized: """
            Frame \(packets), interface \(Self.u32(body, 0, little: little)), \(Self.u32(body, 12, little: little)) \
            of \(Self.u32(body, 16, little: little)) bytes captured
            """)
        case 3 where body.count >= 4:
            packets += 1
            return String(localized: "Frame \(packets), \(Self.u32(body, 0, little: little)) bytes on the wire")
        case 5 where body.count >= 4:
            return String(localized: "Interface \(Self.u32(body, 0, little: little))")
        case 10 where body.count >= 8:
            let secrets = CaptureFileStructure.secretsTitle(Self.u32(body, 0, little: little))
            return String(localized: "\(secrets), \(Self.u32(body, 4, little: little)) bytes (not shown)")
        default:
            return String(localized: "\(bodyLength) bytes of content")
        }
    }
}
