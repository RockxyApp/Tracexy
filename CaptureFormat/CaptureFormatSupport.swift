import Foundation

// MARK: - CaptureFormatLimits

/// Bounds shared by every capture-format reader, inside the app and in the
/// Quick Look / Spotlight extensions that compile the same readers.
nonisolated enum CaptureFormatLimits {
    /// Maximum captured length any reader accepts for one frame. Well above any
    /// real frame (jumbo/LRO segments stay under ~64 KiB), so a larger value is
    /// corrupt metadata to be rejected rather than trusted into an allocation.
    static let maxCapturedLength = 1_000_000
}

// MARK: - CaptureHeaderSignature

/// What a file's leading bytes say it is. This is the same header-only decision
/// `CaptureImporter` makes, factored out so an extension can preview a file
/// without the importer's archive machinery.
nonisolated enum CaptureHeaderSignature: Sendable, Equatable {
    case pcap
    case pcapng
    case gzip
    case zip
    case unknown
    /// Fewer than four bytes: nothing can be said.
    case tooShort

    // MARK: Internal

    static func of(prefix: [UInt8]) -> CaptureHeaderSignature {
        guard prefix.count >= 4 else {
            return .tooShort
        }
        if Array(prefix[0 ..< 4]) == [0x0A, 0x0D, 0x0D, 0x0A] {
            return .pcapng
        }
        let magic = UInt32(prefix[0]) << 24 | UInt32(prefix[1]) << 16 | UInt32(prefix[2]) << 8 | UInt32(prefix[3])
        if MagicFormat(rawMagic: magic) != nil {
            return .pcap
        }
        if prefix[0] == 0x1F, prefix[1] == 0x8B {
            return .gzip
        }
        if prefix[0] == 0x50, prefix[1] == 0x4B {
            return .zip
        }
        return .unknown
    }

    /// Read the leading bytes of `url` and classify them.
    static func of(fileAt url: URL) throws -> CaptureHeaderSignature {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 4) ?? Data()
        return of(prefix: [UInt8](data))
    }
}

// MARK: - MagicFormat

/// The byte order and timestamp resolution implied by a global header's magic.
nonisolated struct MagicFormat {
    // MARK: Lifecycle

    init?(rawMagic: UInt32) {
        switch rawMagic {
        case 0xA1B2C3D4: // big-endian, microsecond
            littleEndian = false
            nanosecond = false
        case 0xD4C3B2A1: // little-endian, microsecond
            littleEndian = true
            nanosecond = false
        case 0xA1B23C4D: // big-endian, nanosecond
            littleEndian = false
            nanosecond = true
        case 0x4D3CB2A1: // little-endian, nanosecond
            littleEndian = true
            nanosecond = true
        default:
            return nil
        }
    }

    // MARK: Internal

    let littleEndian: Bool
    let nanosecond: Bool

    /// The `DLT_*` value carried in a classic global header's link-type word. Newer
    /// libpcap writers fold an FCS-length nibble (bits 28–31) and a reserved flag
    /// (bit 27) into the same 32-bit field; only the low 16 bits name the link type.
    /// Reading the whole word turned an ordinary Ethernet file written with an FCS
    /// hint into an unknown link type and an empty session list.
    static func linkType(fromHeaderField field: UInt32) -> UInt32 {
        field & 0x0000FFFF
    }

    /// Convert a record's seconds + fractional field into a `Date`.
    func timestamp(seconds: UInt32, fraction: UInt32) -> Date {
        let denominator = nanosecond ? 1_000_000_000.0 : 1_000_000.0
        let interval = Double(seconds) + Double(fraction) / denominator
        return Date(timeIntervalSince1970: interval)
    }
}
