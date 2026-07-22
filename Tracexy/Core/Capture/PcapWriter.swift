import Foundation

// MARK: - PcapWriter

/// Writer for the classic libpcap (`.pcap`) capture file format — the inverse of
/// [`PcapReader`]. Emits a little-endian / microsecond file (magic `D4 C3 B2 A1`,
/// version 2.4) so saved captures round-trip back through `PcapReader` and open
/// in Wireshark, tcpdump, and friends.
nonisolated enum PcapWriter {
    // MARK: Internal

    static let snapLength: UInt32 = 262_144

    /// Serialize frames into classic `.pcap` bytes for `linkType`.
    static func data(linkType: UInt32, frames: [CapturedFrame]) -> Data {
        var out = Data(capacity: globalHeaderSize + frames.reduce(0) { $0 + recordHeaderSize + $1.bytes.count })

        // Global header — magic written as raw bytes so the on-disk order is
        // exactly D4 C3 B2 A1 (little-endian, microsecond), then the remaining
        // fields little-endian to match.
        out.append(contentsOf: [0xD4, 0xC3, 0xB2, 0xA1])
        append16(2, to: &out) // version major
        append16(4, to: &out) // version minor
        append32(0, to: &out) // thiszone (GMT offset)
        append32(0, to: &out) // sigfigs
        append32(snapLength, to: &out) // snaplen
        append32(linkType, to: &out) // network / link type

        for frame in frames {
            let interval = frame.timestamp.timeIntervalSince1970
            let seconds = UInt32(max(0, min(interval.rounded(.down), Double(UInt32.max))))
            let micros = UInt32(((interval - interval.rounded(.down)) * 1_000_000).rounded())
            append32(seconds, to: &out)
            append32(min(micros, 999_999), to: &out)
            append32(UInt32(frame.bytes.count), to: &out) // incl_len (captured)
            append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &out) // orig_len
            out.append(contentsOf: frame.bytes)
        }
        return out
    }

    /// Write frames to a `.pcap` file at `url`.
    static func write(linkType: UInt32, frames: [CapturedFrame], to url: URL) throws {
        try data(linkType: linkType, frames: frames).write(to: url, options: .atomic)
    }

    // MARK: Private

    private static let globalHeaderSize = 24
    private static let recordHeaderSize = 16

    private static func append16(_ value: UInt16, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
}
