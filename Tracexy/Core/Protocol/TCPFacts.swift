import Foundation

// MARK: - TCPFlags

/// The eight TCP control bits (RFC 793 / RFC 3168) as a typed set over the raw
/// flags byte at header offset 13. This is the authoritative, decode-derived
/// representation — session logic reads these bits rather than string-matching a
/// rendered "Flags" field, so a display value can never spoof a control bit.
nonisolated struct TCPFlags: OptionSet, Sendable, Hashable {
    static let fin = TCPFlags(rawValue: 0x01)
    static let syn = TCPFlags(rawValue: 0x02)
    static let rst = TCPFlags(rawValue: 0x04)
    static let psh = TCPFlags(rawValue: 0x08)
    static let ack = TCPFlags(rawValue: 0x10)
    static let urg = TCPFlags(rawValue: 0x20)
    static let ece = TCPFlags(rawValue: 0x40)
    static let cwr = TCPFlags(rawValue: 0x80)

    let rawValue: UInt8
}

// MARK: - TCPTimestamps

/// The RFC 7323 TCP Timestamps option value: the sender's timestamp and the echo
/// reply it is acknowledging.
nonisolated struct TCPTimestamps: Sendable, Hashable {
    let value: UInt32
    let echoReply: UInt32
}

// MARK: - TCPOptionFacts

/// Typed facts extracted from the TCP option list (RFC 793 / RFC 7323). Absent
/// options stay `nil`/`false`. Window scale preserves both the raw observed byte
/// and the RFC-required effective cap so later analysis never parses display text.
nonisolated struct TCPOptionFacts: Sendable, Hashable {
    // MARK: Lifecycle

    init(
        maximumSegmentSize: UInt16? = nil,
        windowScaleRaw: UInt8? = nil,
        windowScale: UInt8? = nil,
        sackPermitted: Bool = false,
        timestamps: TCPTimestamps? = nil
    ) {
        self.maximumSegmentSize = maximumSegmentSize
        self.windowScaleRaw = windowScaleRaw
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.timestamps = timestamps
    }

    // MARK: Internal

    /// Maximum Segment Size (kind 2). `nil` when the option is absent or malformed.
    var maximumSegmentSize: UInt16?
    /// Raw Window Scale option byte (kind 3), when structurally valid.
    var windowScaleRaw: UInt8?
    /// Effective shift count. RFC 7323 section 2.3 requires a received value above
    /// 14 to be treated as 14; `windowScaleRaw` preserves the invalid observation.
    var windowScale: UInt8?
    /// Whether SACK-Permitted (kind 4) was present.
    var sackPermitted: Bool
    /// Timestamps (kind 8), when present and well-formed.
    var timestamps: TCPTimestamps?
}

// MARK: - TCPSegmentFacts

/// Typed, decode-derived facts about a single TCP segment, read from exact header
/// offsets. These are the raw on-wire values — no connection or lifecycle state —
/// so a bare/header-only segment still carries a complete fact value.
nonisolated struct TCPSegmentFacts: Sendable, Hashable {
    /// Raw sequence number (header offset 4).
    let sequenceNumber: UInt32
    /// Raw acknowledgement number (header offset 8). Retained even when the ACK
    /// flag is clear — the field is always present on the wire.
    let acknowledgementNumber: UInt32
    /// The eight control bits (header offset 13).
    let flags: TCPFlags
    /// Raw advertised window (header offset 14), before any window-scale shift.
    let windowSize: UInt16
    /// Header length in bytes (data offset × 4).
    let headerLength: Int
    /// Sequence number of the first captured payload byte. The SYN flag consumes
    /// exactly one sequence number, so a SYN segment's payload sequence is
    /// `sequenceNumber + 1`; every other segment's is `sequenceNumber`.
    let payloadSequence: UInt32
    /// Number of captured payload bytes (may be zero for a bare/header-only
    /// segment). This is the captured length, not any declared length.
    let payloadLength: Int
    /// Typed facts parsed from the option list.
    let options: TCPOptionFacts
}
