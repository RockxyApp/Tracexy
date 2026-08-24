import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - IPAddressFamily

/// The address family of a validated binary IP value. Kept as a small neutral enum
/// so containment can reject a cross-family comparison without inspecting byte counts.
nonisolated enum IPAddressFamily: Hashable, Sendable {
    case v4
    case v6

    // MARK: Internal

    /// Fixed on-wire width of an address in this family: 4 bytes (IPv4) or 16 (IPv6).
    var byteCount: Int {
        switch self {
        case .v4: 4
        case .v6: 16
        }
    }

    // MARK: Fileprivate

    /// The C address family constant this maps to for `inet_pton`.
    fileprivate var addressFamily: Int32 {
        switch self {
        case .v4: AF_INET
        case .v6: AF_INET6
        }
    }
}

// MARK: - IPAddressValue

/// A validated binary IPv4/IPv6 address: the family plus the exact fixed-width bytes
/// `inet_pton` produced. It retains no source string — two values are equal iff they
/// have the same family and bytes, so equality and hashing are canonical regardless of
/// how the input text happened to be written.
///
/// The only entry point is `init?(parsing:)`, which parses a *standalone* canonical
/// address (the `IPEndpoint.ip` field), never a rendered `"ip:port"` endpoint, a
/// bracketed UI form, or a DNS name. Parsing is pure: no network IO, no DNS
/// resolution, no locale dependency, and no regular expression.
nonisolated struct IPAddressValue: Hashable, Sendable {
    // MARK: Lifecycle

    /// Parse one standalone canonical IP address through `inet_pton`. Returns `nil`
    /// for any input that is not exactly a single canonical address:
    ///
    /// - empty or whitespace-containing (leading, trailing or interior) text,
    /// - an embedded NUL that would truncate the C string seen by `inet_pton`,
    /// - a zone/scope index (`fe80::1%en0`) or any other `%`,
    /// - a bracketed, ported, or otherwise decorated endpoint,
    /// - a malformed or out-of-range address in either family.
    ///
    /// IPv4 is attempted first, then IPv6; the two grammars are disjoint, so the order
    /// only affects which parser rejects a non-address, never the result for a valid one.
    init?(parsing text: String) {
        guard !text.isEmpty else {
            return nil
        }
        // Reject C-string truncation, whitespace and zone indices up front, so only a
        // complete bare address ever reaches `inet_pton`.
        guard !text.utf8.contains(0),
              !text.contains(where: { $0.isWhitespace || $0 == "%" }) else
        {
            return nil
        }
        if let value = Self.parse(text, family: .v4) {
            self = value
        } else if let value = Self.parse(text, family: .v6) {
            self = value
        } else {
            return nil
        }
    }

    /// Construct directly from an already-validated family and its exact bytes. Private
    /// so every public value originates from `inet_pton`; `maskingHostBits(prefixLength:)`
    /// reuses it after masking host bits, which cannot change the byte count.
    private init(family: IPAddressFamily, bytes: [UInt8]) {
        self.family = family
        self.bytes = bytes
    }

    // MARK: Internal

    let family: IPAddressFamily
    /// Network-order bytes, exactly `family.byteCount` long.
    let bytes: [UInt8]

    // MARK: Fileprivate

    /// The same address with all bits at or beyond `prefixLength` cleared. Callers
    /// guarantee `0 ... family.byteCount * 8`, so every index stays in bounds.
    fileprivate func maskingHostBits(prefixLength: Int) -> IPAddressValue {
        var masked = bytes
        let totalBits = bytes.count * 8
        var bit = prefixLength
        while bit < totalBits {
            let byteIndex = bit / 8
            let bitInByte = 7 - (bit % 8)
            masked[byteIndex] &= ~(UInt8(1) << bitInByte)
            bit += 1
        }
        return IPAddressValue(family: family, bytes: masked)
    }

    // MARK: Private

    /// Parse `text` for one specific family, returning `nil` unless `inet_pton` accepts
    /// it as a complete address. The scratch buffer is exactly the family's width, so
    /// the retained bytes are the canonical fixed-width representation.
    private static func parse(_ text: String, family: IPAddressFamily) -> IPAddressValue? {
        var buffer = [UInt8](repeating: 0, count: family.byteCount)
        let result = text.withCString { cString in
            buffer.withUnsafeMutableBytes { raw in
                inet_pton(family.addressFamily, cString, raw.baseAddress)
            }
        }
        guard result == 1 else {
            return nil
        }
        return IPAddressValue(family: family, bytes: buffer)
    }
}

// MARK: - CIDRValue

/// A validated, host-bit-normalized CIDR block: a network `IPAddressValue` plus a
/// prefix length. Construction requires exactly one standalone address, one `/`, and an
/// ASCII-decimal prefix within the family's range (`0...32` for IPv4, `0...128` for
/// IPv6); host bits are masked to zero so two spellings of the same block compare equal.
///
/// Containment is same-family and bounds-safe. Like `IPAddressValue`, parsing is pure:
/// no network IO, no DNS, no locale dependency, and no regular expression.
nonisolated struct CIDRValue: Hashable, Sendable {
    // MARK: Lifecycle

    /// Parse `"address/prefix"`. Returns `nil` when the input is not exactly one
    /// address, one slash and one ASCII-decimal prefix in the family's range:
    ///
    /// - a missing or duplicate `/`,
    /// - an empty, signed, non-decimal, or overflowing prefix,
    /// - a prefix outside `0...32` (IPv4) or `0...128` (IPv6) — which also rejects a
    ///   mixed-family input such as an IPv4 address with a `/64` prefix,
    /// - any address `IPAddressValue(parsing:)` itself rejects.
    init?(parsing text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else {
            return nil
        }
        guard let address = IPAddressValue(parsing: String(parts[0])) else {
            return nil
        }
        guard let prefixLength = Self.parsePrefix(String(parts[1])) else {
            return nil
        }
        guard prefixLength >= 0, prefixLength <= address.family.byteCount * 8 else {
            return nil
        }
        network = address.maskingHostBits(prefixLength: prefixLength)
        self.prefixLength = prefixLength
    }

    // MARK: Internal

    /// The network address with host bits already cleared on construction.
    let network: IPAddressValue
    let prefixLength: Int

    /// Whether `candidate` falls within this block. A different family is never
    /// contained. Compares only the first `prefixLength` bits, so a `/0` block contains
    /// every same-family address and the walk never reads past either byte buffer.
    func contains(_ candidate: IPAddressValue) -> Bool {
        guard candidate.family == network.family else {
            return false
        }
        var remaining = prefixLength
        var index = 0
        while remaining >= 8 {
            if candidate.bytes[index] != network.bytes[index] {
                return false
            }
            remaining -= 8
            index += 1
        }
        if remaining > 0 {
            let mask = UInt8(0xFF) << (8 - remaining)
            return (candidate.bytes[index] & mask) == (network.bytes[index] & mask)
        }
        return true
    }

    // MARK: Private

    /// Parse a bare, unsigned, ASCII-decimal prefix. Rejects an empty string, a sign,
    /// any non-`0...9` character (whitespace, `+`/`-`, hex, or a non-ASCII digit), and a
    /// value that overflows `Int`. Range is enforced by the caller against the family.
    private static func parsePrefix(_ text: String) -> Int? {
        guard !text.isEmpty, text.allSatisfy({ $0 >= "0" && $0 <= "9" }) else {
            return nil
        }
        return Int(text)
    }
}
