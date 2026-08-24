// MARK: - DNSMessageFacts

/// The fixed 12-byte DNS header (RFC 1035 §4.1.1) as typed fields: the transaction ID,
/// the individual flag bits, the 4-bit opcode/response code, and the four section
/// counts. These are neutral wire facts — the flag names mirror the RFC bits and carry
/// no interpretation of whether a message is good or bad.
nonisolated struct DNSMessageFacts: Hashable, Sendable {
    // MARK: Lifecycle

    /// Reads the fixed 12-byte DNS header from `buf` exactly once, unpacking the flag
    /// bits from the 16-bit flags word so the bit masks live in one neutral place. Any
    /// short-header read throws (via `PacketBuffer`'s bounds check) and constructs
    /// nothing, so an incomplete fixed header yields no facts. Only typed integer fields
    /// are retained — never the underlying bytes.
    init(dnsHeader buf: PacketBuffer) throws {
        transactionID = try buf.u16(0)
        let flags = try buf.u16(2)
        isResponse = flags & 0x8000 != 0
        opcode = UInt8((flags >> 11) & 0x0F)
        isAuthoritativeAnswer = flags & 0x0400 != 0
        isTruncated = flags & 0x0200 != 0
        recursionDesired = flags & 0x0100 != 0
        recursionAvailable = flags & 0x0080 != 0
        authenticData = flags & 0x0020 != 0
        checkingDisabled = flags & 0x0010 != 0
        responseCode = UInt8(flags & 0x000F)
        questionCount = try buf.u16(4)
        answerCount = try buf.u16(6)
        authorityCount = try buf.u16(8)
        additionalCount = try buf.u16(10)
    }

    // MARK: Internal

    /// Transaction ID (offset 0).
    let transactionID: UInt16
    /// QR bit: `true` for a response, `false` for a query.
    let isResponse: Bool
    /// 4-bit opcode (Query, IQuery, Status, …).
    let opcode: UInt8
    /// AA — Authoritative Answer flag.
    let isAuthoritativeAnswer: Bool
    /// TC — Truncation flag (the message was truncated on the wire).
    let isTruncated: Bool
    /// RD — Recursion Desired flag.
    let recursionDesired: Bool
    /// RA — Recursion Available flag.
    let recursionAvailable: Bool
    /// AD — Authentic Data flag (RFC 4035).
    let authenticData: Bool
    /// CD — Checking Disabled flag (RFC 4035).
    let checkingDisabled: Bool
    /// 4-bit response code (RCODE).
    let responseCode: UInt8
    /// QDCOUNT — number of question entries.
    let questionCount: UInt16
    /// ANCOUNT — number of answer resource records.
    let answerCount: UInt16
    /// NSCOUNT — number of authority resource records.
    let authorityCount: UInt16
    /// ARCOUNT — number of additional resource records.
    let additionalCount: UInt16
}

// MARK: - ICMPFamily

/// Which ICMP family a message belongs to. This comes from the already-known IP
/// protocol number, never inferred from the message body.
nonisolated enum ICMPFamily: Hashable, Sendable {
    case ipv4
    case ipv6
}

// MARK: - ICMPMessageFacts

/// The two leading ICMP/ICMPv6 header bytes as typed facts: the family plus the raw
/// type and code. Deliberately nothing more — no per-type body parsing, no classification
/// of whether a type/code pair represents an error.
nonisolated struct ICMPMessageFacts: Hashable, Sendable {
    let family: ICMPFamily
    /// Raw type byte (offset 0).
    let type: UInt8
    /// Raw code byte (offset 1).
    let code: UInt8
}
