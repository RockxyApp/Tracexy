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
/// type and code, and — for the error types that quote the datagram that provoked
/// them — the typed identity of that quoted flow. Deliberately nothing more: no
/// per-type body parsing beyond the quotation's own IP/transport headers, no quoted
/// payload, and no classification of whether a type/code pair represents an error.
nonisolated struct ICMPMessageFacts: Hashable, Sendable {
    // MARK: Lifecycle

    init(family: ICMPFamily, type: UInt8, code: UInt8, quotedFlow: ICMPQuotedFlowFacts? = nil) {
        self.family = family
        self.type = type
        self.code = code
        self.quotedFlow = quotedFlow
    }

    // MARK: Internal

    let family: ICMPFamily
    /// Raw type byte (offset 0).
    let type: UInt8
    /// Raw code byte (offset 1).
    let code: UInt8
    /// The flow the message quoted back, when this type quotes one and the quotation
    /// was complete and unambiguous. `nil` for every non-quoting type, and for a
    /// quotation that was truncated, fragmented, of the wrong IP version or not
    /// TCP/UDP — the decoder never guesses a flow from a partial quotation.
    let quotedFlow: ICMPQuotedFlowFacts?
}

// MARK: - ICMPQuotedFlowFacts

/// The flow identity an ICMP error message quotes back from the datagram that
/// provoked it (RFC 792 "Internet Header + 64 bits of Data", RFC 4443 §3 "as much
/// of invoking packet as possible").
///
/// Only the typed identity is kept — the quoted IP version's addresses, the quoted
/// transport protocol and its two ports. No quoted payload, sequence number,
/// identifier, TTL, length or byte is retained, and nothing here says the quoted
/// flow was captured, existed, or is the one the user cares about: it is exactly
/// what the error message claimed it was answering.
///
/// Built only when the quotation is unambiguous — the quoted IP version matches the
/// ICMP family, the quoted datagram is a first fragment, and its transport is TCP or
/// UDP with both ports readable. Anything else yields no facts at all, so a
/// truncated or exotic quotation can never invent a flow.
nonisolated struct ICMPQuotedFlowFacts: Hashable, Sendable {
    /// The quoted transport protocol: `.tcp` or `.udp` only.
    let proto: ProtocolKind
    /// The quoted datagram's source — the endpoint that sent the datagram the error
    /// answers, which is normally the local side of the affected session.
    let source: IPEndpoint
    /// The quoted datagram's destination — the endpoint the datagram was addressed to.
    let destination: IPEndpoint

    /// The canonical tuple for the quoted flow, identical in form to the tuple the
    /// session fold derives for that flow's own frames, so the two key the same
    /// session id without any re-derivation here.
    var tuple: FiveTuple {
        FiveTuple(proto: proto, source: source, destination: destination)
    }
}
