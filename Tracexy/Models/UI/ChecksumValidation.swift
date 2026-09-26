import Foundation

// MARK: - ChecksumStatus

/// The outcome of checking one header checksum against the frame's bytes.
nonisolated enum ChecksumStatus: Equatable, Sendable {
    case correct
    /// The field holds only the pseudo-header sum: the frame was captured on the
    /// sending Mac before the network card filled the checksum in (offload).
    case partial
    case incorrect(expected: UInt16)
    /// A UDP-over-IPv4 checksum of zero: the sender chose not to compute one.
    case notPresent
    /// The bytes it covers were not all captured.
    case unverified

    // MARK: Internal

    /// The bracketed note after the checksum value, as Wireshark writes it.
    var note: String {
        switch self {
        case .correct: String(localized: "[correct]")
        case .partial: String(localized: "[partial, likely checksum offload]")
        case let .incorrect(expected):
            String(localized: "[incorrect, should be \(PacketDecoder.hex(expected, digits: 4))]")
        case .notPresent: String(localized: "[not present]")
        case .unverified: String(localized: "[unverified, not fully captured]")
        }
    }
}

// MARK: - ChecksumValidation

/// View ▸ Validate Checksums (off by default, as in Wireshark): checks the IPv4
/// header checksum and the TCP, UDP, ICMP and ICMPv6 checksums of one decoded frame
/// against its bytes and notes the result after each Checksum field's value. A
/// presentation pass over the decode tree — the session fold never pays for it.
nonisolated enum ChecksumValidation {
    // MARK: Internal

    /// `layers` with each checksum field's value followed by its status.
    static func annotate(_ layers: [DecodedLayer], bytes: [UInt8]) -> [DecodedLayer] {
        var context: IPContext?
        return layers.map { annotate($0, bytes: bytes, context: &context) }
    }

    /// The status of each checksum field in `layers`, keyed by the layer's title.
    static func statuses(_ layers: [DecodedLayer], bytes: [UInt8]) -> [String: ChecksumStatus] {
        var context: IPContext?
        var result: [String: ChecksumStatus] = [:]
        for layer in layers {
            if let (_, status) = check(layer, bytes: bytes, context: &context) {
                result[layer.title] = status
            }
        }
        return result
    }

    /// Whether any checksum in the frame is wrong (partial offload sums are not).
    static func hasIncorrectChecksum(_ layers: [DecodedLayer], bytes: [UInt8]) -> Bool {
        statuses(layers, bytes: bytes).values.contains { status in
            if case .incorrect = status {
                return true
            }
            return false
        }
    }

    /// The Internet checksum's ones'-complement sum of `bytes`, folded to 16 bits
    /// (RFC 1071), added to `initial`.
    static func onesComplementSum(_ bytes: ArraySlice<UInt8>, initial: UInt32 = 0) -> UInt16 {
        var sum = initial
        var index = bytes.startIndex
        while index + 1 < bytes.endIndex {
            sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.endIndex {
            sum += UInt32(bytes[index]) << 8
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(sum)
    }

    // MARK: Private

    /// The enclosing IP header a transport checksum's pseudo-header is built from.
    private struct IPContext {
        let isIPv6: Bool
        let source: ArraySlice<UInt8>
        let destination: ArraySlice<UInt8>
        /// Where the IP payload ends, from the header's own length field.
        let payloadEnd: Int
    }

    private static func annotate(_ layer: DecodedLayer, bytes: [UInt8], context: inout IPContext?) -> DecodedLayer {
        guard let (fieldName, status) = check(layer, bytes: bytes, context: &context) else {
            return layer
        }
        var annotated = layer
        annotated.fields = layer.fields.map { field in
            guard field.name == fieldName else {
                return field
            }
            return DecodedField(name: field.name, value: "\(field.value) \(status.note)", byteRange: field.byteRange)
        }
        return annotated
    }

    /// The checksum field's name and status for a layer that carries one; updates
    /// the IP context on an IP layer.
    private static func check(
        _ layer: DecodedLayer,
        bytes: [UInt8],
        context: inout IPContext?
    )
        -> (String, ChecksumStatus)?
    {
        guard let range = layer.byteRange, range.upperBound <= bytes.count else {
            return nil
        }
        switch layer.proto {
        case .ipv4:
            let start = range.lowerBound
            guard range.count >= 20 else {
                return nil
            }
            let totalLength = Int(bytes[start + 2]) << 8 | Int(bytes[start + 3])
            context = IPContext(
                isIPv6: false, source: bytes[start + 12 ..< start + 16], destination: bytes[start + 16 ..< start + 20],
                payloadEnd: start + totalLength
            )
            return ("Header Checksum", status(of: bytes[range], checksumAt: start + 10, pseudoSum: nil))
        case .ipv6:
            let start = range.lowerBound
            guard range.count >= 40 else {
                return nil
            }
            let payloadLength = Int(bytes[start + 4]) << 8 | Int(bytes[start + 5])
            context = IPContext(
                isIPv6: true, source: bytes[start + 8 ..< start + 24], destination: bytes[start + 24 ..< start + 40],
                payloadEnd: start + 40 + payloadLength
            )
            return nil
        case .tcp,
             .udp,
             .icmp,
             .icmpv6:
            return transportStatus(layer, bytes: bytes, context: context)
        default:
            return nil
        }
    }

    private static func transportStatus(
        _ layer: DecodedLayer,
        bytes: [UInt8],
        context: IPContext?
    )
        -> (String, ChecksumStatus)?
    {
        guard let context, let range = layer.byteRange,
              layer.fields.contains(where: { $0.name == "Checksum" }) else
        {
            return nil
        }
        let start = range.lowerBound
        var end = context.payloadEnd
        let checksumOffset: Int
        let protocolNumber: UInt32
        switch layer.proto {
        case .tcp:
            checksumOffset = 16
            protocolNumber = 6
        case .udp:
            checksumOffset = 6
            protocolNumber = 17
            if start + 6 <= bytes.count {
                end = min(end, start + (Int(bytes[start + 4]) << 8 | Int(bytes[start + 5])))
            }
        case .icmpv6:
            checksumOffset = 2
            protocolNumber = 58
        default:
            checksumOffset = 2
            protocolNumber = 1
        }
        guard end > start + checksumOffset + 1, end <= bytes.count else {
            return ("Checksum", .unverified)
        }
        let stored = UInt16(bytes[start + checksumOffset]) << 8 | UInt16(bytes[start + checksumOffset + 1])
        if layer.proto == .udp, !context.isIPv6, stored == 0 {
            return ("Checksum", .notPresent)
        }
        // ICMPv4 has no pseudo-header; the others cover source, destination,
        // protocol and length.
        let pseudo: UInt32? = layer.proto == .icmp
            ? nil
            : pseudoHeaderSum(context, protocolNumber: protocolNumber, length: end - start)
        return ("Checksum", status(of: bytes[start ..< end], checksumAt: start + checksumOffset, pseudoSum: pseudo))
    }

    private static func pseudoHeaderSum(_ context: IPContext, protocolNumber: UInt32, length: Int) -> UInt32 {
        UInt32(onesComplementSum(context.source + context.destination))
            + protocolNumber + UInt32(length & 0xFFFF) + UInt32(length >> 16)
    }

    /// Correct when the stored value equals the checksum computed with the field
    /// zeroed; partial when it equals the pseudo-header sum alone (either sense).
    private static func status(
        of covered: ArraySlice<UInt8>,
        checksumAt offset: Int,
        pseudoSum: UInt32?
    )
        -> ChecksumStatus
    {
        var zeroed = Array(covered)
        let local = offset - covered.startIndex
        let stored = UInt16(zeroed[local]) << 8 | UInt16(zeroed[local + 1])
        zeroed[local] = 0
        zeroed[local + 1] = 0
        let expected = ~onesComplementSum(zeroed[...], initial: pseudoSum ?? 0)
        if stored == expected || (expected == 0 && stored == 0xFFFF) {
            return .correct
        }
        if let pseudoSum {
            let partial = onesComplementSum([], initial: pseudoSum)
            if stored == partial || stored == ~partial {
                return .partial
            }
        }
        return .incorrect(expected: expected)
    }
}
