import Foundation

// MARK: - FrameFilterFacts

/// Only facts decoded from this frame. No session summary, rendered Info text or
/// packet payload is consulted by a Frame Expression.
nonisolated struct FrameFilterFacts: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        packet: DecodedPacket,
        capturedLength: Int? = nil,
        originalLength: Int? = nil,
        captureDirection: CaptureDirection = .unknown
    ) {
        self.originalLength = originalLength ?? packet.originalLength
        self.capturedLength = capturedLength
        self.captureDirection = captureDirection
        sourceIPAddresses = Self.ipAddresses(packet, named: "Source")
        destinationIPAddresses = Self.ipAddresses(packet, named: "Destination")
        ipAddressCouldBeHidden = packet.decodeStop != nil || packet.undecodedInnerIPHeader
            || Self.fragmentCouldHideIPHeader(packet)
        sourceTCPPort = packet.tcpFacts == nil ? nil : packet.sourceEndpoint?.port
        destinationTCPPort = packet.tcpFacts == nil ? nil : packet.destinationEndpoint?.port
        sourceUDPPort = packet.transport == .udp ? packet.sourceEndpoint?.port : nil
        destinationUDPPort = packet.transport == .udp ? packet.destinationEndpoint?.port : nil
        sourceSCTPPort = packet.sctpFacts?.sourcePort
        destinationSCTPPort = packet.sctpFacts?.destinationPort
        tcpFlags = packet.tcpFacts?.flags
        tcpWindowSizeValue = packet.tcpFacts?.windowSize
        tcpSequenceRaw = packet.tcpFacts?.sequenceNumber
        tcpAcknowledgementRaw = packet.tcpFacts?.acknowledgementNumber
        ipTTLValues = Self.ipNumericValues(packet, proto: .ipv4, field: "TTL")
        ipv4IdentificationValues = Self.ipValues(packet, proto: .ipv4, field: "Identification").compactMap { value in
            guard value.lowercased().hasPrefix("0x") else {
                return nil
            }
            return UInt16(value.dropFirst(2), radix: 16)
        }
        ipv6HopLimitValues = Self.ipNumericValues(packet, proto: .ipv6, field: "Hop Limit")
        ipv4FragmentOffsets = Self.ipNumericValues(packet, proto: .ipv4, field: "Fragment Offset")
        ipv4MoreFragments = Self.ipValues(packet, proto: .ipv4, field: "More Fragments").compactMap {
            switch $0.lowercased() {
            case "yes",
                 "true",
                 "1": true
            case "no",
                 "false",
                 "0": false
            default: nil
            }
        }
        ipv4DontFragment = Self.ipValues(packet, proto: .ipv4, field: "Don't Fragment").compactMap {
            switch $0.lowercased() {
            case "yes",
                 "true",
                 "1": true
            case "no",
                 "false",
                 "0": false
            default: nil
            }
        }
        dnsIsResponse = packet.dnsFacts?.isResponse
        dnsIsTruncated = packet.dnsFacts?.isTruncated
        dnsResponseCode = packet.dnsFacts?.responseCode
        dnsTransactionID = packet.dnsFacts?.transactionID
        icmpFacts = packet.icmpFacts
        decodingStopped = packet.decodeStop != nil
        unresolvedFragmentIsIPv6 = packet.reassembly == nil && packet.ipFragment?.version == .v6
        unresolvedFragmentProtocol = packet.reassembly == nil ? packet.ipFragment?.protocolNumber : nil
        unresolvedFragmentOffset = packet.reassembly == nil ? packet.ipFragment?.offset : nil
    }

    // MARK: Internal

    let originalLength: Int
    let capturedLength: Int?
    /// Direction relative to the recording interface; absent metadata stays unknown.
    let captureDirection: CaptureDirection
    /// Addresses from every decoded IPv4/IPv6 header, outer and inner, in wire order.
    let sourceIPAddresses: [IPAddressValue]
    let destinationIPAddresses: [IPAddressValue]
    let ipAddressCouldBeHidden: Bool
    let sourceTCPPort: UInt16?
    let destinationTCPPort: UInt16?
    let sourceUDPPort: UInt16?
    let destinationUDPPort: UInt16?
    /// Read from the typed SCTP common header, so a frame cut before its ports
    /// were captured has no port to match rather than a guessed one.
    let sourceSCTPPort: UInt16?
    let destinationSCTPPort: UInt16?
    let tcpFlags: TCPFlags?
    let tcpWindowSizeValue: UInt16?
    let tcpSequenceRaw: UInt32?
    let tcpAcknowledgementRaw: UInt32?
    let ipTTLValues: [UInt8]
    let ipv4IdentificationValues: [UInt16]
    let ipv6HopLimitValues: [UInt8]
    let ipv4FragmentOffsets: [UInt16]
    let ipv4MoreFragments: [Bool]
    let ipv4DontFragment: [Bool]
    let dnsIsResponse: Bool?
    let dnsIsTruncated: Bool?
    let dnsResponseCode: UInt8?
    let dnsTransactionID: UInt16?
    let icmpFacts: ICMPMessageFacts?
    let decodingStopped: Bool
    let unresolvedFragmentIsIPv6: Bool
    /// An unfinished IP fragment can hide the transport header even when the
    /// frame's own IP header decoded cleanly.
    let unresolvedFragmentProtocol: UInt8?
    let unresolvedFragmentOffset: Int?

    // MARK: Private

    private static func ipAddresses(_ packet: DecodedPacket, named name: String) -> [IPAddressValue] {
        let decoded = allIPLayers(packet)
        var addresses: [IPAddressValue] = []
        for layer in decoded {
            guard let text = layer.fields.first(where: { $0.name == name })?.value,
                  let address = IPAddressValue(parsing: text), !addresses.contains(address) else
            {
                continue
            }
            addresses.append(address)
        }
        if addresses.isEmpty,
           let fragmentAddress = name == "Source" ? packet.ipFragment?.source : packet.ipFragment?.destination,
           let address = IPAddressValue(parsing: fragmentAddress)
        {
            addresses.append(address)
        }
        if addresses.isEmpty,
           let endpoint = name == "Source" ? packet.sourceEndpoint : packet.destinationEndpoint,
           endpoint.port != 0 || packet.transport != nil || packet.tcpFacts != nil,
           let address = IPAddressValue(parsing: endpoint.ip)
        {
            addresses.append(address)
        }
        return addresses
    }

    private static func ipLayers(_ packet: DecodedPacket, proto: ProtocolKind) -> [DecodedLayer] {
        allIPLayers(packet).filter { $0.proto == proto }
    }

    private static func allIPLayers(_ packet: DecodedPacket) -> [DecodedLayer] {
        func flatten(_ layers: [DecodedLayer]) -> [DecodedLayer] {
            layers.flatMap { [$0] + flatten($0.children) }
        }
        return flatten(packet.layers).filter { $0.proto == .ipv4 || $0.proto == .ipv6 }
    }

    private static func ipValues(_ packet: DecodedPacket, proto: ProtocolKind, field: String) -> [String] {
        ipLayers(packet, proto: proto).compactMap { layer in
            layer.fields.first(where: { $0.name == field })?.value
        }
    }

    private static func ipNumericValues<T: LosslessStringConvertible>(
        _ packet: DecodedPacket, proto: ProtocolKind, field: String
    )
        -> [T]
    {
        ipValues(packet, proto: proto, field: field).compactMap(T.init)
    }

    private static func fragmentCouldHideIPHeader(_ packet: DecodedPacket) -> Bool {
        guard packet.reassembly == nil, let protocolNumber = packet.ipFragment?.protocolNumber else {
            return false
        }
        if packet.ipFragment?.version == .v6, PacketDecoder.ipv6ExtensionHeaders.contains(protocolNumber) {
            return true
        }
        switch protocolNumber {
        case 4,
             41,
             47:
            return true
        case 17:
            // Offset eight starts at a UDP payload boundary, where a recognized
            // UDP tunnel can still carry an inner IP header.
            return packet.ipFragment?.offset == 8
        default:
            return false
        }
    }
}

// MARK: - FrameTruth

/// Three-valued results prevent `not tcp.rst` from claiming that a frame whose
/// TCP header was cut short is known not to carry RST.
nonisolated enum FrameTruth: Sendable, Equatable {
    case yes
    case no
    case unknown

    // MARK: Internal

    var negated: Self {
        switch self {
        case .yes: .no
        case .no: .yes
        case .unknown: .unknown
        }
    }

    func and(_ other: Self) -> Self {
        if self == .no || other == .no {
            return .no
        }
        if self == .unknown || other == .unknown {
            return .unknown
        }
        return .yes
    }

    func or(_ other: Self) -> Self {
        if self == .yes || other == .yes {
            return .yes
        }
        if self == .unknown || other == .unknown {
            return .unknown
        }
        return .no
    }
}

// MARK: - FrameExpression

/// A deliberately small packet-level grammar. Its field names and semantics are
/// Tracexy's; it does not claim Wireshark display-filter compatibility.
nonisolated indirect enum FrameExpression: Sendable, Equatable {
    case predicate(Predicate)
    case not(FrameExpression)
    case and(FrameExpression, FrameExpression)
    case or(FrameExpression, FrameExpression)

    // MARK: Internal

    enum NumericComparison: String, Sendable, Equatable {
        case equal = "=="
        case greater = ">"
        case greaterOrEqual = ">="
        case less = "<"
        case lessOrEqual = "<="

        // MARK: Internal

        func matches(_ observed: Int, value: Int) -> Bool {
            switch self {
            case .equal: observed == value
            case .greater: observed > value
            case .greaterOrEqual: observed >= value
            case .less: observed < value
            case .lessOrEqual: observed <= value
            }
        }
    }

    enum Predicate: Sendable, Equatable {
        case frameLength(NumericComparison, UInt32)
        case frameCapturedLength(NumericComparison, UInt32)
        case frameTruncated
        case captureDirection(CaptureDirection)
        case ipTTL(FrameExpression.NumericComparison, UInt8)
        case ipv4Identification(UInt16)
        case ipv6HopLimit(FrameExpression.NumericComparison, UInt8)
        case ipv4FragmentOffset(FrameExpression.NumericComparison, UInt16)
        case ipv4MoreFragments
        case ipv4DontFragment
        case tcpWindowSizeValue(NumericComparison, UInt16)
        case tcpSequenceRaw(UInt32)
        case tcpAcknowledgementRaw(UInt32)
        case tcpFlag(TCPFlags)
        case tcpRST
        case tcpSYN
        case tcpPort(UInt16)
        case tcpSourcePort(UInt16)
        case tcpDestinationPort(UInt16)
        case udpPort(UInt16)
        case udpSourcePort(UInt16)
        case udpDestinationPort(UInt16)
        case sctpPort(UInt16)
        case sctpSourcePort(UInt16)
        case sctpDestinationPort(UInt16)
        case ipAddress(IPAddressValue)
        case ipSource(IPAddressValue)
        case ipDestination(IPAddressValue)
        case dnsResponse
        case dnsTruncated
        case dnsResponseCode(UInt8)
        case dnsTransactionID(UInt16)
        case icmpType(UInt8)
        case icmpCode(UInt8)
        case icmpv6Type(UInt8)
        case icmpv6Code(UInt8)

        // MARK: Internal

        func evaluate(_ facts: FrameFilterFacts) -> FrameTruth {
            switch self {
            case let .frameLength(comparison, length):
                guard facts.originalLength >= 0 else {
                    return .unknown
                }
                return comparison.matches(facts.originalLength, value: Int(length)) ? .yes : .no
            case let .frameCapturedLength(comparison, length):
                guard let capturedLength = facts.capturedLength, capturedLength >= 0 else {
                    return .unknown
                }
                return comparison.matches(capturedLength, value: Int(length)) ? .yes : .no
            case .frameTruncated:
                guard let capturedLength = facts.capturedLength, facts.originalLength >= 0,
                      capturedLength >= 0 else
                {
                    return .unknown
                }
                return capturedLength < facts.originalLength ? .yes : .no
            case let .captureDirection(direction):
                guard facts.captureDirection != .unknown else {
                    return .unknown
                }
                return facts.captureDirection == direction ? .yes : .no
            case let .ipTTL(comparison, value):
                return numericIPMatch(comparison, value: value, observed: facts.ipTTLValues, facts: facts)
            case let .ipv4Identification(value):
                if facts.ipv4IdentificationValues.contains(value) {
                    return .yes
                }
                return ipv4HeaderCouldBeHidden(facts) ? .unknown : .no
            case let .ipv6HopLimit(comparison, value):
                return numericIPMatch(comparison, value: value, observed: facts.ipv6HopLimitValues, facts: facts)
            case let .ipv4FragmentOffset(comparison, value):
                return numericIPMatch(comparison, value: value, observed: facts.ipv4FragmentOffsets, facts: facts)
            case .ipv4MoreFragments:
                if facts.ipv4MoreFragments.contains(true) {
                    return .yes
                }
                return ipv4HeaderCouldBeHidden(facts) ? .unknown : .no
            case .ipv4DontFragment:
                if facts.ipv4DontFragment.contains(true) {
                    return .yes
                }
                return ipv4HeaderCouldBeHidden(facts) ? .unknown : .no
            case let .tcpWindowSizeValue(comparison, value):
                guard let observed = facts.tcpWindowSizeValue else {
                    return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
                }
                return comparison.matches(Int(observed), value: Int(value)) ? .yes : .no
            case let .tcpSequenceRaw(value):
                return tcpRawMatch(value, observed: facts.tcpSequenceRaw, facts: facts)
            case let .tcpAcknowledgementRaw(value):
                return tcpRawMatch(value, observed: facts.tcpAcknowledgementRaw, facts: facts)
            case let .tcpFlag(flag):
                guard let flags = facts.tcpFlags else {
                    return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
                }
                return flags.contains(flag) ? .yes : .no
            case .tcpRST:
                guard let flags = facts.tcpFlags else {
                    return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
                }
                return flags.contains(.rst) ? .yes : .no
            case .tcpSYN:
                guard let flags = facts.tcpFlags else {
                    return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
                }
                return flags.contains(.syn) ? .yes : .no
            case let .tcpPort(port):
                guard facts.tcpFlags != nil else {
                    return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
                }
                guard let source = facts.sourceTCPPort, let destination = facts.destinationTCPPort else {
                    return .unknown
                }
                return source == port || destination == port ? .yes : .no
            case let .tcpSourcePort(port):
                return portMatch(port, observed: facts.sourceTCPPort, protocolNumber: 6, facts: facts)
            case let .tcpDestinationPort(port):
                return portMatch(port, observed: facts.destinationTCPPort, protocolNumber: 6, facts: facts)
            case let .udpPort(port):
                guard let source = facts.sourceUDPPort, let destination = facts.destinationUDPPort else {
                    return facts
                        .decodingStopped || fragmentMayContain(protocolNumber: 17, facts: facts) ? .unknown : .no
                }
                return source == port || destination == port ? .yes : .no
            case let .udpSourcePort(port):
                return portMatch(port, observed: facts.sourceUDPPort, protocolNumber: 17, facts: facts)
            case let .udpDestinationPort(port):
                return portMatch(port, observed: facts.destinationUDPPort, protocolNumber: 17, facts: facts)
            case let .sctpPort(port):
                guard let source = facts.sourceSCTPPort, let destination = facts.destinationSCTPPort else {
                    return facts
                        .decodingStopped || fragmentMayContain(protocolNumber: 132, facts: facts) ? .unknown : .no
                }
                return source == port || destination == port ? .yes : .no
            case let .sctpSourcePort(port):
                return portMatch(port, observed: facts.sourceSCTPPort, protocolNumber: 132, facts: facts)
            case let .sctpDestinationPort(port):
                return portMatch(port, observed: facts.destinationSCTPPort, protocolNumber: 132, facts: facts)
            case let .ipAddress(address):
                if facts.sourceIPAddresses.contains(address) || facts.destinationIPAddresses.contains(address) {
                    return .yes
                }
                return facts.ipAddressCouldBeHidden ? .unknown : .no
            case let .ipSource(address):
                if facts.sourceIPAddresses.contains(address) {
                    return .yes
                }
                return facts.ipAddressCouldBeHidden ? .unknown : .no
            case let .ipDestination(address):
                if facts.destinationIPAddresses.contains(address) {
                    return .yes
                }
                return facts.ipAddressCouldBeHidden ? .unknown : .no
            case .dnsResponse:
                guard let response = facts.dnsIsResponse else {
                    return dnsFactCouldBeHidden(facts) ? .unknown : .no
                }
                return response ? .yes : .no
            case .dnsTruncated:
                guard let isTruncated = facts.dnsIsTruncated else {
                    return dnsFactCouldBeHidden(facts) ? .unknown : .no
                }
                return isTruncated ? .yes : .no
            case let .dnsResponseCode(code):
                guard let observedCode = facts.dnsResponseCode else {
                    return dnsFactCouldBeHidden(facts) ? .unknown : .no
                }
                return observedCode == code ? .yes : .no
            case let .dnsTransactionID(identifier):
                guard let observedIdentifier = facts.dnsTransactionID else {
                    return dnsFactCouldBeHidden(facts) ? .unknown : .no
                }
                return observedIdentifier == identifier ? .yes : .no
            case let .icmpType(value):
                return icmpMatch(value, field: .type, family: .ipv4, facts: facts)
            case let .icmpCode(value):
                return icmpMatch(value, field: .code, family: .ipv4, facts: facts)
            case let .icmpv6Type(value):
                return icmpMatch(value, field: .type, family: .ipv6, facts: facts)
            case let .icmpv6Code(value):
                return icmpMatch(value, field: .code, family: .ipv6, facts: facts)
            }
        }

        // MARK: Private

        private enum ICMPField {
            case type
            case code
        }

        private func numericIPMatch(
            _ comparison: FrameExpression.NumericComparison, value: UInt8, observed: [UInt8], facts: FrameFilterFacts
        )
            -> FrameTruth
        {
            if observed.contains(where: { comparison.matches(Int($0), value: Int(value)) }) {
                return .yes
            }
            return facts.decodingStopped ? .unknown : .no
        }

        private func numericIPMatch(
            _ comparison: FrameExpression.NumericComparison, value: UInt16, observed: [UInt16], facts: FrameFilterFacts
        )
            -> FrameTruth
        {
            if observed.contains(where: { comparison.matches(Int($0), value: Int(value)) }) {
                return .yes
            }
            return facts.decodingStopped ? .unknown : .no
        }

        private func portMatch(
            _ expected: UInt16,
            observed: UInt16?,
            protocolNumber: UInt8,
            facts: FrameFilterFacts
        )
            -> FrameTruth
        {
            guard let observed else {
                return facts.decodingStopped || fragmentMayContain(protocolNumber: protocolNumber, facts: facts)
                    ? .unknown : .no
            }
            return observed == expected ? .yes : .no
        }

        private func fragmentMayContain(protocolNumber: UInt8, facts: FrameFilterFacts) -> Bool {
            facts.unresolvedFragmentProtocol == protocolNumber
                || (facts.unresolvedFragmentIsIPv6
                    && facts.unresolvedFragmentProtocol.map(PacketDecoder.ipv6ExtensionHeaders.contains) == true)
        }

        private func tcpRawMatch(_ expected: UInt32, observed: UInt32?, facts: FrameFilterFacts) -> FrameTruth {
            guard let observed else {
                return facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts) ? .unknown : .no
            }
            return observed == expected ? .yes : .no
        }

        private func dnsFactCouldBeHidden(_ facts: FrameFilterFacts) -> Bool {
            facts.decodingStopped || fragmentMayContain(protocolNumber: 6, facts: facts)
                || fragmentMayContain(protocolNumber: 17, facts: facts)
        }

        private func ipv4HeaderCouldBeHidden(_ facts: FrameFilterFacts) -> Bool {
            guard !facts.decodingStopped else {
                return true
            }
            guard let protocolNumber = facts.unresolvedFragmentProtocol else {
                return false
            }
            if facts.unresolvedFragmentIsIPv6, PacketDecoder.ipv6ExtensionHeaders.contains(protocolNumber) {
                return true
            }
            switch protocolNumber {
            case 4,
                 41,
                 47:
                return true
            case 17:
                return facts.unresolvedFragmentOffset == 8
            default:
                return false
            }
        }

        private func icmpMatch(
            _ expected: UInt8,
            field: ICMPField,
            family: ICMPFamily,
            facts: FrameFilterFacts
        )
            -> FrameTruth
        {
            if let observed = facts.icmpFacts {
                guard observed.family == family else {
                    return .no
                }
                let value = switch field {
                case .type: observed.type
                case .code: observed.code
                }
                return value == expected ? .yes : .no
            }
            let fragmentCouldContainFamily = switch family {
            case .ipv4: facts.unresolvedFragmentProtocol == 1
            case .ipv6:
                facts.unresolvedFragmentIsIPv6
                    && facts.unresolvedFragmentProtocol.map {
                        $0 == 58 || PacketDecoder.ipv6ExtensionHeaders.contains($0)
                    } == true
            }
            return facts.decodingStopped || fragmentCouldContainFamily ? .unknown : .no
        }
    }

    func evaluate(_ facts: FrameFilterFacts?) -> FrameTruth {
        guard let facts else {
            return .unknown
        }
        return switch self {
        case let .predicate(predicate): predicate.evaluate(facts)
        case let .not(expression): expression.evaluate(facts).negated
        case let .and(lhs, rhs): lhs.evaluate(facts).and(rhs.evaluate(facts))
        case let .or(lhs, rhs): lhs.evaluate(facts).or(rhs.evaluate(facts))
        }
    }
}

// MARK: - FrameExpressionError

nonisolated struct FrameExpressionError: Error, Equatable, Sendable {
    let position: Int
    let reason: String
}

// MARK: - FrameExpressionParser

/// Recursive-descent parser with bounded input, token count and nesting depth.
/// Positions are one-based character offsets for the editor's error label.
nonisolated struct FrameExpressionParser {
    // MARK: Internal

    mutating func parse(_ source: String) throws -> FrameExpression {
        guard source.count <= 512 else {
            throw FrameExpressionError(position: 513, reason: "Expression is too long")
        }
        tokens = try Self.tokenize(source)
        index = 0
        guard !tokens.isEmpty else {
            throw FrameExpressionError(position: 1, reason: "Enter a frame condition")
        }
        let result = try parseOr(depth: 0)
        if index < tokens.count {
            throw FrameExpressionError(position: tokens[index].position, reason: "Unexpected token")
        }
        return result
    }

    // MARK: Private

    private struct Token {
        let text: String
        let position: Int
    }

    private var tokens: [Token] = []
    private var index = 0

    private var position: Int {
        index < tokens.count ? tokens[index].position : (tokens.last.map { $0.position + $0.text.count } ?? 1)
    }

    private static func tokenize(_ source: String) throws -> [Token] {
        var tokens: [Token] = []
        let characters = Array(source)
        var offset = 0
        while offset < characters.count {
            if characters[offset].isWhitespace {
                offset += 1
                continue
            }
            let start = offset
            let character = characters[offset]
            if character == "(" || character == ")" {
                offset += 1
            } else if character == "=" || character == ">" || character == "<" {
                if character == "=" {
                    guard offset + 1 < characters.count, characters[offset + 1] == "=" else {
                        throw FrameExpressionError(position: start + 1, reason: "Expected ==")
                    }
                    offset += 2
                } else {
                    offset += offset + 1 < characters.count && characters[offset + 1] == "=" ? 2 : 1
                }
            } else {
                while offset < characters.count,
                      !characters[offset].isWhitespace,
                      characters[offset] != "(", characters[offset] != ")",
                      characters[offset] != "=", characters[offset] != ">", characters[offset] != "<"
                {
                    offset += 1
                }
            }
            tokens.append(Token(text: String(characters[start ..< offset]), position: start + 1))
            if tokens.count > 64 {
                throw FrameExpressionError(position: start + 1, reason: "Too many conditions")
            }
        }
        return tokens
    }

    private mutating func parseOr(depth: Int) throws -> FrameExpression {
        var result = try parseAnd(depth: depth)
        while consume("or") {
            result = try .or(result, parseAnd(depth: depth))
        }
        return result
    }

    private mutating func parseAnd(depth: Int) throws -> FrameExpression {
        var result = try parseUnary(depth: depth)
        while consume("and") {
            result = try .and(result, parseUnary(depth: depth))
        }
        return result
    }

    private mutating func parseUnary(depth: Int) throws -> FrameExpression {
        guard depth <= 16 else {
            throw FrameExpressionError(position: position, reason: "Too many nested conditions")
        }
        if consume("not") {
            return try .not(parseUnary(depth: depth + 1))
        }
        if consume("(") {
            let result = try parseOr(depth: depth + 1)
            guard consume(")") else {
                throw FrameExpressionError(position: position, reason: "Expected )")
            }
            return result
        }
        return try .predicate(parsePredicate())
    }

    private mutating func parsePredicate() throws -> FrameExpression.Predicate {
        guard index < tokens.count else {
            throw FrameExpressionError(
                position: position,
                reason: "Expected a frame field"
            )
        }
        let field = tokens[index]
        index += 1
        switch field.text.lowercased() {
        case "frame.truncated": return .frameTruncated
        case "frame.capture_direction": return try parseCaptureDirection()
        case "ip.flags.mf": return .ipv4MoreFragments
        case "ip.frag_offset": return try parseIPv4FragmentOffset()
        case "ip.ttl",
             "ipv6.hlim":
            guard index < tokens.count,
                  let comparison = FrameExpression.NumericComparison(rawValue: tokens[index].text) else
            {
                throw FrameExpressionError(position: position, reason: "Expected ==, >, >=, <, or <=")
            }
            index += 1
            guard index < tokens.count, let value = UInt8(tokens[index].text) else {
                throw FrameExpressionError(
                    position: index < tokens.count ? tokens[index].position : position,
                    reason: "Expected a value from 0 to 255"
                )
            }
            index += 1
            return field.text.lowercased() == "ip.ttl" ? .ipTTL(comparison, value) : .ipv6HopLimit(comparison, value)
        case "frame.len",
             "frame.cap_len":
            guard index < tokens.count,
                  let comparison = FrameExpression.NumericComparison(rawValue: tokens[index].text) else
            {
                throw FrameExpressionError(position: position, reason: "Expected ==, >, >=, <, or <=")
            }
            index += 1
            guard index < tokens.count else {
                throw FrameExpressionError(position: position, reason: "Expected a frame length")
            }
            let value = tokens[index]
            index += 1
            guard let length = UInt32(value.text) else {
                throw FrameExpressionError(
                    position: value.position,
                    reason: "Expected a frame length from 0 to 4294967295"
                )
            }
            return field.text.lowercased() == "frame.len"
                ? .frameLength(comparison, length) : .frameCapturedLength(comparison, length)
        case "tcp.window_size_value":
            guard index < tokens.count,
                  let comparison = FrameExpression.NumericComparison(rawValue: tokens[index].text) else
            {
                throw FrameExpressionError(position: position, reason: "Expected ==, >, >=, <, or <=")
            }
            index += 1
            guard index < tokens.count else {
                throw FrameExpressionError(position: position, reason: "Expected a TCP window value")
            }
            let value = tokens[index]
            index += 1
            guard let window = UInt16(value.text) else {
                throw FrameExpressionError(
                    position: value.position,
                    reason: "Expected a TCP window value from 0 to 65535"
                )
            }
            return .tcpWindowSizeValue(comparison, window)
        case "tcp.seq_raw",
             "tcp.ack_raw": return try parseTCPRawPredicate(field: field)
        case "tcp.rst": return .tcpRST
        case "tcp.syn": return .tcpSYN
        case "tcp.flags.fin": return .tcpFlag(.fin)
        case "tcp.flags.syn": return .tcpFlag(.syn)
        case "tcp.flags.reset": return .tcpFlag(.rst)
        case "tcp.flags.push": return .tcpFlag(.psh)
        case "tcp.flags.ack": return .tcpFlag(.ack)
        case "tcp.flags.urg": return .tcpFlag(.urg)
        case "tcp.flags.ece": return .tcpFlag(.ece)
        case "tcp.flags.cwr": return .tcpFlag(.cwr)
        case "dns.response": return .dnsResponse
        case "dns.flags.truncated": return .dnsTruncated
        case "dns.id": return try parseDNSIdentifier(field: field)
        case "ip.id": return try parseIPv4Identification(field: field)
        case "ip.flags.df": return .ipv4DontFragment
        case "icmp.type",
             "icmp.code",
             "icmpv6.type",
             "icmpv6.code": return try parseICMPPredicate(field: field)
        case "tcp.port",
             "tcp.srcport",
             "tcp.dstport",
             "udp.port",
             "udp.srcport",
             "udp.dstport",
             "sctp.port",
             "sctp.srcport",
             "sctp.dstport",
             "dns.rcode",
             "ip.addr",
             "ip.src",
             "ip.dst":
            guard consume("==") else {
                throw FrameExpressionError(position: position, reason: "Expected ==")
            }
            guard index < tokens.count else {
                throw FrameExpressionError(position: position, reason: "Expected a value")
            }
            let value = tokens[index]
            index += 1
            switch field.text.lowercased() {
            case "tcp.port",
                 "tcp.srcport",
                 "tcp.dstport",
                 "udp.port",
                 "udp.srcport",
                 "udp.dstport",
                 "sctp.port",
                 "sctp.srcport",
                 "sctp.dstport":
                guard let port = UInt16(value.text) else {
                    throw FrameExpressionError(position: value.position, reason: "Expected a port from 0 to 65535")
                }
                switch field.text.lowercased() {
                case "tcp.port": return .tcpPort(port)
                case "tcp.srcport": return .tcpSourcePort(port)
                case "tcp.dstport": return .tcpDestinationPort(port)
                case "udp.port": return .udpPort(port)
                case "udp.srcport": return .udpSourcePort(port)
                case "udp.dstport": return .udpDestinationPort(port)
                case "sctp.port": return .sctpPort(port)
                case "sctp.srcport": return .sctpSourcePort(port)
                default: return .sctpDestinationPort(port)
                }
            case "dns.rcode":
                guard let code = UInt8(value.text), code <= 15 else {
                    throw FrameExpressionError(
                        position: value.position,
                        reason: "Expected a DNS response code from 0 to 15"
                    )
                }
                return .dnsResponseCode(code)
            case "ip.addr",
                 "ip.src":
                guard let address = IPAddressValue(parsing: value.text) else {
                    throw FrameExpressionError(position: value.position, reason: "Expected an IP address")
                }
                return field.text.lowercased() == "ip.addr" ? .ipAddress(address) : .ipSource(address)
            default:
                guard let address = IPAddressValue(parsing: value.text) else {
                    throw FrameExpressionError(position: value.position, reason: "Expected an IP address")
                }
                return .ipDestination(address)
            }
        default:
            throw FrameExpressionError(position: field.position, reason: "Unsupported frame field: \(field.text)")
        }
    }

    private mutating func parseTCPRawPredicate(field: Token) throws -> FrameExpression.Predicate {
        guard consume("==") else {
            throw FrameExpressionError(position: position, reason: "Expected ==")
        }
        guard index < tokens.count else {
            throw FrameExpressionError(position: position, reason: "Expected a raw TCP value")
        }
        let value = tokens[index]
        index += 1
        guard let rawValue = UInt32(value.text) else {
            throw FrameExpressionError(
                position: value.position,
                reason: "Expected a raw TCP value from 0 to 4294967295"
            )
        }
        return field.text.lowercased() == "tcp.seq_raw"
            ? .tcpSequenceRaw(rawValue) : .tcpAcknowledgementRaw(rawValue)
    }

    private mutating func parseCaptureDirection() throws -> FrameExpression.Predicate {
        guard consume("==") else {
            throw FrameExpressionError(position: position, reason: "Expected ==")
        }
        guard index < tokens.count else {
            throw FrameExpressionError(position: position, reason: "Expected inbound or outbound")
        }
        let value = tokens[index]
        index += 1
        switch value.text.lowercased() {
        case "inbound": return .captureDirection(.inbound)
        case "outbound": return .captureDirection(.outbound)
        default:
            throw FrameExpressionError(position: value.position, reason: "Expected inbound or outbound")
        }
    }

    private mutating func parseDNSIdentifier(field: Token) throws -> FrameExpression.Predicate {
        guard consume("==") else {
            throw FrameExpressionError(position: position, reason: "Expected ==")
        }
        guard index < tokens.count, let identifier = UInt16(tokens[index].text) else {
            throw FrameExpressionError(
                position: index < tokens.count ? tokens[index].position : position,
                reason: "Expected a DNS transaction ID from 0 to 65535"
            )
        }
        index += 1
        return .dnsTransactionID(identifier)
    }

    private mutating func parseIPv4FragmentOffset() throws -> FrameExpression.Predicate {
        guard index < tokens.count,
              let comparison = FrameExpression.NumericComparison(rawValue: tokens[index].text) else
        {
            throw FrameExpressionError(position: position, reason: "Expected ==, >, >=, <, or <=")
        }
        index += 1
        guard index < tokens.count, let value = UInt16(tokens[index].text) else {
            throw FrameExpressionError(
                position: index < tokens.count ? tokens[index].position : position,
                reason: "Expected an IPv4 fragment offset from 0 to 65535"
            )
        }
        index += 1
        return .ipv4FragmentOffset(comparison, value)
    }

    private mutating func parseIPv4Identification(field: Token) throws -> FrameExpression.Predicate {
        guard consume("==") else {
            throw FrameExpressionError(position: position, reason: "Expected ==")
        }
        guard index < tokens.count, let identifier = UInt16(tokens[index].text) else {
            throw FrameExpressionError(
                position: index < tokens.count ? tokens[index].position : position,
                reason: "Expected an IPv4 identification value from 0 to 65535"
            )
        }
        index += 1
        return .ipv4Identification(identifier)
    }

    private mutating func parseICMPPredicate(field: Token) throws -> FrameExpression.Predicate {
        guard consume("==") else {
            throw FrameExpressionError(position: position, reason: "Expected ==")
        }
        guard index < tokens.count, let value = UInt8(tokens[index].text) else {
            throw FrameExpressionError(
                position: index < tokens.count ? tokens[index].position : position,
                reason: "Expected an ICMP type or code from 0 to 255"
            )
        }
        index += 1
        return switch field.text.lowercased() {
        case "icmp.type": .icmpType(value)
        case "icmp.code": .icmpCode(value)
        case "icmpv6.type": .icmpv6Type(value)
        default: .icmpv6Code(value)
        }
    }

    private mutating func consume(_ text: String) -> Bool {
        guard index < tokens.count, tokens[index].text.lowercased() == text else {
            return false
        }
        index += 1
        return true
    }
}

// MARK: - FrameExpressionSelection

/// Evaluated off the main actor over the scanner's bounded retained window.
/// Unknown frames are excluded from matches and counted for honest coverage.
nonisolated struct FrameExpressionSelection: Sendable {
    let matchingOrdinals: Set<UInt64>
    let unknownCount: Int

    static func evaluate(_ expression: FrameExpression, rows: [CaptureFrameRow]) -> Self? {
        var matches: Set<UInt64> = []
        var unknown = 0
        for (index, row) in rows.enumerated() {
            if index.isMultiple(of: 1_024), Task.isCancelled {
                return nil
            }
            switch expression.evaluate(row.filterFacts) {
            case .yes: matches.insert(row.ordinal)
            case .no: break
            case .unknown: unknown += 1
            }
        }
        return Self(matchingOrdinals: matches, unknownCount: unknown)
    }
}

// MARK: - FrameExpressionCaptureCoverage

/// A complete stable-source pass keeps only counts and the nearest matching
/// ordinals outside the current retained window. No capture-wide ordinal set is
/// held in memory.
nonisolated struct FrameExpressionCaptureCoverage: Sendable, Equatable {
    let matchingCount: Int
    let unknownCount: Int
    let previousMatchOrdinal: UInt64?
    let nextMatchOrdinal: UInt64?
}

// MARK: - FrameExpressionCaptureCounter

nonisolated struct FrameExpressionCaptureCounter {
    // MARK: Lifecycle

    init(expression: FrameExpression, pageStart: Int, pageSize: Int) {
        self.expression = expression
        firstPageOrdinal = UInt64(max(1, pageStart))
        lastPageOrdinal = firstPageOrdinal + UInt64(max(1, pageSize)) - 1
    }

    // MARK: Internal

    private(set) var matchingCount = 0
    private(set) var unknownCount = 0
    private(set) var previousMatchOrdinal: UInt64?
    private(set) var nextMatchOrdinal: UInt64?

    var coverage: FrameExpressionCaptureCoverage {
        FrameExpressionCaptureCoverage(
            matchingCount: matchingCount,
            unknownCount: unknownCount,
            previousMatchOrdinal: previousMatchOrdinal,
            nextMatchOrdinal: nextMatchOrdinal
        )
    }

    mutating func record(_ row: CaptureFrameRow) {
        switch expression.evaluate(row.filterFacts) {
        case .yes:
            matchingCount += 1
            if row.ordinal < firstPageOrdinal {
                previousMatchOrdinal = row.ordinal
            } else if row.ordinal > lastPageOrdinal, nextMatchOrdinal == nil {
                nextMatchOrdinal = row.ordinal
            }
        case .no:
            break
        case .unknown:
            unknownCount += 1
        }
    }

    // MARK: Private

    private let expression: FrameExpression
    private let firstPageOrdinal: UInt64
    private let lastPageOrdinal: UInt64
}
