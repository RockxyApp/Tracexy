import Foundation

/// Packet-level terms offered by the decode tree. These use Tracexy's Frame
/// Expression grammar and are deliberately separate from Session Expressions.
nonisolated enum DecodedFrameFilter {
    // MARK: Internal

    struct Availability: Sendable, Equatable {
        let hasSingleIPLayer: Bool
        let hasSingleTransportLayer: Bool
        let hasSingleTCPLayer: Bool
        let hasSingleICMPv4Layer: Bool
        let hasSingleICMPv6Layer: Bool
        let hasSingleDNSLayer: Bool

        func supports(proto: ProtocolKind, field: String) -> Bool {
            switch (proto, field) {
            case (.ipv4, "Source"),
                 (.ipv4, "Destination"),
                 (.ipv6, "Source"),
                 (.ipv6, "Destination"),
                 (.ipv4, "Identification"),
                 (.ipv4, "TTL"),
                 (.ipv6, "Hop Limit"),
                 (.ipv4, "Fragment Offset"),
                 (.ipv4, "More Fragments"),
                 (.ipv4, "Don't Fragment"):
                hasSingleIPLayer
            case (.tcp, "Source Port"),
                 (.tcp, "Destination Port"),
                 (.udp, "Source Port"),
                 (.udp, "Destination Port"):
                hasSingleTransportLayer
            case (.tcp, "Window"),
                 (.tcp, "Seq"),
                 (.tcp, "Ack"):
                hasSingleTransportLayer && hasSingleTCPLayer
            case (.tcp, "FIN"),
                 (.tcp, "SYN"),
                 (.tcp, "RST"),
                 (.tcp, "PSH"),
                 (.tcp, "Acknowledgment (ACK)"),
                 (.tcp, "URG"),
                 (.tcp, "ECE"),
                 (.tcp, "CWR"):
                hasSingleTransportLayer && hasSingleTCPLayer
            case (.icmp, "Type"),
                 (.icmp, "Code"):
                hasSingleICMPv4Layer
            case (.icmpv6, "Type"),
                 (.icmpv6, "Code"):
                hasSingleICMPv6Layer
            case (.dns, "Transaction ID"),
                 (.mdns, "Transaction ID"),
                 (.llmnr, "Transaction ID"):
                hasSingleDNSLayer
            case (.dns, "Truncated (TC)"),
                 (.mdns, "Truncated (TC)"),
                 (.llmnr, "Truncated (TC)"):
                hasSingleDNSLayer
            default:
                false
            }
        }
    }

    static func availability(in layers: [DecodedLayer]) -> Availability {
        var ipCount = 0
        var transportCount = 0
        var tcpCount = 0
        var icmpv4Count = 0
        var icmpv6Count = 0
        var dnsCount = 0
        func count(_ layer: DecodedLayer) {
            switch layer.proto {
            case .ipv4,
                 .ipv6: ipCount += 1
            case .tcp: transportCount += 1
                tcpCount += 1
            case .udp: transportCount += 1
            case .icmp: icmpv4Count += 1
            case .icmpv6: icmpv6Count += 1
            case .dns,
                 .mdns,
                 .llmnr: dnsCount += 1
            default: break
            }
            layer.children.forEach(count)
        }
        layers.forEach(count)
        return Availability(
            hasSingleIPLayer: ipCount == 1,
            hasSingleTransportLayer: transportCount == 1,
            hasSingleTCPLayer: tcpCount == 1,
            hasSingleICMPv4Layer: icmpv4Count == 1,
            hasSingleICMPv6Layer: icmpv6Count == 1,
            hasSingleDNSLayer: dnsCount == 1
        )
    }

    static func term(proto: ProtocolKind, field name: String, value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let term: String? = switch (proto, name) {
        case (.ipv4, "Source"),
             (.ipv6, "Source"):
            IPAddressValue(parsing: value).map { _ in "ip.src == \(value)" }
        case (.ipv4, "Destination"),
             (.ipv6, "Destination"):
            IPAddressValue(parsing: value).map { _ in "ip.dst == \(value)" }
        case (.ipv4, "TTL"):
            UInt8(value).map { "ip.ttl == \($0)" }
        case (.ipv4, "Identification"):
            ipv4IdentificationValue(value).map { "ip.id == \($0)" }
        case (.ipv6, "Hop Limit"):
            UInt8(value).map { "ipv6.hlim == \($0)" }
        case (.ipv4, "Fragment Offset"):
            UInt16(value).map { "ip.frag_offset == \($0)" }
        case (.ipv4, "More Fragments"):
            switch value.lowercased() {
            case "yes",
                 "true",
                 "1": "ip.flags.mf"
            case "no",
                 "false",
                 "0": "not ip.flags.mf"
            default: nil
            }
        case (.ipv4, "Don't Fragment"):
            switch value.lowercased() {
            case "yes",
                 "true",
                 "1": "ip.flags.df"
            case "no",
                 "false",
                 "0": "not ip.flags.df"
            default: nil
            }
        case (.tcp, "Source Port"):
            UInt16(value.prefix { $0.isNumber }).map { "tcp.srcport == \($0)" }
        case (.tcp, "Destination Port"):
            UInt16(value.prefix { $0.isNumber }).map { "tcp.dstport == \($0)" }
        case (.udp, "Source Port"):
            UInt16(value.prefix { $0.isNumber }).map { "udp.srcport == \($0)" }
        case (.udp, "Destination Port"):
            UInt16(value.prefix { $0.isNumber }).map { "udp.dstport == \($0)" }
        case (.tcp, "Window"):
            UInt16(value).map { "tcp.window_size_value == \($0)" }
        case (.tcp, "Seq"):
            UInt32(value).map { "tcp.seq_raw == \($0)" }
        case (.tcp, "Ack"):
            UInt32(value).map { "tcp.ack_raw == \($0)" }
        case (.tcp, "FIN"),
             (.tcp, "SYN"),
             (.tcp, "RST"),
             (.tcp, "PSH"),
             (.tcp, "Acknowledgment (ACK)"),
             (.tcp, "URG"),
             (.tcp, "ECE"),
             (.tcp, "CWR"):
            tcpFlagTerm(field: name, value: value)
        case (.icmp, "Type"):
            icmpTypeValue(value).map { "icmp.type == \($0)" }
        case (.icmp, "Code"):
            UInt8(value).map { "icmp.code == \($0)" }
        case (.icmpv6, "Type"):
            icmpTypeValue(value).map { "icmpv6.type == \($0)" }
        case (.icmpv6, "Code"):
            UInt8(value).map { "icmpv6.code == \($0)" }
        case (.dns, "Transaction ID"),
             (.mdns, "Transaction ID"),
             (.llmnr, "Transaction ID"):
            UInt16(value).map { "dns.id == \($0)" }
        case (.dns, "Truncated (TC)"),
             (.mdns, "Truncated (TC)"),
             (.llmnr, "Truncated (TC)"):
            switch value.lowercased() {
            case "yes",
                 "true",
                 "1": "dns.flags.truncated"
            case "no",
                 "false",
                 "0": "not dns.flags.truncated"
            default: nil
            }
        default:
            nil
        }
        guard let term else {
            return nil
        }
        var parser = FrameExpressionParser()
        return (try? parser.parse(term)) == nil ? nil : term
    }

    // MARK: Private

    private static func icmpTypeValue(_ displayValue: String) -> UInt8? {
        guard displayValue.hasSuffix(")"),
              let opening = displayValue.lastIndex(of: "(") else
        {
            return nil
        }
        let numberStart = displayValue.index(after: opening)
        let numberEnd = displayValue.index(before: displayValue.endIndex)
        return UInt8(displayValue[numberStart ..< numberEnd])
    }

    private static func ipv4IdentificationValue(_ displayValue: String) -> UInt16? {
        let hexadecimal = displayValue.lowercased()
        guard hexadecimal.hasPrefix("0x") else {
            return nil
        }
        return UInt16(hexadecimal.dropFirst(2), radix: 16)
    }

    private static func tcpFlagTerm(field: String, value: String) -> String? {
        let expression: String? = switch field {
        case "FIN": "tcp.flags.fin"
        case "SYN": "tcp.flags.syn"
        case "RST": "tcp.flags.reset"
        case "PSH": "tcp.flags.push"
        case "Acknowledgment (ACK)": "tcp.flags.ack"
        case "URG": "tcp.flags.urg"
        case "ECE": "tcp.flags.ece"
        case "CWR": "tcp.flags.cwr"
        default: nil
        }
        guard let expression else {
            return nil
        }
        return switch value.lowercased() {
        case "yes",
             "true",
             "1": expression
        case "no",
             "false",
             "0": "not \(expression)"
        default: nil
        }
    }
}
