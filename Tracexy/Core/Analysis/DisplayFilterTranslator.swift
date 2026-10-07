import Foundation

// MARK: - DisplayFilterTranslation

nonisolated enum DisplayFilterTranslation: Equatable, Sendable {
    /// The Session Expression that finds the sessions the filter's packets belong
    /// to. `approximate` says the meaning shifted from packets to sessions in a way
    /// worth a look (for example a DNS response code read as a finding).
    case translated(String, approximate: Bool)
    /// Why no Session Expression says the same thing.
    case untranslatable(String)
}

// MARK: - DisplayFilterTranslator

/// Translates a Wireshark display filter — as saved in a `dfilters` file — into a
/// Tracexy Session Expression where one says the same thing about sessions. A
/// display filter selects packets and a Session Expression selects sessions, so
/// only fields with a session meaning translate: addresses, ports, protocols,
/// HTTP method/status, the names a session is known by, and the TCP/DNS/ICMP/TLS
/// conditions Tracexy reports as findings. Everything else is refused with the
/// reason, never guessed. The result is checked by ``SessionQueryParser`` before
/// it is offered.
nonisolated enum DisplayFilterTranslator {
    // MARK: Internal

    static func translate(_ filter: String) -> DisplayFilterTranslation {
        let tokens: [Token]
        do {
            tokens = try tokenize(filter)
        } catch let error as Refusal {
            return .untranslatable(error.reason)
        } catch {
            return .untranslatable("The filter could not be read.")
        }
        guard !tokens.isEmpty else {
            return .untranslatable("The filter is empty.")
        }
        var output: [String] = []
        var approximate = false
        var index = 0
        do {
            while index < tokens.count {
                let token = tokens[index]
                switch token {
                case .open: output.append("(")
                case .close: output.append(")")
                case .and: output.append("and")
                case .or: output.append("or")
                case .not: output.append("not")
                case let .word(field):
                    var comparison: (op: String, value: Value)?
                    if index + 2 < tokens.count, case let .op(op) = tokens[index + 1] {
                        comparison = try (op, value(tokens[index + 2]))
                        index += 2
                    }
                    let term = try translateTerm(field: field, comparison: comparison)
                    approximate = approximate || term.approximate
                    output.append(term.text)
                default:
                    throw Refusal("“\(describe(token))” is not where a field was expected.")
                }
                index += 1
            }
        } catch let refusal as Refusal {
            return .untranslatable(refusal.reason)
        } catch {
            return .untranslatable("The filter could not be translated.")
        }
        let expression = output.joined(separator: " ").replacingOccurrences(of: "( ", with: "(")
            .replacingOccurrences(of: " )", with: ")")
        do {
            _ = try SessionQueryParser().parse(expression)
        } catch {
            return .untranslatable("The translation “\(expression.prefix(80))” is not a valid Session Expression.")
        }
        return .translated(expression, approximate: approximate)
    }

    // MARK: Private

    private struct Refusal: Error {
        // MARK: Lifecycle

        init(_ reason: String) {
            self.reason = reason
        }

        // MARK: Internal

        let reason: String
    }

    private enum Token: Equatable {
        case word(String)
        case text(String)
        case set([String])
        case op(String)
        case and
        case or
        case not
        case open
        case close
    }

    private enum Value {
        case literal(String)
        case text(String)
        case set([String])
    }

    private static let protocols: [String: String] = [
        "ip": "ipv4", "ipv6": "ipv6", "arp": "arp", "icmp": "icmp", "icmpv6": "icmpv6", "tcp": "tcp",
        "udp": "udp", "dns": "dns", "tls": "tls", "ssl": "tls", "http": "http", "http2": "http2",
        "quic": "quic", "websocket": "websocket", "stun": "stun", "mdns": "mdns", "dhcp": "dhcp",
        "bootp": "dhcp", "ntp": "ntp", "gre": "gre", "vxlan": "vxlan",
    ]

    /// Boolean fields Wireshark sets on packets that Tracexy reports as findings.
    private static let findingFlags: [String: String] = [
        "tcp.analysis.retransmission": "retransmission",
        "tcp.analysis.fast_retransmission": "fastRetransmission",
        "tcp.analysis.spurious_retransmission": "spuriousRetransmission",
        "tcp.analysis.duplicate_ack": "duplicateAck",
        "tcp.analysis.zero_window": "zeroWindow",
        "tcp.analysis.zero_window_probe": "zeroWindow",
        "tcp.analysis.window_full": "windowFull",
        "tcp.analysis.keep_alive": "keepAlive",
        "tcp.analysis.out_of_order": "outOfOrder",
        "tcp.analysis.lost_segment": "outOfOrder",
        "tcp.analysis.reused_ports": "tupleReuse",
        "tcp.analysis.ack_lost_segment": "ackedUnseen",
        "tcp.analysis.flags": "{retransmission, fastRetransmission, spuriousRetransmission, duplicateAck, "
            + "zeroWindow, windowFull, keepAlive, outOfOrder, tupleReuse}",
        "tls.alert_message": "{tlsFatalAlert, tlsWarningAlert}",
    ]

    private static let operators: [String: String] = [
        "==": "==", "eq": "==", "===": "==", "!=": "!=", "ne": "!=", "!==": "!=", ">=": ">=", "ge": ">=",
        "<=": "<=", "le": "<=", ">": ">", "gt": ">", "<": "<", "lt": "<", "contains": "contains",
        "matches": "matches", "~": "matches", "in": "in",
    ]

    private static func translateTerm(
        field: String,
        comparison: (op: String, value: Value)?
    )
        throws -> (text: String, approximate: Bool)
    {
        let lower = field.lowercased()
        guard let comparison else {
            if let name = protocols[lower] {
                return (name, false)
            }
            if let finding = findingFlags[lower] {
                return (finding.hasPrefix("{") ? "finding in \(finding)" : "finding == \(finding)", true)
            }
            // A bare field asks whether the packet has it; these have a session meaning.
            let presence: [String: String] = [
                "_ws.expert": "finding", "tls.handshake.extensions_server_name": "sni",
                "dns.qry.name": "dns.query", "dns.a": "dns.answer", "dns.aaaa": "dns.answer",
            ]
            if let term = presence[lower] {
                return (term, true)
            }
            throw Refusal("“\(field.prefix(64))” has no session meaning in Tracexy.")
        }
        switch lower {
        case "ip.addr",
             "ipv6.addr",
             "ip.host",
             "ipv6.host":
            return try (address("ip", comparison), false)
        case "ip.src",
             "ipv6.src",
             "ip.src_host",
             "ipv6.src_host":
            return try (address("source.ip", comparison), false)
        case "ip.dst",
             "ipv6.dst",
             "ip.dst_host",
             "ipv6.dst_host":
            return try (address("destination.ip", comparison), false)
        case "tcp.port",
             "udp.port":
            return try ("(\(lower.prefix(3)) and \(port("port", comparison)))", false)
        case "tcp.srcport",
             "udp.srcport":
            return try ("(\(lower.prefix(3)) and \(port("source.port", comparison)))", false)
        case "tcp.dstport",
             "udp.dstport":
            return try ("(\(lower.prefix(3)) and \(port("destination.port", comparison)))", false)
        case "eth.addr":
            return try (mac("mac", comparison), false)
        case "eth.src":
            return try (mac("source.mac", comparison), false)
        case "eth.dst":
            return try (mac("destination.mac", comparison), false)
        case "http.request.method":
            guard comparison.op == "==" || comparison.op == "in" else {
                throw Refusal("http.request.method translates only with == or in.")
            }
            return try (named("http.method", comparison, uppercase: true), false)
        case "http.response.code":
            return try (status(comparison), false)
        case "tcp.completeness":
            guard comparison.op == "==", case let .literal(value) = comparison.value,
                  UInt8(value).map({ $0 <= 63 }) == true else
            {
                throw Refusal("tcp.completeness translates only as == a number from 0 to 63.")
            }
            // Wireshark keeps this per packet of the stream; Tracexy per session — the same set.
            return ("tcp.completeness == \(value)", false)
        case "http.host",
             "tls.handshake.extensions_server_name",
             "dns.qry.name":
            return try (host(comparison), lower == "dns.qry.name")
        case "dns.flags.rcode":
            guard comparison.op == "==", case let .literal(code) = comparison.value else {
                throw Refusal("dns.flags.rcode translates only as == 2, 3 or 5.")
            }
            switch code {
            case "3": return ("finding == dnsNameError", true)
            case "2",
                 "5": return ("finding == dnsServerFailure", true)
            default: throw Refusal("DNS response code \(code.prefix(8)) is not a finding Tracexy reports.")
            }
        case "tcp.flags.reset":
            guard comparison.op == "==", case let .literal(flag) = comparison.value,
                  ["1", "true", "True"].contains(flag) else
            {
                throw Refusal("tcp.flags.reset translates only as == 1.")
            }
            return ("finding == reset", true)
        case "icmp.type",
             "icmpv6.type":
            guard comparison.op == "==", case let .literal(type) = comparison.value else {
                throw Refusal("\(lower) translates only as == a type number.")
            }
            let v6 = lower == "icmpv6.type"
            switch (v6, type) {
            case (false, "3"),
                 (true, "1"): return ("finding in {icmpUnreachable, icmpReportedUnreachable}", true)
            case (false, "11"),
                 (true, "3"): return ("finding in {icmpTimeExceeded, icmpReportedTimeExceeded}", true)
            case (true, "2"): return ("finding in {icmpPacketTooBig, icmpReportedPacketTooBig}", true)
            default: throw Refusal("ICMP type \(type.prefix(8)) is not a finding Tracexy reports.")
            }
        case "frame.len",
             "frame.number",
             "frame.time",
             "frame.time_relative",
             "frame.time_delta":
            throw Refusal("“\(lower)” describes single packets; a session has no such value.")
        default:
            throw Refusal("“\(field.prefix(64))” has no session meaning in Tracexy.")
        }
    }

    private static func address(_ field: String, _ comparison: (op: String, value: Value)) throws -> String {
        switch (comparison.op, comparison.value) {
        case let ("==", .literal(value)):
            return value.contains("/") ? "\(field) in \(value)" : "\(field) == \(value)"
        case let ("!=", .literal(value)):
            return value.contains("/") ? "not \(field) in \(value)" : "not \(field) == \(value)"
        case let ("in", .set(values)):
            return "\(field) in {\(values.joined(separator: ", "))}"
        default:
            throw Refusal("Addresses translate with ==, != or in {…}.")
        }
    }

    private static func port(_ field: String, _ comparison: (op: String, value: Value)) throws -> String {
        func number(_ text: String) throws -> Int {
            guard let value = Int(text), (0 ... 65_535).contains(value) else {
                throw Refusal("“\(text.prefix(16))” is not a port number.")
            }
            return value
        }
        switch (comparison.op, comparison.value) {
        case let ("==", .literal(value)): return try "\(field) == \(number(value))"
        case let ("!=", .literal(value)): return try "not \(field) == \(number(value))"
        case let (">=", .literal(value)): return try "\(field) in \(number(value))..65535"
        case let (">", .literal(value)): return try "\(field) in \(min(65_535, number(value) + 1))..65535"
        case let ("<=", .literal(value)): return try "\(field) in 0..\(number(value))"
        case let ("<", .literal(value)): return try "\(field) in 0..\(max(0, number(value) - 1))"
        case let ("in", .set(values)):
            let members = try values.map { member -> String in
                let parts = member.components(separatedBy: "..")
                return try parts.map { try String(number($0)) }.joined(separator: "..")
            }
            return "\(field) in {\(members.joined(separator: ", "))}"
        default:
            throw Refusal("Ports translate with ==, !=, >=, <=, >, < or in {…}.")
        }
    }

    private static func status(_ comparison: (op: String, value: Value)) throws -> String {
        func code(_ text: String) throws -> Int {
            guard let value = Int(text), (100 ... 599).contains(value) else {
                throw Refusal("“\(text.prefix(16))” is not an HTTP status code.")
            }
            return value
        }
        switch (comparison.op, comparison.value) {
        case let ("==", .literal(value)): return try "http.status == \(code(value))"
        case let ("!=", .literal(value)): return try "not http.status == \(code(value))"
        case let (">=", .literal(value)): return try "http.status in \(code(value))..599"
        case let (">", .literal(value)): return try "http.status in \(min(599, code(value) + 1))..599"
        case let ("<=", .literal(value)): return try "http.status in 100..\(code(value))"
        case let ("<", .literal(value)): return try "http.status in 100..\(max(100, code(value) - 1))"
        case let ("in", .set(values)):
            return try "http.status in {\(values.map { try String(code($0)) }.joined(separator: ", "))}"
        default:
            throw Refusal("http.response.code translates with a comparison or in {…}.")
        }
    }

    private static func named(
        _ field: String,
        _ comparison: (op: String, value: Value),
        uppercase: Bool
    )
        throws -> String
    {
        func clean(_ text: String) throws -> String {
            let value = uppercase ? text.uppercased() : text
            guard !value.isEmpty, value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
                throw Refusal("“\(text.prefix(16))” is not a plain name.")
            }
            return value
        }
        switch comparison.value {
        case let .literal(value),
             let .text(value):
            return try "\(field) == \(clean(value))"
        case let .set(values):
            return try "\(field) in {\(values.map(clean).joined(separator: ", "))}"
        }
    }

    /// `eth.addr == aa:bb:…` → `mac == aa:bb:…` (also `in { … }`).
    private static func mac(_ field: String, _ comparison: (op: String, value: Value)) throws -> String {
        guard comparison.op == "==" || comparison.op == "in" else {
            throw Refusal("MAC addresses translate only with == or in.")
        }
        func clean(_ text: String) throws -> String {
            guard let mac = SessionSummary.normalizedMAC(text) else {
                throw Refusal("“\(text.prefix(24))” is not a MAC address.")
            }
            return mac
        }
        switch comparison.value {
        case let .literal(value),
             let .text(value):
            return try "\(field) == \(clean(value))"
        case let .set(values):
            return try "\(field) in {\(values.map(clean).joined(separator: ", "))}"
        }
    }

    private static func host(_ comparison: (op: String, value: Value)) throws -> String {
        let text: String
        switch comparison.value {
        case let .text(value),
             let .literal(value):
            text = value
        case .set:
            throw Refusal("A set of names does not translate; use one name per filter.")
        }
        let quoted = "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(
            of: "\"",
            with: "\\\""
        ) + "\""
        switch comparison.op {
        case "==": return "host matches \(quoted)"
        case "contains": return "host contains \(quoted)"
        case "!=": return "not host matches \(quoted)"
        default: throw Refusal("Names translate with ==, != or contains (not regular expressions).")
        }
    }

    private static func value(_ token: Token) throws -> Value {
        switch token {
        case let .word(text): .literal(text)
        case let .text(text): .text(text)
        case let .set(values): .set(values)
        default: throw Refusal("A value is expected after the operator.")
        }
    }

    private static func describe(_ token: Token) -> String {
        switch token {
        case let .word(text): String(text.prefix(32))
        case .text: "text"
        case .set: "{…}"
        case let .op(op): op
        case .and: "and"
        case .or: "or"
        case .not: "not"
        case .open: "("
        case .close: ")"
        }
    }

    private static func tokenize(_ filter: String) throws -> [Token] {
        guard filter.count <= 1_024 else {
            throw Refusal("The filter is longer than 1,024 characters.")
        }
        var tokens: [Token] = []
        var characters = Array(filter)[...]
        func isWordCharacter(_ character: Character) -> Bool {
            character.isLetter || character.isNumber || "._:/-".contains(character)
        }
        while let character = characters.first {
            if character.isWhitespace {
                characters.removeFirst()
                continue
            }
            switch character {
            case "(":
                tokens.append(.open)
                characters.removeFirst()
            case ")":
                tokens.append(.close)
                characters.removeFirst()
            case "\"":
                characters.removeFirst()
                var text = ""
                var closed = false
                while let next = characters.popFirst() {
                    if next == "\\", let escaped = characters.popFirst() {
                        text.append(escaped)
                    } else if next == "\"" {
                        closed = true
                        break
                    } else {
                        text.append(next)
                    }
                }
                guard closed else {
                    throw Refusal("A quoted value has no closing quote.")
                }
                tokens.append(.text(text))
            case "{":
                characters.removeFirst()
                var inner = ""
                var closed = false
                while let next = characters.popFirst() {
                    if next == "}" {
                        closed = true
                        break
                    }
                    inner.append(next)
                }
                guard closed else {
                    throw Refusal("A set has no closing brace.")
                }
                let members = inner.split { $0 == "," || $0.isWhitespace }.map {
                    String($0).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                }
                guard !members.isEmpty else {
                    throw Refusal("A set is empty.")
                }
                tokens.append(.set(members))
            case "&",
                 "|",
                 "=",
                 "!",
                 "<",
                 ">",
                 "~":
                var symbol = String(characters.removeFirst())
                while let next = characters.first, "&|=<>".contains(next) {
                    symbol.append(characters.removeFirst())
                }
                switch symbol {
                case "&&": tokens.append(.and)
                case "||": tokens.append(.or)
                case "!": tokens.append(.not)
                default:
                    guard let op = operators[symbol] else {
                        throw Refusal("“\(symbol)” is not an operator Tracexy translates.")
                    }
                    tokens.append(.op(op))
                }
            default:
                guard isWordCharacter(character) else {
                    throw Refusal("“\(character)” is not something Tracexy translates.")
                }
                var word = ""
                while let next = characters.first, isWordCharacter(next) {
                    word.append(characters.removeFirst())
                }
                switch word.lowercased() {
                case "and": tokens.append(.and)
                case "or": tokens.append(.or)
                case "not": tokens.append(.not)
                case "xor": throw Refusal("xor does not translate.")
                default:
                    if let op = operators[word.lowercased()] {
                        tokens.append(.op(op))
                    } else {
                        tokens.append(.word(word))
                    }
                }
            }
        }
        return tokens
    }
}
