import Foundation

// MARK: - DecodedFieldFilter

/// Wireshark's Apply as Filter and Prepare as Filter for the decode tree: the Session
/// Expression term that finds the sessions carrying a field's value — an address, a
/// port, a MAC, a host name, an HTTP method or status, a DHCP message type — or a
/// layer's protocol. A field with no session-level term offers no filter; every term
/// offered parses.
nonisolated enum DecodedFieldFilter {
    // MARK: Internal

    /// How the term joins the expression already in the editor, as Wireshark's six
    /// Apply as Filter items.
    enum Combination: String, CaseIterable, Identifiable {
        case selected
        case notSelected
        case andSelected
        case orSelected
        case andNotSelected
        case orNotSelected

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .selected: String(localized: "Selected")
            case .notSelected: String(localized: "Not Selected")
            case .andSelected: String(localized: "…and Selected")
            case .orSelected: String(localized: "…or Selected")
            case .andNotSelected: String(localized: "…and not Selected")
            case .orNotSelected: String(localized: "…or not Selected")
            }
        }

        /// The expression this combination makes of `existing` and `term`; with no
        /// existing expression, the term alone (negated where the item says not).
        func combine(_ existing: String, _ term: String) -> String {
            let trimmed = existing.trimmingCharacters(in: .whitespacesAndNewlines)
            let negated = "not \(DecodedFieldFilter.grouped(term))"
            switch self {
            case .selected: return term
            case .notSelected: return negated
            case .andSelected: return SessionExpressionTerm.narrowing(trimmed, with: term)
            case .andNotSelected: return SessionExpressionTerm.narrowing(trimmed, with: negated)
            case .orSelected: return trimmed.isEmpty ? term : "\(trimmed) or \(term)"
            case .orNotSelected: return trimmed.isEmpty ? negated : "\(trimmed) or \(negated)"
            }
        }
    }

    /// The term for one decoded field, or `nil` when sessions cannot be found by it.
    static func term(proto: ProtocolKind, field name: String, value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let term: String? = switch (proto, name) {
        case (.ethernet, "Source"),
             (.ethernet, "Destination"):
            SessionSummary.normalizedMAC(value) == nil ? nil : "mac == \(value)"
        case (.ipv4, "Source"),
             (.ipv4, "Destination"),
             (.ipv6, "Source"),
             (.ipv6, "Destination"):
            IPAddressValue(parsing: value) == nil ? nil : "ip == \(value)"
        case (.tcp, "Source Port"),
             (.tcp, "Destination Port"),
             (.udp, "Source Port"),
             (.udp, "Destination Port"):
            UInt16(value.prefix { $0.isNumber }).map { "port == \($0)" }
        case (.http, "Request"):
            value.split(separator: " ").first.map { "http.method == \($0)" }
        case (.http, "Status"):
            value.split(separator: " ").first.map { "http.status == \($0)" }
        case (.http, "Host"):
            SessionExpressionTerm.sameHost(hostWithoutPort(value))
        case (.tls, "server_name"),
             (.dns, "Query"),
             (.mdns, "Query"),
             (.llmnr, "Query"):
            SessionExpressionTerm.sameHost(value)
        case (.dhcp, "Message type"):
            "dhcp.message == \(value)"
        default:
            nil
        }
        return term.flatMap(parsed)
    }

    /// The protocol keyword for a layer, or `nil` when the protocol has none.
    static func term(for proto: ProtocolKind) -> String? {
        SessionExpressionTerm.sameProtocol(proto).flatMap(parsed)
    }

    // MARK: Private

    /// `term` if the parser accepts it.
    private static func parsed(_ term: String) -> String? {
        (try? SessionQueryParser().parse(term)) == nil ? nil : term
    }

    /// A term with a space in it, parenthesized so `not` covers all of it.
    private static func grouped(_ term: String) -> String {
        term.contains(" ") ? "(\(term))" : term
    }

    /// `name:port` without its port; a bracketed or bare IPv6 literal is kept.
    private static func hostWithoutPort(_ host: String) -> String {
        guard !host.hasPrefix("["), host.filter({ $0 == ":" }).count == 1,
              let colon = host.lastIndex(of: ":"), host[host.index(after: colon)...].allSatisfy(\.isNumber) else
        {
            return host
        }
        return String(host[..<colon])
    }
}
