import Foundation

// MARK: - FirewallProduct

/// The firewalls Tools ▸ Firewall Rules writes for, as Wireshark's Firewall ACL
/// Rules dialog does (with pf first, since it is the Mac's own).
enum FirewallProduct: String, CaseIterable, Identifiable {
    case pf
    case iptables
    case nftables
    case ipfw
    case ciscoACL
    case windows

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .pf: String(localized: "Packet Filter (pf)")
        case .iptables: String(localized: "Netfilter (iptables)")
        case .nftables: String(localized: "Netfilter (nftables)")
        case .ipfw: String(localized: "IPFirewall (ipfw)")
        case .ciscoACL: String(localized: "Cisco IOS access list")
        case .windows: String(localized: "Windows Firewall (netsh)")
        }
    }
}

// MARK: - FirewallRuleScope

/// What the rule matches, from the selected session's client → server tuple.
enum FirewallRuleScope: String, CaseIterable, Identifiable {
    case sourceAddress
    case destinationAddress
    case destinationPort
    case conversation

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .sourceAddress: String(localized: "Source address")
        case .destinationAddress: String(localized: "Destination address")
        case .destinationPort: String(localized: "Destination port")
        case .conversation: String(localized: "Both addresses and the port")
        }
    }

    var usesPort: Bool {
        self == .destinationPort || self == .conversation
    }
}

// MARK: - FirewallRules

/// Rule text for one session's traffic. Pure and offline: it only formats the
/// addresses and port the session already shows; nothing is applied.
enum FirewallRules {
    // MARK: Internal

    struct Request: Equatable {
        let product: FirewallProduct
        let scope: FirewallRuleScope
        let source: IPEndpoint
        let destination: IPEndpoint
        /// `tcp`, `udp`, or `nil` for any other protocol (no port rules then).
        let transport: String?
        var deny = true
        var inbound = true
    }

    /// The rule, or `nil` when the scope needs a port the session does not have.
    static func rule(_ request: Request) -> String? {
        guard !request.scope.usesPort || (request.transport != nil && request.destination.port > 0) else {
            return nil
        }
        return switch request.product {
        case .pf: pf(request)
        case .iptables: iptables(request)
        case .nftables: nftables(request)
        case .ipfw: ipfw(request)
        case .ciscoACL: cisco(request)
        case .windows: windows(request)
        }
    }

    // MARK: Private

    private static func isIPv6(_ address: String) -> Bool {
        address.contains(":")
    }

    private static func matchesSource(_ request: Request) -> Bool {
        request.scope == .sourceAddress || request.scope == .conversation
    }

    private static func matchesDestination(_ request: Request) -> Bool {
        request.scope == .destinationAddress || request.scope == .conversation
    }

    private static func pf(_ request: Request) -> String {
        var parts = [request.deny ? "block" : "pass", request.inbound ? "in" : "out", "quick"]
        if request.scope.usesPort, let transport = request.transport {
            parts += ["proto", transport]
        } else if request.scope != .destinationPort {
            parts.append(isIPv6(request.source.ip) ? "inet6" : "inet")
        }
        parts += ["from", matchesSource(request) ? request.source.ip : "any"]
        parts += ["to", matchesDestination(request) ? request.destination.ip : "any"]
        if request.scope.usesPort {
            parts += ["port", String(request.destination.port)]
        }
        return parts.joined(separator: " ")
    }

    private static func iptables(_ request: Request) -> String {
        var parts = [isIPv6(request.source.ip) ? "ip6tables" : "iptables", "-A", request.inbound ? "INPUT" : "OUTPUT"]
        if request.scope.usesPort, let transport = request.transport {
            parts += ["-p", transport]
        }
        if matchesSource(request) {
            parts += ["-s", request.source.ip]
        }
        if matchesDestination(request) {
            parts += ["-d", request.destination.ip]
        }
        if request.scope.usesPort {
            parts += ["--dport", String(request.destination.port)]
        }
        parts += ["-j", request.deny ? "DROP" : "ACCEPT"]
        return parts.joined(separator: " ")
    }

    private static func nftables(_ request: Request) -> String {
        let family = isIPv6(request.source.ip) ? "ip6" : "ip"
        var parts = ["nft", "add", "rule", "inet", "filter", request.inbound ? "input" : "output"]
        if matchesSource(request) {
            parts += [family, "saddr", request.source.ip]
        }
        if matchesDestination(request) {
            parts += [family, "daddr", request.destination.ip]
        }
        if request.scope.usesPort, let transport = request.transport {
            parts += [transport, "dport", String(request.destination.port)]
        }
        parts.append(request.deny ? "drop" : "accept")
        return parts.joined(separator: " ")
    }

    private static func ipfw(_ request: Request) -> String {
        var parts = ["ipfw", "add", request.deny ? "deny" : "allow"]
        parts.append(request.scope.usesPort ? request.transport ?? "ip" : "ip")
        parts += ["from", matchesSource(request) ? request.source.ip : "any"]
        parts += ["to", matchesDestination(request) ? request.destination.ip : "any"]
        if request.scope.usesPort {
            parts.append(String(request.destination.port))
        }
        parts.append(request.inbound ? "in" : "out")
        return parts.joined(separator: " ")
    }

    private static func cisco(_ request: Request) -> String {
        let v6 = isIPv6(request.source.ip)
        var parts = [request.deny ? "deny" : "permit"]
        parts.append(request.scope.usesPort ? request.transport ?? "ip" : (v6 ? "ipv6" : "ip"))
        parts.append(matchesSource(request) ? "host \(request.source.ip)" : "any")
        parts.append(matchesDestination(request) ? "host \(request.destination.ip)" : "any")
        if request.scope.usesPort {
            parts += ["eq", String(request.destination.port)]
        }
        let entry = parts.joined(separator: " ")
        let direction = request.inbound ? "in" : "out"
        if v6 {
            return "ipv6 access-list TRACEXY\n \(entry)\n! apply: ipv6 traffic-filter TRACEXY \(direction)"
        }
        return "access-list 101 \(entry)\n! apply: ip access-group 101 \(direction)"
    }

    /// netsh names addresses from this machine's side: inbound traffic comes from
    /// the remote source to a local port; outbound goes from local to a remote one.
    private static func windows(_ request: Request) -> String {
        var parts = [
            "netsh", "advfirewall", "firewall", "add", "rule", "name=\"Tracexy rule\"",
            "dir=\(request.inbound ? "in" : "out")", "action=\(request.deny ? "block" : "allow")",
        ]
        if request.scope.usesPort, let transport = request.transport {
            parts.append("protocol=\(transport.uppercased())")
        }
        let sourceKey = request.inbound ? "remoteip" : "localip"
        let destinationKey = request.inbound ? "localip" : "remoteip"
        if matchesSource(request) {
            parts.append("\(sourceKey)=\(request.source.ip)")
        }
        if matchesDestination(request) {
            parts.append("\(destinationKey)=\(request.destination.ip)")
        }
        if request.scope.usesPort {
            parts.append("\(request.inbound ? "localport" : "remoteport")=\(request.destination.port)")
        }
        return parts.joined(separator: " ")
    }
}
