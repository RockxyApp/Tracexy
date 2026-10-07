import Foundation

// MARK: - ConversationFilter

/// Wireshark's Conversation Filter for a frame's session: the Session Expression that
/// keeps only that conversation at one layer — its two Ethernet addresses, its two IP
/// addresses, or its TCP or UDP endpoints. Every offered term parses.
nonisolated enum ConversationFilter {
    struct Option: Identifiable, Hashable, Sendable {
        let title: String
        let term: String

        var id: String {
            title
        }
    }

    static func options(for session: SessionSummary) -> [Option] {
        var options: [Option] = []
        if let macs = session.macAddresses {
            options.append(Option(title: "Ethernet", term: "mac == \(macs.client) and mac == \(macs.server)"))
        }
        if let source = session.sourceEndpointValue, let destination = session.destinationEndpointValue,
           let version = IPAddressValue(parsing: source.ip)
        {
            let addresses = "ip == \(source.ip) and ip == \(destination.ip)"
            options.append(Option(title: version.family == .v6 ? "IPv6" : "IPv4", term: addresses))
            for transport in [ProtocolKind.tcp, .udp] where session.protocolStack.contains(transport) {
                let ports = source.port == destination.port
                    ? "port == \(source.port)" : "port == \(source.port) and port == \(destination.port)"
                options.append(Option(
                    title: transport.label, term: "\(transport.rawValue) and \(addresses) and \(ports)"
                ))
            }
        }
        return options.filter { (try? SessionQueryParser().parse($0.term)) != nil }
    }
}
