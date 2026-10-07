import Foundation

// MARK: - EncryptedDNSTransport

nonisolated enum EncryptedDNSTransport: String, CaseIterable, Sendable {
    case tls
    case quic
    case https

    // MARK: Internal

    var title: String {
        switch self {
        case .tls: "DNS over TLS"
        case .quic: "DNS over QUIC"
        case .https: "DNS over HTTPS"
        }
    }
}

// MARK: - EncryptedDNSRow

/// One encrypted-DNS server the sessions in view talked to, how, and on what basis
/// Tracexy says so. The payload stays encrypted: nothing here names a query.
nonisolated struct EncryptedDNSRow: Identifiable, Hashable, Sendable {
    let server: String
    let transport: EncryptedDNSTransport
    /// Why the sessions count as encrypted DNS: the standard port (853), or — for
    /// DNS over HTTPS, which shares port 443 with the web — the server's name.
    let basis: String
    var sessionCount: Int
    var byteCount: Int

    var id: String {
        "\(transport.rawValue)|\(server)"
    }
}

// MARK: - EncryptedDNS

/// Answers "is my DNS encrypted?" for the sessions in view, from facts every
/// session already carries: DNS over TLS and over QUIC use port 853 (RFC 7858,
/// RFC 9250); DNS over HTTPS is ordinary HTTPS, so it is recognized only by a
/// server name on a list of well-known public resolvers — and says so.
nonisolated enum EncryptedDNS {
    /// Public DNS-over-HTTPS endpoints as their operators document them. A private
    /// or unlisted resolver is simply not recognized; nothing is guessed from traffic.
    static let knownHTTPSResolvers: Set<String> = [
        "dns.google", "dns.google.com", "dns64.dns.google",
        "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
        "security.cloudflare-dns.com", "family.cloudflare-dns.com", "mozilla.cloudflare-dns.com",
        "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
        "doh.opendns.com", "doh.familyshield.opendns.com",
        "dns.nextdns.io", "dns.adguard-dns.com", "family.adguard-dns.com", "unfiltered.adguard-dns.com",
        "doh.cleanbrowsing.org", "dns.mullvad.net", "doh.mullvad.net", "freedns.controld.com",
        "doh.dns.sb", "dns.alidns.com", "doh.pub",
    ]

    /// The encrypted-DNS transport a session used, with its basis, or `nil`.
    static func classify(_ session: SessionSummary) -> (transport: EncryptedDNSTransport, basis: String)? {
        let stack = session.protocolStack
        let port = session.destinationEndpointValue?.port
        if port == 853, stack.contains(.tcp) {
            return (.tls, "port 853")
        }
        if port == 853, stack.contains(.udp) {
            return (.quic, "port 853")
        }
        let name = (session.sni ?? session.host).lowercased()
        if port == 443, stack.contains(.tls) || stack.contains(.quic), knownHTTPSResolvers.contains(name)
            || name.hasSuffix(".dns.nextdns.io")
        {
            return (.https, "server name")
        }
        return nil
    }

    static func rows(of sessions: [SessionSummary]) -> [EncryptedDNSRow] {
        var groups: [String: EncryptedDNSRow] = [:]
        for session in sessions {
            guard let (transport, basis) = classify(session) else {
                continue
            }
            let server = session.sni ?? session.host
            let key = "\(transport.rawValue)|\(server)"
            var row = groups[key]
                ?? EncryptedDNSRow(server: server, transport: transport, basis: basis, sessionCount: 0, byteCount: 0)
            row.sessionCount += 1
            row.byteCount += session.totalBytes
            groups[key] = row
        }
        return groups.values
            .sorted { ($0.sessionCount, $1.server) > ($1.sessionCount, $0.server) }
    }

    /// Unicast DNS sessions in the clear (multicast DNS excluded) beside the
    /// encrypted ones, for the one-line answer.
    static func summary(of sessions: [SessionSummary]) -> String {
        let plain = sessions.count { $0.protocolStack.contains(.dns) && !$0.protocolStack.contains(.mdns) }
        let encrypted = rows(of: sessions)
        let encryptedCount = encrypted.reduce(0) { $0 + $1.sessionCount }
        let plainText = plain == 1 ? "1 plain DNS session" : "\(plain.formatted()) plain DNS sessions"
        guard encryptedCount > 0 else {
            return "\(plainText), no encrypted DNS recognized"
        }
        let parts = EncryptedDNSTransport.allCases.compactMap { transport -> String? in
            let count = encrypted.filter { $0.transport == transport }.reduce(0) { $0 + $1.sessionCount }
            guard count > 0 else {
                return nil
            }
            return "\(transport.title) \(count.formatted())"
        }
        return "\(plainText), \(encryptedCount.formatted()) encrypted (\(parts.joined(separator: ", ")))"
    }
}
