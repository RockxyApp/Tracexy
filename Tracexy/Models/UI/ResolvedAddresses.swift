import Foundation

// MARK: - ResolvedAddressSource

/// Where a name for an address came from.
nonisolated enum ResolvedAddressSource: Hashable, Sendable {
    /// A unicast DNS answer observed in this capture.
    case dns
    /// A multicast DNS (Bonjour) answer observed in this capture.
    case mdns
    /// A name the user gave the address in this Project.
    case named
    /// A name the user gave an IPv4 block in this Project (the row's address is the block).
    case namedSubnet

    // MARK: Internal

    var label: String {
        switch self {
        case .dns: "DNS answer"
        case .mdns: "mDNS answer"
        case .named: "Named by you"
        case .namedSubnet: "Subnet named by you"
        }
    }
}

// MARK: - ResolvedAddressRow

/// One address and one name it was given, with the session that taught it.
nonisolated struct ResolvedAddressRow: Identifiable, Hashable, Sendable {
    let address: String
    let name: String
    let source: ResolvedAddressSource
    /// The DNS or mDNS session whose answer carried the name; `nil` for a name the
    /// user gave.
    let sessionID: UUID?
    /// How many sessions' answers gave this address this name.
    let answerCount: Int
    /// Whether answers in this capture gave the address more than one name, so a
    /// session to it may be labelled with a different one.
    let hasOtherNames: Bool

    var id: String {
        "\(address)|\(name)|\(source.label)"
    }
}

// MARK: - ResolvedAddresses

/// The names learned for addresses in a capture — from DNS and mDNS answers carried by
/// its sessions — beside the names the user gave in this Project. Derived from the
/// sessions on demand, so it holds nothing the sessions do not already hold, and every
/// learned name leads back to the session whose answer carried it.
nonisolated enum ResolvedAddresses {
    // MARK: Internal

    static func rows(
        sessions: [SessionSummary],
        namedAddresses: [String: String],
        namedSubnets: [String: String] = [:]
    )
        -> [ResolvedAddressRow]
    {
        struct Learned {
            var source: ResolvedAddressSource
            var sessionID: UUID
            var ordinal: UInt64
            var count: Int
        }
        var learned: [String: [String: Learned]] = [:]
        for session in sessions {
            guard let name = session.dnsQuery?.trimmingCharacters(in: .whitespaces), !name.isEmpty,
                  !session.dnsAnswers.isEmpty else
            {
                continue
            }
            let source: ResolvedAddressSource = session.protocolStack.contains(.mdns) ? .mdns : .dns
            let ordinal = session.firstCaptureOrdinal ?? .max
            for answer in session.dnsAnswers where IPAddressValue(parsing: answer) != nil {
                if var existing = learned[answer]?[name] {
                    existing.count += 1
                    if ordinal < existing.ordinal {
                        existing.ordinal = ordinal
                        existing.sessionID = session.id
                        existing.source = source
                    }
                    learned[answer]?[name] = existing
                } else {
                    learned[answer, default: [:]][name] = Learned(
                        source: source, sessionID: session.id, ordinal: ordinal, count: 1
                    )
                }
            }
        }

        var rows: [ResolvedAddressRow] = []
        for (address, names) in learned {
            for (name, fact) in names {
                rows.append(ResolvedAddressRow(
                    address: address, name: name, source: fact.source, sessionID: fact.sessionID,
                    answerCount: fact.count, hasOtherNames: names.count > 1
                ))
            }
        }
        for (address, name) in namedAddresses {
            rows.append(ResolvedAddressRow(
                address: address, name: name, source: .named, sessionID: nil,
                answerCount: 0, hasOtherNames: false
            ))
        }
        for (block, name) in namedSubnets {
            rows.append(ResolvedAddressRow(
                address: block, name: name, source: .namedSubnet, sessionID: nil,
                answerCount: 0, hasOtherNames: false
            ))
        }
        return rows.sorted(by: precedes)
    }

    /// The Session Expression that finds the sessions a row explains.
    static func term(_ row: ResolvedAddressRow) -> String {
        row.source == .namedSubnet ? "ip in \(row.address)" : "ip == \(row.address)"
    }

    /// Whether `row` matches a filter typed by the user, over address and name.
    static func matches(_ row: ResolvedAddressRow, filter: String) -> Bool {
        let needle = filter.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else {
            return true
        }
        return row.address.localizedCaseInsensitiveContains(needle)
            || row.name.localizedCaseInsensitiveContains(needle)
    }

    // MARK: Private

    /// IPv4 before IPv6, each in numeric order; then name; then source.
    private static func precedes(_ lhs: ResolvedAddressRow, _ rhs: ResolvedAddressRow) -> Bool {
        // A subnet row sorts by its network address.
        let left = IPAddressValue(parsing: String(lhs.address.prefix { $0 != "/" }))
        let right = IPAddressValue(parsing: String(rhs.address.prefix { $0 != "/" }))
        if let left, let right, left != right {
            if left.bytes.count != right.bytes.count {
                return left.bytes.count < right.bytes.count
            }
            return left.bytes.lexicographicallyPrecedes(right.bytes)
        }
        if lhs.address != rhs.address {
            return lhs.address < rhs.address
        }
        if lhs.name != rhs.name {
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
        return lhs.source.label < rhs.source.label
    }
}
