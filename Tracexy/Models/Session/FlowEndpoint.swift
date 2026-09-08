import Foundation

/// One remote destination address in the captured traffic, with everything the
/// Flow surface needs to place it, list it and drill into it.
///
/// The map alone could only ever answer "roughly where is my traffic
/// administered" — five markers for the whole capture. The question users
/// actually arrive with is narrower and more concrete: *which address is that,
/// and what talked to it*. That needs a row per address, not a marker per
/// region, which is why this type exists alongside the region rollup rather
/// than being derived from it.
struct FlowEndpoint: Identifiable, Hashable {
    // MARK: Internal

    /// The bare remote destination address, without a port. Also the identity:
    /// one row per address, however many conversations it carried.
    ///
    /// Rows are grouped by the *binary* identity of the typed destination
    /// endpoint, so two spellings of one IPv6 address are one row; this is the
    /// deterministic text chosen to display that group (see
    /// ``endpoints(from:)``).
    let address: String
    /// Hostnames observed for this address, most-seen first. Usually one, but a
    /// CDN address legitimately answers to several — and the list says so
    /// rather than picking one.
    let names: [String]
    let region: EndpointRegion
    let bytes: Int
    let sessionCount: Int
    /// Worst status across the conversations with this address.
    let status: SessionStatus

    var id: String {
        address
    }

    /// The name to lead the row with, falling back to the address itself when
    /// nothing resolved it. Never invents a name.
    var displayName: String {
        names.first ?? address
    }

    /// Whether this address can be drawn on the map at all.
    ///
    /// Private, loopback, multicast and unallocated space has no registry
    /// region, so there is no honest point to put a marker at. Such endpoints
    /// stay in the *list* — they are real traffic and hiding them would make
    /// the totals lie — but they are marked as unmappable rather than dropped
    /// at 0,0 in the Gulf of Guinea.
    var isMappable: Bool {
        region != .local && region != .unknown
    }

    /// Builds one row per remote destination address from the sessions in view.
    ///
    /// Grouping is by the **typed** destination endpoint's binary address, never
    /// by re-parsing a rendered `"ip:port"` string: the display string is a
    /// presentation copy, and splitting it again is exactly how a row's session
    /// count drifts away from the list a click on it produces. Two spellings of
    /// the same IPv6 address therefore collapse into one row.
    ///
    /// A session whose typed destination is absent or not a valid address
    /// contributes to no row. It is not silently folded into one either — see
    /// ``omittedSessionCount(in:)``, which the surface reports so the totals here
    /// are never read as the whole capture.
    static func endpoints(from sessions: [SessionSummary]) -> [FlowEndpoint] {
        var bytes: [IPAddressValue: Int] = [:]
        var counts: [IPAddressValue: Int] = [:]
        var statuses: [IPAddressValue: SessionStatus] = [:]
        var nameCounts: [IPAddressValue: [String: Int]] = [:]
        var spellings: [IPAddressValue: String] = [:]

        for session in sessions {
            guard let destination = Self.destination(of: session) else {
                continue
            }
            let key = destination.value
            bytes[key, default: 0] += session.totalBytes
            counts[key, default: 0] += 1
            statuses[key] = Self.worse(statuses[key], session.status)
            // One deterministic spelling per group. The accumulator already
            // publishes canonical text, so this only decides between equivalent
            // spellings — and it decides the same way every run.
            if let existing = spellings[key] {
                spellings[key] = min(existing, destination.text)
            } else {
                spellings[key] = destination.text
            }
            if !session.host.isEmpty {
                nameCounts[key, default: [:]][session.host, default: 0] += 1
            }
        }

        return counts.keys.map { key in
            let address = spellings[key] ?? ""
            // A host that is just the address written out is not a resolved name
            // — it is the list falling back — so it is not recorded as one, in
            // whichever spelling it arrived.
            let names = (nameCounts[key] ?? [:])
                .filter { IPAddressValue(parsing: $0.key) != key }
                .sorted { ($0.value, $1.key) > ($1.value, $0.key) }
                .map(\.key)
            return FlowEndpoint(
                address: address,
                names: names,
                region: EndpointRegionResolver.region(forAddress: address),
                bytes: bytes[key] ?? 0,
                sessionCount: counts[key] ?? 0,
                status: statuses[key] ?? .ok
            )
        }
        .sorted { ($0.bytes, $1.address) > ($1.bytes, $0.address) }
    }

    /// Sessions in view that carry no usable typed destination address, so they
    /// appear in no row above.
    ///
    /// Reported rather than hidden: without it the address list would quietly
    /// describe fewer sessions than the surface says it is showing.
    static func omittedSessionCount(in sessions: [SessionSummary]) -> Int {
        sessions.count { Self.destination(of: $0) == nil }
    }

    // MARK: Private

    /// The typed destination address of a session, plus the exact text it was
    /// published as. `nil` when the fold supplied no typed destination or the
    /// text is not a single valid address — an unknown destination is never
    /// guessed at from the rendered endpoint.
    private static func destination(of session: SessionSummary) -> (value: IPAddressValue, text: String)? {
        guard let endpoint = session.destinationEndpointValue,
              let value = IPAddressValue(parsing: endpoint.ip) else
        {
            return nil
        }
        return (value, endpoint.ip)
    }

    private static func worse(_ lhs: SessionStatus?, _ rhs: SessionStatus) -> SessionStatus {
        guard let lhs else {
            return rhs
        }
        if lhs == .error || rhs == .error {
            return .error
        }
        if lhs == .warning || rhs == .warning {
            return .warning
        }
        return .ok
    }
}
