import Foundation

/// One remote address this Mac talked to, with everything the Flow surface
/// needs to place it, list it and drill into it.
///
/// The map alone could only ever answer "roughly where is my traffic
/// administered" — five markers for the whole capture. The question users
/// actually arrive with is narrower and more concrete: *which address is that,
/// and what talked to it*. That needs a row per address, not a marker per
/// region, which is why this type exists alongside the region rollup rather
/// than being derived from it.
struct FlowEndpoint: Identifiable, Hashable {
    // MARK: Internal

    /// The bare remote address, without a port. Also the identity: one row per
    /// address, however many conversations it carried.
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

    /// Builds one row per remote address from the sessions in view.
    static func endpoints(from sessions: [SessionSummary]) -> [FlowEndpoint] {
        var bytes: [String: Int] = [:]
        var counts: [String: Int] = [:]
        var statuses: [String: SessionStatus] = [:]
        var nameCounts: [String: [String: Int]] = [:]

        for session in sessions {
            let address = Self.address(from: session.destinationEndpoint)
            guard !address.isEmpty else {
                continue
            }
            bytes[address, default: 0] += session.totalBytes
            counts[address, default: 0] += 1
            statuses[address] = Self.worse(statuses[address], session.status)
            // A host equal to the address is not a resolved name — it is the
            // list falling back — so it is not recorded as one.
            if !session.host.isEmpty, session.host != address {
                nameCounts[address, default: [:]][session.host, default: 0] += 1
            }
        }

        return counts.keys.map { address in
            let names = (nameCounts[address] ?? [:])
                .sorted { ($0.value, $1.key) > ($1.value, $0.key) }
                .map(\.key)
            return FlowEndpoint(
                address: address,
                names: names,
                region: EndpointRegionResolver.region(forAddress: address),
                bytes: bytes[address] ?? 0,
                sessionCount: counts[address] ?? 0,
                status: statuses[address] ?? .ok
            )
        }
        .sorted { ($0.bytes, $1.address) > ($1.bytes, $0.address) }
    }

    // MARK: Private

    /// Strips the port. IPv6 literals carry several colons, so split from the
    /// right — the same rule `EndpointRegionResolver` uses, so a row and its
    /// marker can never disagree about which address they describe.
    private static func address(from endpoint: String) -> String {
        guard let separator = endpoint.lastIndex(of: ":") else {
            return endpoint
        }
        return String(endpoint[endpoint.startIndex ..< separator])
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
