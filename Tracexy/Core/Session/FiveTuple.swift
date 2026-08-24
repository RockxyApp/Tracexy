import Foundation

// MARK: - IPEndpoint

nonisolated struct IPEndpoint: Hashable, Comparable, Sendable {
    let ip: String
    let port: UInt16

    var display: String {
        "\(ip):\(port)"
    }

    static func < (lhs: IPEndpoint, rhs: IPEndpoint) -> Bool {
        lhs.ip == rhs.ip ? lhs.port < rhs.port : lhs.ip < rhs.ip
    }
}

// MARK: - FiveTuple

nonisolated struct FiveTuple: Hashable, Sendable {
    // MARK: Lifecycle

    init(proto: ProtocolKind, source: IPEndpoint, destination: IPEndpoint) {
        self.proto = proto
        // Canonical order: smaller endpoint first, so A→B and B→A collapse.
        if source <= destination {
            a = source
            b = destination
        } else {
            a = destination
            b = source
        }
    }

    // MARK: Internal

    let proto: ProtocolKind
    let a: IPEndpoint
    let b: IPEndpoint
}
