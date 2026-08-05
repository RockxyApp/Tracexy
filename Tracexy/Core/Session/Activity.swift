import CryptoKit
import Foundation

// MARK: - ConfidenceTier

/// How strongly the evidence supports grouping sessions together.
///
/// Grouping is an *inference*, not a fact read off the wire, so it is always
/// reported with the strength of the claim behind it. A tool that guesses
/// silently is worse than one that does not guess: the user can work around a
/// visible "weak", but cannot detect a confident lie.
enum ConfidenceTier: Int, Comparable, Hashable, Sendable {
    /// Suggestive only. Never sufficient on its own to group anything.
    case weak = 0
    /// Consistent identifiers, but no observed causal step.
    case strong = 1
    /// One session directly caused the next — a DNS answer that the following
    /// connection then dialled.
    case causal = 2

    // MARK: Internal

    nonisolated var title: String {
        switch self {
        case .weak: "weak"
        case .strong: "strong"
        case .causal: "causal"
        }
    }

    nonisolated static func < (lhs: ConfidenceTier, rhs: ConfidenceTier) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

// MARK: - ActivityEvidence

/// One reason a set of sessions was grouped. Stored rather than recomputed so
/// the UI can show *why* — and so a wrong grouping can be argued with.
enum ActivityEvidence: Hashable, Sendable {
    /// A DNS answer named the address the next connection dialled.
    case dnsAnswerToConnection(name: String, address: String)
    /// The same process owned every session at connect time.
    case sameProcessAtConnect(process: String)
    /// DNS query name, TLS SNI and the connection host all agree.
    case canonicalNameMatch(name: String)
    /// Sessions began close together. Supporting evidence only.
    case temporalAdjacency(seconds: TimeInterval)

    // MARK: Internal

    nonisolated var tier: ConfidenceTier {
        switch self {
        case .dnsAnswerToConnection: .causal
        case .sameProcessAtConnect: .causal
        case .canonicalNameMatch: .strong
        // Deliberately weak: things that merely happen at the same moment are
        // not related, and on a busy interface almost everything is adjacent.
        case .temporalAdjacency: .weak
        }
    }

    nonisolated var summary: String {
        switch self {
        case let .dnsAnswerToConnection(name, address):
            "DNS answer for \(name) → connection to \(address)"
        case let .sameProcessAtConnect(process):
            "Same process at connect — \(process)"
        case let .canonicalNameMatch(name):
            "DNS, SNI and host all agree on \(name)"
        case let .temporalAdjacency(seconds):
            String(format: "Began %.1f s apart", seconds)
        }
    }
}

// MARK: - Activity

/// A set of sessions that together form one user-visible action — the DNS
/// lookup, the TCP connect to the address it returned, the TLS handshake
/// carrying that hostname, and the HTTP request over it.
///
/// This is the unit Wireshark cannot express: its engine relates packets within
/// one conversation and one protocol, and never joins conversations of different
/// protocols, so "follow one stream at a time" is a property of its data model
/// rather than of its UI.
struct Activity: Identifiable, Hashable, Sendable {
    // MARK: Lifecycle

    init(id: UUID? = nil, sessions: [SessionSummary], evidence: [ActivityEvidence], competingNames: [String] = []) {
        let ordered = sessions.sorted { $0.startTime < $1.startTime }
        self.sessions = ordered
        self.evidence = evidence
        self.competingNames = competingNames
        // A caller-supplied id wins (the coordinator recreates filtered survivor
        // activities with the original id); otherwise derive a stable one from
        // the oldest member so the same action keeps the same row across rebuilds.
        self.id = id ?? Self.identifier(anchor: ordered.first?.id)
    }

    // MARK: Internal

    let id: UUID
    /// Constituent sessions, oldest first — the order the action actually ran in.
    let sessions: [SessionSummary]
    let evidence: [ActivityEvidence]
    /// Other names that also resolved to the shared address. Non-empty means the
    /// attribution is contested, and the grouping is presented as such.
    let competingNames: [String]

    /// The strongest evidence available, capped when the address was contested.
    ///
    /// A shared CDN address is the common case where naive grouping goes wrong:
    /// two hostnames resolve to one IP, so a DNS answer no longer identifies
    /// which name a later connection belongs to. That ambiguity *lowers*
    /// confidence rather than being silently resolved in favour of the first
    /// candidate.
    var confidence: ConfidenceTier {
        let best = evidence.map(\.tier).max() ?? .weak
        return competingNames.isEmpty ? best : min(best, .weak)
    }

    var isContested: Bool {
        !competingNames.isEmpty
    }

    /// The action's name, preferring a real hostname over an address.
    var title: String {
        sessions.first { !$0.host.isEmpty && $0.host.contains(where: \.isLetter) }?.host
            ?? sessions.first?.host
            ?? "—"
    }

    var processName: String? {
        sessions.compactMap(\.processName).first
    }

    var startTime: Date {
        sessions.first?.startTime ?? .distantPast
    }

    /// Wall-clock span of the whole action, not the sum of its parts — the
    /// sessions overlap, so summing durations would overstate it.
    var duration: TimeInterval {
        guard let first = sessions.first else {
            return 0
        }
        let end = sessions.map { $0.startTime.addingTimeInterval($0.duration) }.max() ?? first.startTime
        return end.timeIntervalSince(first.startTime)
    }

    /// Worst status across the action: one failed step makes the action failed.
    var status: SessionStatus {
        if sessions.contains(where: { $0.status == .error }) {
            return .error
        }
        if sessions.contains(where: { $0.status == .warning }) {
            return .warning
        }
        return .ok
    }

    var totalBytes: Int {
        sessions.reduce(0) { $0 + $1.totalBytes }
    }

    /// Protocols in the order they were actually used, de-duplicated —
    /// `DNS → TCP → TLS → HTTP/2`.
    var protocolPath: [ProtocolKind] {
        var seen: Set<ProtocolKind> = []
        var path: [ProtocolKind] = []
        for session in sessions {
            for proto in session.protocolStack where !seen.contains(proto) {
                seen.insert(proto)
                path.append(proto)
            }
        }
        return path
    }

    // MARK: Private

    /// A stable identity derived from the oldest member rather than a fresh
    /// `UUID()`.
    ///
    /// The activity list is rebuilt on every capture tick, so a random id would
    /// hand `Table` a brand-new action row each second: disclosure and selection
    /// state would drop, and the grouped rows would churn while traffic was live.
    /// Anchoring on the oldest session keeps an action the *same* row for as long
    /// as its first step persists, and adding a later member leaves it unchanged.
    ///
    /// The `activity:` namespace is deliberate: action roots and their disclosure
    /// children share one `Table` hierarchy, so this must never collide with a
    /// child session id — hashing a namespaced anchor guarantees it cannot.
    private static func identifier(anchor: UUID?) -> UUID {
        let seed = anchor?.uuidString ?? "—"
        let digest = SHA256.hash(data: Data("activity:\(seed)".utf8))
        var bytes = Array(digest.prefix(16))
        // Stamp RFC 4122 version 4 / variant bits so this is a well-formed UUID.
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}
