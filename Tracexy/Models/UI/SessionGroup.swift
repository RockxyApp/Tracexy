import CryptoKit
import Foundation

/// Sessions gathered by an attribute that was **observed**, not inferred.
///
/// Deliberately a different type from `Activity`. An action is a claim — that
/// four conversations served one intent — so it carries evidence and a
/// confidence tier and can be argued with. "Same host" and "same process" are
/// facts read straight off the session, so they carry neither: presenting them
/// through `Activity` would attach a confidence to something that was never
/// uncertain, and teach the user to discount the tier where it does matter.
struct SessionGroup: Identifiable, Hashable {
    // MARK: Lifecycle

    init(kind: Kind, key: String, sessions: [SessionSummary]) {
        self.kind = kind
        self.key = key
        self.sessions = sessions.sorted { $0.startTime < $1.startTime }
        id = Self.identifier(kind: kind, key: key)
    }

    // MARK: Internal

    /// Which observed attribute gathered these sessions.
    enum Kind: String, Hashable {
        case host
        case process
    }

    let id: UUID
    let kind: Kind
    /// The attribute's value — the hostname, or the process name.
    let key: String
    /// Members, oldest first.
    let sessions: [SessionSummary]

    var title: String {
        key
    }

    var startTime: Date {
        sessions.first?.startTime ?? .distantPast
    }

    /// Worst status across the group: one failed member makes the group failed.
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

    /// Protocols used across the group, in first-seen order, de-duplicated.
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

    /// A stable identity derived from the grouping attribute rather than a fresh
    /// `UUID()`.
    ///
    /// The row list is recomputed on every capture tick, so a random id would
    /// hand `NSTableView` a brand-new row each second: selection and disclosure
    /// state would drop, and the list would flicker while traffic was live.
    /// Hashing the attribute keeps a group the *same* row for as long as it
    /// means the same thing.
    private static func identifier(kind: Kind, key: String) -> UUID {
        let digest = SHA256.hash(data: Data("\(kind.rawValue):\(key)".utf8))
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
