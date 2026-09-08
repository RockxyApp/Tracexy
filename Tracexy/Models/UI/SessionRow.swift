import Foundation

/// A row in the session list: either a correlated action, or a single session.
///
/// Both cases expose the same column accessors so the table renders one set of
/// columns regardless of grouping. An action answers each column for the whole
/// action — its span, its worst status, its full protocol path — rather than
/// borrowing the values of whichever session happens to lead it.
enum SessionRow: Identifiable, Hashable {
    case action(Activity)
    case group(SessionGroup)
    case session(SessionSummary)

    // MARK: Internal

    var id: UUID {
        switch self {
        case let .action(activity): activity.id
        case let .group(group): group.id
        case let .session(session): session.id
        }
    }

    /// The session this row resolves to for selection purposes. Selecting an
    /// action selects its first session, so the inspector and the dock always
    /// have a concrete thing to describe.
    var representativeSessionID: UUID? {
        switch self {
        case let .action(activity): activity.sessions.first?.id
        case let .group(group): group.sessions.first?.id
        case let .session(session): session.id
        }
    }

    /// The row's earliest known start, or `nil` when nothing under it carries one.
    var startTime: Date? {
        switch self {
        case let .action(activity): activity.startTime
        case let .group(group): group.startTime
        case let .session(session): session.startTime
        }
    }

    var host: String {
        switch self {
        case let .action(activity): activity.title
        case let .group(group): group.title
        case let .session(session): session.host
        }
    }

    var processName: String? {
        switch self {
        case let .action(activity): activity.processName
        case let .group(group): group.kind == .process ? group.key : nil
        case let .session(session): session.processName
        }
    }

    var status: SessionStatus {
        switch self {
        case let .action(activity): activity.status
        case let .group(group): group.status
        case let .session(session): session.status
        }
    }

    var totalBytes: Int {
        switch self {
        case let .action(activity): activity.totalBytes
        case let .group(group): group.totalBytes
        case let .session(session): session.totalBytes
        }
    }

    /// Endpoints are a property of a single connection; an action spans several,
    /// so it reports an em dash rather than picking one arbitrarily.
    var sourceEndpoint: String {
        switch self {
        case .action,
             .group: "—"
        case let .session(session): session.sourceEndpoint
        }
    }

    var destinationEndpoint: String {
        switch self {
        case .action,
             .group: "—"
        case let .session(session): session.destinationEndpoint
        }
    }

    var primaryProtocol: ProtocolKind? {
        switch self {
        case let .action(activity): activity.protocolPath.first
        case let .group(group): group.protocolPath.first
        case let .session(session): session.primaryProtocol
        }
    }

    var summary: String {
        switch self {
        case let .action(activity):
            let path = activity.protocolPath.map(\.label).joined(separator: " → ")
            return "\(activity.sessions.count) sessions · \(path)"
        case let .group(group):
            let path = group.protocolPath.map(\.label).joined(separator: " · ")
            return "\(group.sessions.count) sessions · \(path)"
        case let .session(session):
            return session.infoSummary
        }
    }

    var childRows: [SessionRow] {
        switch self {
        case let .action(activity): activity.sessions.map(SessionRow.session)
        case let .group(group): group.sessions.map(SessionRow.session)
        case .session: []
        }
    }

    /// Oldest first, with rows whose start time is unknown trailing every known-time
    /// row and ordering by first source ordinal then id among themselves. This mirrors
    /// ``SessionChronology`` for the mixed row type; no sentinel date is used.
    static func orderedBefore(_ lhs: SessionRow, _ rhs: SessionRow) -> Bool {
        switch (lhs.startTime, rhs.startTime) {
        case let (left?, right?):
            if left != right {
                return left < right
            }
        case (.some, .none):
            return true
        case (.none, .some):
            return false
        case (.none, .none):
            switch (lhs.firstSourceOrdinal, rhs.firstSourceOrdinal) {
            case let (left?, right?) where left != right: return left < right
            case (.some, .none): return true
            case (.none, .some): return false
            default: break
            }
        }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    // MARK: Private

    private var firstSourceOrdinal: UInt64? {
        switch self {
        case let .session(session): session.firstCaptureOrdinal
        case let .action(activity): activity.sessions.compactMap(\.firstCaptureOrdinal).min()
        case let .group(group): group.sessions.compactMap(\.firstCaptureOrdinal).min()
        }
    }
}
