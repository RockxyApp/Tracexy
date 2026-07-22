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

    var startTime: Date {
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
}
