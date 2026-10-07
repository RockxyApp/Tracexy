import Foundation

// MARK: - SessionTag

/// A color label an investigator puts on a session — the Finder's set, so the
/// meaning is the user's own. It never changes what Tracexy observed.
nonisolated enum SessionTag: String, CaseIterable, Codable, Hashable, Sendable, Identifiable {
    case red
    case orange
    case yellow
    case green
    case blue
    case purple
    case gray

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .red: "Red"
        case .orange: "Orange"
        case .yellow: "Yellow"
        case .green: "Green"
        case .blue: "Blue"
        case .purple: "Purple"
        case .gray: "Gray"
        }
    }
}

// MARK: - SessionTagRecord

/// The tags on one session of one capture (the same scope notes use).
nonisolated struct SessionTagRecord: Hashable, Codable, Sendable {
    let scope: InvestigationNoteScope
    let sessionID: UUID
    var tags: [SessionTag]
}
