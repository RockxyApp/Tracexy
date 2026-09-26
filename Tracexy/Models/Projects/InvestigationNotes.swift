import Foundation
import Observation

// MARK: - InvestigationNoteScope

/// Which capture a note belongs to. A session id is a hash of its five-tuple only,
/// so the same tuple in another capture has the same id; the scope is what keeps a
/// note on the capture it was written about.
///
/// A saved capture is identified by its **content** — the SHA-256 of its leading
/// 64 KiB and its size — so a note survives moving, renaming or copying the file,
/// and never attaches to a different file. A live or stopped-live capture has no
/// file yet; it gets a run identity, and saving the capture carries its notes over
/// to the file's content identity.
nonisolated struct InvestigationNoteScope: Hashable, Codable, Sendable {
    let rawValue: String

    var isLiveRun: Bool {
        rawValue.hasPrefix("live:")
    }

    /// The content identity of the capture file at `url`. Reads only the leading
    /// bytes; call it off the main actor.
    static func capture(at url: URL) throws -> InvestigationNoteScope {
        let (identity, digest) = try CaptureReference.snapshot(url)
        return InvestigationNoteScope(rawValue: "capture:\(digest):\(identity.size)")
    }

    /// A fresh identity for one live capture run.
    static func liveRun(_ id: UUID = UUID()) -> InvestigationNoteScope {
        InvestigationNoteScope(rawValue: "live:\(id.uuidString)")
    }
}

// MARK: - InvestigationNoteTarget

/// What a note is written about: a whole session, or one finding on it.
nonisolated enum InvestigationNoteTarget: Hashable, Codable, Sendable {
    case session(UUID)
    /// A finding's deterministic id (derived from its session and evidence) and its session.
    case finding(id: UUID, sessionID: UUID)

    // MARK: Internal

    var sessionID: UUID {
        switch self {
        case let .session(id): id
        case let .finding(_, sessionID): sessionID
        }
    }
}

// MARK: - InvestigationNote

/// One user-written note. Plain text the investigator typed; never generated,
/// never sent anywhere unless the investigator exports it.
nonisolated struct InvestigationNote: Hashable, Codable, Sendable {
    let scope: InvestigationNoteScope
    let target: InvestigationNoteTarget
    var text: String
    var updatedAt: Date
}

// MARK: - InvestigationNotesStore

/// The active Project's notes, written through to that Project's own preference
/// suite on every change so a quit, crash or Project switch loses nothing.
///
/// Bounds: at most ``maximumNotes`` notes per Project and ``maximumCharacters``
/// characters per note. Text beyond the character bound is cut, and a new note
/// past the count bound is refused with ``lastRefusal`` set — never silently
/// dropped, and an existing note is never evicted to make room.
@MainActor
@Observable
final class InvestigationNotesStore {
    // MARK: Lifecycle

    init(now: @escaping () -> Date = Date.init) {
        self.now = now
    }

    // MARK: Internal

    enum Refusal: Equatable {
        case noCaptureScope
        case projectFull(limit: Int)
    }

    static let maximumNotes = 500
    static let maximumCharacters = 2_000
    /// Tagged sessions kept per Project, across its captures.
    static let maximumTaggedSessions = 2_000

    /// The capture the current workspace shows, or `nil` when no capture is open
    /// (or a saved file's identity is still being read).
    var scope: InvestigationNoteScope?

    private(set) var notes: [InvestigationNote] = []
    private(set) var tagRecords: [SessionTagRecord] = []
    private(set) var lastRefusal: Refusal?

    /// The in-flight read of a capture's content identity, kept so a caller can
    /// await it rather than poll.
    @ObservationIgnored var pendingScopeTask: Task<Void, Never>?

    /// Session ids with at least one note in the current scope.
    var annotatedSessionIDs: Set<UUID> {
        guard let scope else {
            return []
        }
        return Set(notes.lazy.filter { $0.scope == scope }.map(\.target.sessionID))
    }

    /// Every tagged session of the current scope, by tag name, for the Session
    /// Expression's `tag` field.
    var currentTagNames: [UUID: Set<String>] {
        guard let scope else {
            return [:]
        }
        var names: [UUID: Set<String>] = [:]
        for record in tagRecords where record.scope == scope {
            names[record.sessionID] = Set(record.tags.map(\.rawValue))
        }
        return names
    }

    /// Whether `sessionID` has any note in the current scope.
    func hasNote(onSession sessionID: UUID) -> Bool {
        guard let scope else {
            return false
        }
        return notes.contains { $0.scope == scope && $0.target.sessionID == sessionID }
    }

    /// The tags on `sessionID` in the current scope, in palette order.
    func tags(onSession sessionID: UUID) -> [SessionTag] {
        guard let scope else {
            return []
        }
        return tagRecords.first { $0.scope == scope && $0.sessionID == sessionID }?.tags ?? []
    }

    /// Put `tag` on (or take it off) every session in `sessionIDs`, in the current scope.
    @discardableResult
    func setTag(_ tag: SessionTag, on sessionIDs: [UUID], enabled: Bool) -> Bool {
        guard let scope else {
            lastRefusal = .noCaptureScope
            return false
        }
        for sessionID in sessionIDs {
            if let index = tagRecords.firstIndex(where: { $0.scope == scope && $0.sessionID == sessionID }) {
                var tags = Set(tagRecords[index].tags)
                if enabled {
                    tags.insert(tag)
                } else {
                    tags.remove(tag)
                }
                if tags.isEmpty {
                    tagRecords.remove(at: index)
                } else {
                    tagRecords[index].tags = SessionTag.allCases.filter(tags.contains)
                }
            } else if enabled {
                guard tagRecords.count < Self.maximumTaggedSessions else {
                    lastRefusal = .projectFull(limit: Self.maximumTaggedSessions)
                    persistTags()
                    return false
                }
                tagRecords.append(SessionTagRecord(scope: scope, sessionID: sessionID, tags: [tag]))
            }
        }
        lastRefusal = nil
        persistTags()
        return true
    }

    /// Load the Project's notes from its suite and write through to it from now on.
    func bind(to defaults: UserDefaults) {
        self.defaults = defaults
        lastRefusal = nil
        if let data = defaults.data(forKey: ProjectScopedSettingsKeys.sessionTags),
           let decoded = try? JSONDecoder().decode([SessionTagRecord].self, from: data)
        {
            tagRecords = Array(decoded.prefix(Self.maximumTaggedSessions))
        } else {
            tagRecords = []
        }
        guard let data = defaults.data(forKey: ProjectScopedSettingsKeys.investigationNotes),
              let decoded = try? JSONDecoder().decode([InvestigationNote].self, from: data) else
        {
            notes = []
            return
        }
        notes = Array(decoded.prefix(Self.maximumNotes))
    }

    /// The note on `target` in `explicitScope` (default: the current scope), or an
    /// empty string.
    func text(for target: InvestigationNoteTarget, in explicitScope: InvestigationNoteScope? = nil) -> String {
        guard let scope = explicitScope ?? scope else {
            return ""
        }
        return notes.first { $0.scope == scope && $0.target == target }?.text ?? ""
    }

    /// Every note on `sessionID` (the session and its findings) in the current
    /// scope, session note first, then findings in the order written.
    func notes(onSession sessionID: UUID) -> [InvestigationNote] {
        guard let scope else {
            return []
        }
        return notes
            .filter { $0.scope == scope && $0.target.sessionID == sessionID }
            .sorted { lhs, rhs in
                if case .session = lhs.target {
                    return true
                }
                if case .session = rhs.target {
                    return false
                }
                return lhs.updatedAt < rhs.updatedAt
            }
    }

    /// Write, replace or (with blank text) delete the note on `target`, in
    /// `explicitScope` when given (an editor writing back to the capture it was
    /// opened on) or else in the current scope.
    @discardableResult
    func setText(
        _ text: String,
        for target: InvestigationNoteTarget,
        in explicitScope: InvestigationNoteScope? = nil
    )
        -> Bool
    {
        guard let scope = explicitScope ?? scope else {
            lastRefusal = .noCaptureScope
            return false
        }
        let bounded = String(text.prefix(Self.maximumCharacters))
        let isBlank = bounded.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        if let index = notes.firstIndex(where: { $0.scope == scope && $0.target == target }) {
            if isBlank {
                notes.remove(at: index)
            } else if notes[index].text != bounded {
                notes[index].text = bounded
                notes[index].updatedAt = now()
            } else {
                return true
            }
        } else {
            guard !isBlank else {
                return true
            }
            guard notes.count < Self.maximumNotes else {
                lastRefusal = .projectFull(limit: Self.maximumNotes)
                return false
            }
            notes.append(InvestigationNote(scope: scope, target: target, text: bounded, updatedAt: now()))
        }
        lastRefusal = nil
        persist()
        return true
    }

    /// Carry every note written in `source` over to `destination`, keeping any note
    /// the destination already has for the same target. Used when a live capture is
    /// saved to a file.
    func move(from source: InvestigationNoteScope, to destination: InvestigationNoteScope) {
        guard source != destination else {
            return
        }
        let existing = Set(notes.lazy.filter { $0.scope == destination }.map(\.target))
        var moved = false
        notes = notes.compactMap { note in
            guard note.scope == source else {
                return note
            }
            moved = true
            guard !existing.contains(note.target) else {
                return nil
            }
            return InvestigationNote(
                scope: destination, target: note.target, text: note.text, updatedAt: note.updatedAt
            )
        }
        if moved {
            persist()
        }
        let taggedThere = Set(tagRecords.lazy.filter { $0.scope == destination }.map(\.sessionID))
        var movedTags = false
        tagRecords = tagRecords.compactMap { record in
            guard record.scope == source else {
                return record
            }
            movedTags = true
            guard !taggedThere.contains(record.sessionID) else {
                return nil
            }
            return SessionTagRecord(scope: destination, sessionID: record.sessionID, tags: record.tags)
        }
        if movedTags {
            persistTags()
        }
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
    @ObservationIgnored private let now: () -> Date

    private func persistTags() {
        guard let defaults, let data = try? JSONEncoder().encode(tagRecords) else {
            return
        }
        defaults.set(data, forKey: ProjectScopedSettingsKeys.sessionTags)
    }

    private func persist() {
        guard let defaults, let data = try? JSONEncoder().encode(notes) else {
            return
        }
        defaults.set(data, forKey: ProjectScopedSettingsKeys.investigationNotes)
    }
}
