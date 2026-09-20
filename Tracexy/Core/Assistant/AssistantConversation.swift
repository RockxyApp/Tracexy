import Foundation

// The bounded, in-memory conversation values.
//
// Nothing here is persisted. A conversation lives for as long as its Project and
// workspace are alive in this run and is discarded with them — prompts and
// answers are never written to disk, a defaults suite, History, or a Project
// document.

// MARK: - AssistantConversationLimits

nonisolated enum AssistantConversationLimits {
    /// The largest number of turns one conversation retains. Older turns are
    /// dropped from the front, and the drop is counted rather than hidden.
    static let maxMessages = 40
}

// MARK: - AssistantMessageRole

nonisolated enum AssistantMessageRole: String, Sendable, Equatable {
    case user
    case assistant
}

// MARK: - AssistantMessageState

/// How finished one assistant turn is. An incomplete answer is *always* labelled;
/// there is no state in which partial text is presented as a conclusion.
nonisolated enum AssistantMessageState: Sendable, Equatable {
    /// Tokens are still arriving.
    case streaming
    /// The model finished on its own terms.
    case complete
    /// The user stopped it, or a bound was reached. The retained text is real but
    /// the answer is not a conclusion.
    case incomplete(reason: String)
    /// The exchange failed. `message` is actionable copy, never a URL or body.
    case failed(message: String)

    // MARK: Internal

    var isStreaming: Bool {
        self == .streaming
    }
}

// MARK: - AssistantMessage

nonisolated struct AssistantMessage: Identifiable, Sendable, Equatable {
    // MARK: Lifecycle

    init(
        id: UUID = UUID(),
        role: AssistantMessageRole,
        text: String,
        state: AssistantMessageState
    ) {
        self.id = id
        self.role = role
        self.text = text
        self.state = state
    }

    // MARK: Internal

    let id: UUID
    let role: AssistantMessageRole
    var text: String
    var state: AssistantMessageState

    /// The citation ids this text actually references, in first-appearance order,
    /// restricted to ids the brief really carried. A model that invents an id
    /// therefore produces no clickable citation rather than a dead link.
    func citationIDs(knownIDs: Set<String>) -> [String] {
        guard role == .assistant, !knownIDs.isEmpty else {
            return []
        }
        var found: [String] = []
        var seen = Set<String>()
        // Scan for the exact `frame-<digits>` shape the brief mints, then confirm
        // membership; matching the shape alone would let a hallucinated ordinal
        // render as a real citation.
        var scanner = text[...]
        while let range = scanner.range(of: "frame-") {
            var end = range.upperBound
            while end < scanner.endIndex, scanner[end].isNumber {
                end = scanner.index(after: end)
            }
            let candidate = String(scanner[range.lowerBound ..< end])
            if knownIDs.contains(candidate), !seen.contains(candidate) {
                seen.insert(candidate)
                found.append(candidate)
            }
            scanner = scanner[end...]
        }
        return found
    }
}

// MARK: - AssistantConversation

/// One bounded conversation for one Project workspace.
nonisolated struct AssistantConversation: Sendable, Equatable {
    var messages: [AssistantMessage] = []
    /// Turns dropped from the front to honor the bound.
    private(set) var droppedMessageCount = 0

    var isEmpty: Bool {
        messages.isEmpty
    }

    /// The most recent user prompt, for Retry.
    var lastUserPrompt: String? {
        messages.last { $0.role == .user }?.text
    }

    mutating func append(_ message: AssistantMessage) {
        messages.append(message)
        while messages.count > AssistantConversationLimits.maxMessages {
            messages.removeFirst()
            droppedMessageCount += 1
        }
    }

    /// Apply an edit to one message by id. A late edit for a message that is no
    /// longer retained is a no-op rather than an append.
    mutating func update(id: UUID, transform: (inout AssistantMessage) -> Void) {
        guard let index = messages.firstIndex(where: { $0.id == id }) else {
            return
        }
        transform(&messages[index])
    }

    mutating func removeAll() {
        messages.removeAll()
        droppedMessageCount = 0
    }
}

// MARK: - AssistantConversationKey

/// Conversations are owned per Project *and* per workspace, so switching either
/// one shows that scope's own transcript instead of leaking another's.
nonisolated struct AssistantConversationKey: Hashable, Sendable {
    let projectID: UUID
    let workspaceID: UUID
}
