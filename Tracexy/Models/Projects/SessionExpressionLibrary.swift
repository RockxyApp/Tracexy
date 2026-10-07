import Foundation
import Observation

// MARK: - SavedSessionExpression

/// One named session expression the investigator chose to keep.
nonisolated struct SavedSessionExpression: Hashable, Codable, Sendable, Identifiable {
    let id: UUID
    var name: String
    var expression: String
}

// MARK: - SessionExpressionLibrary

/// The active Project's recently applied and saved session expressions, written
/// through to that Project's own preference suite.
///
/// Recent expressions are recorded only when the user applies one and it compiles,
/// most recent first, without duplicates, at most ``maximumRecent``. Saved expressions
/// are named by the user, at most ``maximumSaved``; saving a name that exists replaces
/// that entry's text rather than adding a second one.
@MainActor
@Observable
final class SessionExpressionLibrary {
    // MARK: Internal

    static let maximumRecent = 12
    static let maximumSaved = 40
    static let maximumNameCharacters = 80

    private(set) var recent: [String] = []
    private(set) var saved: [SavedSessionExpression] = []
    /// Rewrites expression text before it is compiled; none by default.
    @ObservationIgnored weak var preprocessor: (any SessionExpressionPreprocessor)?

    func bind(to defaults: UserDefaults) {
        self.defaults = defaults
        recent = Array((defaults.stringArray(forKey: ProjectScopedSettingsKeys.recentSessionExpressions) ?? [])
            .prefix(Self.maximumRecent))
        let key = ProjectScopedSettingsKeys.savedSessionExpressions
        if let data = defaults.data(forKey: key) {
            if let decoded = try? JSONDecoder().decode([SavedSessionExpression].self, from: data) {
                saved = Array(decoded.prefix(Self.maximumSaved))
            } else {
                UnreadableStoredValue.preserve(data, key: key, in: defaults)
                saved = []
            }
        } else {
            saved = []
        }
    }

    /// Record an applied expression at the front of the recent list.
    func recordApplied(_ expression: String) {
        let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return
        }
        recent.removeAll { $0 == trimmed }
        recent.insert(trimmed, at: 0)
        if recent.count > Self.maximumRecent {
            recent.removeLast(recent.count - Self.maximumRecent)
        }
        defaults?.set(recent, forKey: ProjectScopedSettingsKeys.recentSessionExpressions)
    }

    /// Save `expression` under `name`. Returns `false` when the name or expression is
    /// blank, or the library is full and `name` is new.
    @discardableResult
    func save(_ expression: String, named name: String) -> Bool {
        let trimmedName = String(name.trimmingCharacters(in: .whitespacesAndNewlines)
            .prefix(Self.maximumNameCharacters))
        let trimmedExpression = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty, !trimmedExpression.isEmpty else {
            return false
        }
        if let index = saved.firstIndex(where: { $0.name.caseInsensitiveCompare(trimmedName) == .orderedSame }) {
            saved[index].expression = trimmedExpression
        } else {
            guard saved.count < Self.maximumSaved else {
                return false
            }
            saved.append(SavedSessionExpression(id: UUID(), name: trimmedName, expression: trimmedExpression))
        }
        persistSaved()
        return true
    }

    func delete(_ id: UUID) {
        saved.removeAll { $0.id == id }
        persistSaved()
    }

    func clearRecent() {
        recent = []
        defaults?.set(recent, forKey: ProjectScopedSettingsKeys.recentSessionExpressions)
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?

    private func persistSaved() {
        guard let data = try? JSONEncoder().encode(saved) else {
            return
        }
        defaults?.set(data, forKey: ProjectScopedSettingsKeys.savedSessionExpressions)
    }
}

// MARK: - SessionExpressionCompletion

/// Completion for the session-expression editor: the names that can follow what is
/// typed, filtered by the word being typed at the end of the text. It knows the same
/// vocabulary the parser accepts and nothing else, so a suggestion always parses.
nonisolated enum SessionExpressionCompletion {
    // MARK: Internal

    static let maximumSuggestions = 8

    /// Every name a term can start with.
    static var termNames: [String] {
        [
            "ip",
            "source.ip",
            "destination.ip",
            "port",
            "source.port",
            "destination.port",
            "host",
            "process",
            "bytes",
            "bytes.sent",
            "bytes.received",
            "frames",
            "frames.sent",
            "frames.received",
            "finding",
            "http.method",
            "http.status",
            "dhcp.message",
            "mac",
            "source.mac",
            "destination.mac",
            "tcp.completeness",
            "duration",
            "latency",
            "start", "tag",
            "sni",
            "dns.query",
            "dns.answer",
            "not"
        ]
            + SessionQueryParser.protocolKeywords.keys.sorted()
    }

    /// Suggestions for the word at the end of `text`, with the word they replace.
    static func suggestions(for text: String) -> (partial: String, candidates: [String]) {
        let partial = String(text.reversed().prefix { isWordCharacter($0) }.reversed())
        let before = String(text.dropLast(partial.count))
        let words = before.split { " \n\t(){},".contains($0) }.map(String.init)
        let previous = words.last
        let field = words.last { fieldNames.contains($0) }
        let insideSet = before.count { $0 == "{" } > before.count { $0 == "}" }

        let isNumeric = field.flatMap(QueryNumericField.init(rawValue:)) != nil
        let pool: [String] = if isNumeric, let previous,
                                ["==", ">=", "<=", "+", "-", "*", "/", "%"].contains(previous)
        {
            // A numeric value may read another measure (`bytes.received >= 10 * bytes.sent`).
            QueryNumericField.allCases.map(\.rawValue)
        } else if insideSet || previous == "==" {
            // Only finding values are a closed vocabulary; addresses, ports and quoted
            // text are typed freely.
            switch field {
            case "finding": SessionQueryParser.findingNames.keys.sorted()
            case "http.method": ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"]
            case "dhcp.message": ["Discover", "Offer", "Request", "ACK", "NAK", "Release", "Inform"]
            case "tag": SessionTag.allCases.map(\.rawValue)
            case "tcp.completeness": ["complete", "incomplete", "31", "47"]
            default: []
            }
        } else if let previous, ["host", "process"].contains(previous) {
            ["contains", "matches"]
        } else if let previous, ["duration", "latency"].contains(previous) {
            [">=", "<=", "in"]
        } else if previous == "start" {
            [">=", "<="]
        } else if let previous, QueryNumericField(rawValue: previous) != nil {
            ["==", ">=", "<="]
        } else if let previous, fieldNames.contains(previous) {
            ["==", "in"]
        } else if previous == nil || ["and", "or", "not", "&&", "||", "!"].contains(previous ?? "") {
            termNames
        } else {
            ["and", "or"]
        }
        let matching = pool.filter { candidate in
            partial.isEmpty || (candidate.lowercased().hasPrefix(partial.lowercased()) && candidate != partial)
        }
        return (partial, Array(matching.prefix(maximumSuggestions)))
    }

    /// `text` with its trailing partial word replaced by `candidate` and a space.
    static func applying(_ candidate: String, to text: String) -> String {
        let partial = suggestions(for: text).partial
        return String(text.dropLast(partial.count)) + candidate + " "
    }

    // MARK: Private

    private static let fieldNames: Set<String> = [
        "ip", "source.ip", "destination.ip", "port", "source.port", "destination.port",
        "host", "process", "bytes", "bytes.sent", "bytes.received", "frames", "frames.sent", "frames.received",
        "finding", "http.method", "http.status", "dhcp.message", "duration", "latency",
        "start", "tcp.completeness", "mac", "source.mac", "destination.mac",
    ]

    private static func isWordCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "." || character == "_"
    }
}

// MARK: - SessionExpressionTerm

/// Session-expression terms built from a selected session's own facts, for
/// "Investigate Sessions Like This". Every term is one the parser accepts.
nonisolated enum SessionExpressionTerm {
    // MARK: Internal

    static func sameHost(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("*"), !trimmed.contains("?") else {
            return nil
        }
        return "host matches \(quoted(trimmed))"
    }

    static func sameProcess(_ process: String?) -> String? {
        guard let process, !process.isEmpty, !process.contains("*"), !process.contains("?") else {
            return nil
        }
        return "process matches \(quoted(process))"
    }

    static func sameDestinationIP(_ endpoint: IPEndpoint?) -> String? {
        guard let endpoint, IPAddressValue(parsing: endpoint.ip) != nil else {
            return nil
        }
        return "destination.ip == \(endpoint.ip)"
    }

    static func sameDestinationPort(_ endpoint: IPEndpoint?) -> String? {
        endpoint.map { "destination.port == \($0.port)" }
    }

    static func sameProtocol(_ kind: ProtocolKind) -> String? {
        SessionQueryParser.protocolKeywords.first { $0.value == kind }?.key
    }

    /// `existing and term`, parenthesizing an existing expression that contains `or`
    /// so the new term narrows the whole of it.
    static func narrowing(_ existing: String, with term: String) -> String {
        let trimmed = existing.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return term
        }
        let needsGroup = trimmed.contains(" or ") || trimmed.contains("||")
        return needsGroup ? "(\(trimmed)) and \(term)" : "\(trimmed) and \(term)"
    }

    // MARK: Private

    private static func quoted(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
