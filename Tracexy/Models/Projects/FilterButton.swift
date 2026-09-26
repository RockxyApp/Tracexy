import Foundation

// MARK: - FilterButton

/// One user-defined button that applies a Session Expression. A label written as
/// `Group//Label` puts the button in a pull-down named `Group`; more `//` nest
/// further.
nonisolated struct FilterButton: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(id: UUID = UUID(), label: String, expression: String, comment: String = "") {
        self.id = id
        self.label = label
        self.expression = expression
        self.comment = comment
    }

    // MARK: Internal

    /// Most buttons a Project stores — the storage ceiling. How many may be
    /// *added* is the injected policy's ``AppPolicy/maxFilterButtons``.
    static let maximumButtons = ProjectLimits.maximumFilterButtons
    static let maximumLabelCharacters = 80
    static let maximumCommentCharacters = 400
    static let groupSeparator = "//"

    let id: UUID
    var label: String
    var expression: String
    var comment: String

    /// The label split on `//`, empty parts dropped.
    var path: [String] {
        let parts = label.components(separatedBy: Self.groupSeparator)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return parts.isEmpty ? [label.trimmingCharacters(in: .whitespaces)] : parts
    }

    /// What the button itself shows: the last part of its label.
    var title: String {
        path.last ?? label
    }

    /// The help text: the comment, else the expression.
    var helpText: String {
        comment.isEmpty ? expression : comment
    }
}

// MARK: - FilterButtonItem

/// The bar's contents: buttons and pull-downs, in the order their first button
/// appears in the user's list.
nonisolated indirect enum FilterButtonItem: Hashable, Sendable, Identifiable {
    case button(FilterButton, title: String)
    case group(name: String, items: [FilterButtonItem])

    // MARK: Internal

    static let maximumDepth = 4

    var id: String {
        switch self {
        case let .button(button, _): button.id.uuidString
        case let .group(name, _): "group:" + name
        }
    }

    /// Groups `buttons` by their `//` paths. Paths deeper than ``maximumDepth`` keep
    /// their remaining parts joined in the button's title.
    static func build(_ buttons: [FilterButton]) -> [FilterButtonItem] {
        build(buttons.map { ($0, $0.path) }, depth: 1)
    }

    // MARK: Private

    private static func build(_ entries: [(FilterButton, [String])], depth: Int) -> [FilterButtonItem] {
        var order: [String] = []
        var groups: [String: [(FilterButton, [String])]] = [:]
        var items: [(key: String, item: FilterButtonItem?)] = []
        for (button, path) in entries {
            if path.count <= 1 || depth >= maximumDepth {
                let title = path.joined(separator: " " + FilterButton.groupSeparator + " ")
                items.append((button.id.uuidString, .button(button, title: title.isEmpty ? button.label : title)))
                continue
            }
            let name = path[0]
            if groups[name] == nil {
                order.append(name)
                items.append(("group:" + name, nil))
            }
            groups[name, default: []].append((button, Array(path.dropFirst())))
        }
        return items.map { entry in
            if let item = entry.item {
                return item
            }
            let name = String(entry.key.dropFirst("group:".count))
            return .group(name: name, items: build(groups[name] ?? [], depth: depth + 1))
        }
    }
}

// MARK: - ExpressionLibraryStore

/// Reads and writes filter buttons and macros in the active Project's own
/// preferences suite. Unreadable or malformed stored values are dropped rather
/// than trusted; the lists are bounded by the storage ceilings, never by the
/// growth limits, so an imported list longer than the limit is kept.
///
/// Whatever is dropped is not lost: the stored value is set aside once, as
/// written, under ``setAsideKey(for:)`` before the next save can replace it — a
/// newer version of the app may be able to read what this one cannot.
nonisolated enum ExpressionLibraryStore {
    // MARK: Internal

    static let buttonsKey = ProjectScopedSettingsKeys.filterButtons
    static let macrosKey = ProjectScopedSettingsKeys.expressionMacros

    static func loadButtons(from defaults: UserDefaults) -> [FilterButton] {
        guard let data = defaults.data(forKey: buttonsKey) else {
            return []
        }
        guard let decoded = try? JSONDecoder().decode([FilterButton].self, from: data) else {
            setAside(data, key: buttonsKey, in: defaults)
            return []
        }
        let kept = Array(decoded.filter { ExpressionLibraryLimits.buttonProblem($0) == nil }
            .prefix(FilterButton.maximumButtons))
        if kept.count != decoded.count {
            setAside(data, key: buttonsKey, in: defaults)
        }
        return kept
    }

    static func loadMacros(from defaults: UserDefaults) -> [ExpressionMacro] {
        guard let data = defaults.data(forKey: macrosKey) else {
            return []
        }
        guard let decoded = try? JSONDecoder().decode([ExpressionMacro].self, from: data) else {
            setAside(data, key: macrosKey, in: defaults)
            return []
        }
        var seen: Set<String> = []
        let kept = Array(decoded.filter { macro in
            ExpressionMacro.isValidName(macro.name)
                && ExpressionMacroValidation.textProblem(macro.text) == nil
                && seen.insert(macro.name).inserted
        }
        .prefix(ExpressionMacroValidation.maximumMacros))
        if kept.count != decoded.count {
            setAside(data, key: macrosKey, in: defaults)
        }
        return kept
    }

    /// Where a stored list this build could not fully read is kept.
    static func setAsideKey(for key: String) -> String {
        key + ".unreadable"
    }

    static func save(_ buttons: [FilterButton], to defaults: UserDefaults) {
        write(buttons, key: buttonsKey, to: defaults)
    }

    static func save(_ macros: [ExpressionMacro], to defaults: UserDefaults) {
        write(macros, key: macrosKey, to: defaults)
    }

    // MARK: Private

    /// Keeps the first unreadable value only: a later one is what this build
    /// already rewrote, not the original.
    private static func setAside(_ data: Data, key: String, in defaults: UserDefaults) {
        let aside = setAsideKey(for: key)
        guard defaults.object(forKey: aside) == nil else {
            return
        }
        defaults.set(data, forKey: aside)
    }

    private static func write(_ value: some Encodable, key: String, to defaults: UserDefaults) {
        guard let data = try? JSONEncoder().encode(value) else {
            return
        }
        defaults.set(data, forKey: key)
    }
}

// MARK: - ExpressionLibraryLimits

/// Shape checks every stored or imported entry passes before it is kept.
nonisolated enum ExpressionLibraryLimits {
    enum Problem: Hashable, Sendable {
        case emptyLabel
        case labelTooLong
        case emptyExpression
        case expressionTooLong
        case commentTooLong
        case controlCharacter
    }

    static let maximumExpressionUTF8Bytes = SessionQueryParser.Configuration.productionMaxUTF8Bytes

    static func buttonProblem(_ button: FilterButton) -> Problem? {
        let label = button.label.trimmingCharacters(in: .whitespaces)
        if label.isEmpty || button.path.allSatisfy(\.isEmpty) {
            return .emptyLabel
        }
        if button.label.count > FilterButton.maximumLabelCharacters {
            return .labelTooLong
        }
        if button.comment.count > FilterButton.maximumCommentCharacters {
            return .commentTooLong
        }
        if hasControlCharacter(button.label) || hasControlCharacter(button.comment) {
            return .controlCharacter
        }
        return expressionProblem(button.expression)
    }

    static func expressionProblem(_ expression: String) -> Problem? {
        if expression.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return .emptyExpression
        }
        if expression.utf8.count > maximumExpressionUTF8Bytes {
            return .expressionTooLong
        }
        // Line breaks and tabs are whitespace to the parser; nothing else is.
        if expression.unicodeScalars.contains(where: {
            $0.properties.generalCategory == .control && !["\n", "\r", "\t"].contains($0)
        }) {
            return .controlCharacter
        }
        return nil
    }

    static func hasControlCharacter(_ text: String) -> Bool {
        text.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    static func message(for problem: Problem) -> String {
        switch problem {
        case .emptyLabel:
            String(localized: "Enter a label.")
        case .labelTooLong:
            String(localized: "Keep the label within \(FilterButton.maximumLabelCharacters) characters.")
        case .emptyExpression:
            String(localized: "Enter a Session Expression.")
        case .expressionTooLong:
            String(localized: "Keep the expression within \(maximumExpressionUTF8Bytes) bytes.")
        case .commentTooLong:
            String(
                localized: "Keep the comment within \(FilterButton.maximumCommentCharacters) characters."
            )
        case .controlCharacter:
            String(localized: "Remove the control character.")
        }
    }
}
