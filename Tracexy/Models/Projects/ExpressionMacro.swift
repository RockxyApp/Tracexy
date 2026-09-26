import Foundation

// MARK: - ExpressionMacro

/// A named piece of Session Expression text. `$1` … `$9` in the text are replaced by
/// the values given where the macro is used, so `$port_or_tls(8443)` can stand for
/// `port == 8443 or tls`.
nonisolated struct ExpressionMacro: Codable, Hashable, Sendable, Identifiable {
    // MARK: Lifecycle

    init(id: UUID = UUID(), name: String, text: String) {
        self.id = id
        self.name = name
        self.text = text
    }

    // MARK: Internal

    static let maximumNameCharacters = 32
    static let maximumPlaceholder = 9

    let id: UUID
    var name: String
    var text: String

    /// How many values a use must give: the highest `$n` in the text.
    var arity: Int {
        ExpressionMacroExpander.placeholders(in: Array(text.unicodeScalars)).max() ?? 0
    }

    /// Whether `name` can be written after `$`: a letter or underscore, then
    /// letters, digits or underscores.
    static func isValidName(_ name: String) -> Bool {
        let scalars = Array(name.unicodeScalars)
        guard let first = scalars.first, !scalars.isEmpty, scalars.count <= maximumNameCharacters,
              ExpressionMacroExpander.isNameStart(first) else
        {
            return false
        }
        return scalars.allSatisfy(ExpressionMacroExpander.isNameCharacter)
    }
}

// MARK: - ExpressionMacroError

/// Why a macro use could not be expanded. `position` is the 1-based Unicode-scalar
/// offset of the use in the text the user wrote.
nonisolated struct ExpressionMacroError: Error, Hashable, Sendable {
    // MARK: Internal

    enum Kind: Hashable, Sendable {
        case unknownMacro(String)
        case wrongValueCount(name: String, expected: Int, given: Int)
        case cycle(String)
        case tooDeep
        case tooLong
        case unclosedValues(brace: Bool)
        case missingName
    }

    var position: Int
    let kind: Kind

    /// The error as the expression parser would report it, so it reaches the
    /// Session Expression editor through the path every other mistake takes.
    var parseError: SessionQueryParseError {
        let reason: SessionQueryParseError.Reason = switch kind {
        case let .unknownMacro(name):
            .unknownName("$" + name)
        case let .wrongValueCount(name, _, given):
            .operatorNotSupportedForField(field: "$" + name, operatorText: Self.valueCountText(given))
        case .cycle,
             .tooDeep:
            .depthLimitExceeded(limit: ExpressionMacroExpander.maximumDepth)
        case .tooLong:
            .inputTooLong(limit: ExpressionMacroExpander.maximumExpandedUTF8Bytes)
        case let .unclosedValues(brace):
            brace ? .unbalancedBrace : .unbalancedParenthesis
        case .missingName:
            .unexpectedCharacter
        }
        return SessionQueryParseError(position: position, reason: reason)
    }

    /// A precise account for the library's own sheets.
    var message: String {
        switch kind {
        case let .unknownMacro(name):
            String(localized: "There is no macro named $\(name).")
        case let .wrongValueCount(name, expected, _):
            if expected == 0 {
                String(localized: "$\(name) takes no values.")
            } else {
                String(localized: "$\(name) takes \(expected) values.")
            }
        case let .cycle(name):
            String(localized: "$\(name) refers back to itself.")
        case .tooDeep:
            String(
                localized: "Macros are nested more than \(ExpressionMacroExpander.maximumDepth) deep."
            )
        case .tooLong:
            String(
                localized: "The expanded expression is longer than \(ExpressionMacroExpander.maximumExpandedUTF8Bytes) bytes."
            )
        case .unclosedValues:
            String(localized: "The values of this macro have no closing bracket.")
        case .missingName:
            String(localized: "A macro name must follow $.")
        }
    }

    // MARK: Private

    private static func valueCountText(_ count: Int) -> String {
        String(localized: "\(count) values")
    }
}

// MARK: - ExpressionMacroExpansion

/// Text with every macro use replaced, and where each top-level use landed, so a
/// diagnostic about the expanded text can point back at what was typed.
nonisolated struct ExpressionMacroExpansion: Hashable, Sendable {
    struct Segment: Hashable, Sendable {
        /// 0-based scalar ranges.
        let original: Range<Int>
        let expanded: Range<Int>
    }

    let text: String
    let segments: [Segment]

    var usedMacros: Bool {
        !segments.isEmpty
    }

    /// The position in the typed text that corresponds to `position` (1-based) in
    /// the expanded text. Anything inside an expansion maps to the start of its use.
    func originalPosition(for position: Int) -> Int {
        let offset = max(0, position - 1)
        var delta = 0
        for segment in segments {
            if offset < segment.expanded.lowerBound {
                break
            }
            if offset < segment.expanded.upperBound {
                return segment.original.lowerBound + 1
            }
            delta += segment.expanded.count - segment.original.count
        }
        return max(1, offset - delta + 1)
    }
}

// MARK: - ExpressionMacroBuiltIns

/// Macros the app supplies rather than the user writes, such as GeoIP lookups.
/// A user macro with the same name wins.
nonisolated protocol ExpressionMacroBuiltIns: Sendable {
    /// `nil` when `name` isn't one of these; otherwise its expansion for `values`
    /// (trimmed, already expanded).
    func expansion(of name: String, values: [String]) -> ExpressionMacroBuiltInExpansion?
}

// MARK: - ExpressionMacroBuiltInExpansion

nonisolated enum ExpressionMacroBuiltInExpansion: Hashable, Sendable {
    /// Session Expression text; wrapped in parentheses when it is a whole expression.
    case text(String)
    case wrongValueCount(expected: Int)
}

// MARK: - ExpressionMacroExpander

/// Expands `$name`, `$name(a, b)` and `${name:a;b}` uses before a Session
/// Expression is parsed. Pure, bounded and deterministic.
///
/// - Uses inside quoted text are left alone; `$` has no other meaning in the grammar.
/// - Values are expanded first, then put in place of `$1` … `$9`; a value placed
///   inside quotes in the macro's text has `\` and `"` escaped.
/// - An expansion that is a complete expression on its own is wrapped in
///   parentheses, so `$web and dns` means what it looks like whatever `$web` holds.
/// - Nesting is limited to ``maximumDepth``, a macro that reaches itself is
///   reported as a cycle, and the result is limited to the parser's byte ceiling.
nonisolated struct ExpressionMacroExpander: Sendable {
    // MARK: Lifecycle

    init(
        macros: [ExpressionMacro],
        builtIns: (any ExpressionMacroBuiltIns)? = nil,
        parser: SessionQueryParser = SessionQueryParser()
    ) {
        var byName: [String: ExpressionMacro] = [:]
        for macro in macros where byName[macro.name] == nil {
            byName[macro.name] = macro
        }
        self.macros = byName
        self.builtIns = builtIns
        self.parser = parser
    }

    // MARK: Internal

    static let maximumDepth = 8
    static let maximumExpandedUTF8Bytes = SessionQueryParser.Configuration.productionMaxUTF8Bytes
    static let maximumUses = 256

    /// Whether `text` holds a `$` outside quoted text, i.e. may use a macro.
    static func mayUseMacros(_ text: String) -> Bool {
        var inQuote = false
        var escaped = false
        for scalar in text.unicodeScalars {
            if inQuote {
                if escaped {
                    escaped = false
                } else if scalar == "\\" {
                    escaped = true
                } else if scalar == "\"" {
                    inQuote = false
                }
            } else if scalar == "\"" {
                inQuote = true
            } else if scalar == "$" {
                return true
            }
        }
        return false
    }

    /// The macro names `text` uses outside quoted text, in order.
    static func referencedNames(in text: String) -> [String] {
        var names: [String] = []
        let scalars = Array(text.unicodeScalars)
        var index = 0
        var inQuote = false
        while index < scalars.count {
            let scalar = scalars[index]
            if inQuote {
                if scalar == "\\" {
                    index += 2
                    continue
                }
                if scalar == "\"" {
                    inQuote = false
                }
                index += 1
                continue
            }
            if scalar == "\"" {
                inQuote = true
            } else if scalar == "$" {
                var cursor = index + 1
                if cursor < scalars.count, scalars[cursor] == "{" {
                    cursor += 1
                }
                let start = cursor
                while cursor < scalars.count, isNameCharacter(scalars[cursor]) {
                    cursor += 1
                }
                if cursor > start, isNameStart(scalars[start]) {
                    names.append(String(String.UnicodeScalarView(scalars[start ..< cursor])))
                }
            }
            index += 1
        }
        return names
    }

    /// The `$n` numbers in `scalars`, inside or outside quotes.
    static func placeholders(in scalars: [Unicode.Scalar]) -> [Int] {
        var numbers: [Int] = []
        var index = 0
        while index < scalars.count {
            if scalars[index] == "$", index + 1 < scalars.count, isDigit(scalars[index + 1]) {
                var cursor = index + 1
                var value = 0
                while cursor < scalars.count, isDigit(scalars[cursor]), value < 1_000 {
                    value = value * 10 + Int(scalars[cursor].value - 48)
                    cursor += 1
                }
                numbers.append(value)
                index = cursor
            } else {
                index += 1
            }
        }
        return numbers
    }

    static func isNameStart(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "_" || (scalar.isASCII && scalar.properties.isAlphabetic)
    }

    static func isNameCharacter(_ scalar: Unicode.Scalar) -> Bool {
        isNameStart(scalar) || isDigit(scalar)
    }

    func expand(_ text: String) throws -> ExpressionMacroExpansion {
        var budget = Budget()
        var segments: [ExpressionMacroExpansion.Segment] = []
        let output = try expandLevel(
            Array(text.unicodeScalars),
            depth: 0,
            stack: [],
            budget: &budget,
            segments: &segments
        )
        return ExpressionMacroExpansion(text: String(String.UnicodeScalarView(output)), segments: segments)
    }

    // MARK: Private

    private struct Budget {
        var uses = 0
    }

    private struct Use {
        let name: String
        let values: [[Unicode.Scalar]]
        /// One past the use's last scalar.
        let end: Int
    }

    private let macros: [String: ExpressionMacro]
    private let builtIns: (any ExpressionMacroBuiltIns)?
    private let parser: SessionQueryParser

    private static func isDigit(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value >= 48 && scalar.value <= 57
    }

    private static func utf8Count(_ scalars: [Unicode.Scalar]) -> Int {
        scalars.reduce(0) { $0 + UTF8.width($1) }
    }

    private static func trimmed(_ scalars: ArraySlice<Unicode.Scalar>) -> [Unicode.Scalar] {
        var slice = scalars
        while let first = slice.first, first.properties.isWhitespace {
            slice.removeFirst()
        }
        while let last = slice.last, last.properties.isWhitespace {
            slice.removeLast()
        }
        return Array(slice)
    }

    private func expandLevel(
        _ scalars: [Unicode.Scalar],
        depth: Int,
        stack: [String],
        budget: inout Budget,
        segments: inout [ExpressionMacroExpansion.Segment]
    )
        throws -> [Unicode.Scalar]
    {
        var output: [Unicode.Scalar] = []
        output.reserveCapacity(scalars.count)
        var index = 0
        var inQuote = false
        while index < scalars.count {
            let scalar = scalars[index]
            if inQuote {
                output.append(scalar)
                if scalar == "\\", index + 1 < scalars.count {
                    output.append(scalars[index + 1])
                    index += 2
                    continue
                }
                if scalar == "\"" {
                    inQuote = false
                }
                index += 1
                continue
            }
            guard scalar == "$", index + 1 < scalars.count,
                  scalars[index + 1] == "{" || Self.isNameStart(scalars[index + 1]) else
            {
                // A lone `$` (or `$1` outside a macro) is left for the parser to reject.
                if scalar == "\"" {
                    inQuote = true
                }
                output.append(scalar)
                index += 1
                continue
            }
            let position = index + 1
            let replacement: [Unicode.Scalar]
            let use: Use
            do {
                use = try parseUse(scalars, at: index)
                replacement = try expandUse(use, depth: depth, stack: stack, budget: &budget)
            } catch let error as ExpressionMacroError {
                // Anything that goes wrong inside a use is reported at the use.
                throw ExpressionMacroError(position: position, kind: error.kind)
            }
            let start = output.count
            output.append(contentsOf: replacement)
            if depth == 0 {
                segments.append(.init(original: index ..< use.end, expanded: start ..< output.count))
            }
            guard Self.utf8Count(output) <= Self.maximumExpandedUTF8Bytes else {
                throw ExpressionMacroError(position: position, kind: .tooLong)
            }
            index = use.end
        }
        return output
    }

    private func expandUse(
        _ use: Use,
        depth: Int,
        stack: [String],
        budget: inout Budget
    )
        throws -> [Unicode.Scalar]
    {
        guard let macro = macros[use.name] else {
            return try expandBuiltIn(use, depth: depth, stack: stack, budget: &budget)
        }
        guard !stack.contains(use.name) else {
            throw ExpressionMacroError(position: 0, kind: .cycle(use.name))
        }
        guard depth < Self.maximumDepth else {
            throw ExpressionMacroError(position: 0, kind: .tooDeep)
        }
        budget.uses += 1
        guard budget.uses <= Self.maximumUses else {
            throw ExpressionMacroError(position: 0, kind: .tooLong)
        }
        let arity = macro.arity
        guard arity == use.values.count else {
            throw ExpressionMacroError(
                position: 0,
                kind: .wrongValueCount(name: use.name, expected: arity, given: use.values.count)
            )
        }
        // Values are expanded where they are written, so a value may itself use a
        // macro without that counting as the called macro reaching itself.
        var ignored: [ExpressionMacroExpansion.Segment] = []
        var values: [[Unicode.Scalar]] = []
        for value in use.values {
            try values.append(expandLevel(value, depth: depth, stack: stack, budget: &budget, segments: &ignored))
        }
        let body = substitute(Array(macro.text.unicodeScalars), values: values)
        let expanded = try expandLevel(
            body,
            depth: depth + 1,
            stack: stack + [use.name],
            budget: &budget,
            segments: &ignored
        )
        let text = String(String.UnicodeScalarView(expanded))
        if (try? parser.parse(text)) != nil {
            return ["("] + expanded + [")"]
        }
        return expanded
    }

    /// A built-in's expansion: its values are expanded where they are written, then
    /// trimmed and handed over as text.
    private func expandBuiltIn(
        _ use: Use,
        depth: Int,
        stack: [String],
        budget: inout Budget
    )
        throws -> [Unicode.Scalar]
    {
        var ignored: [ExpressionMacroExpansion.Segment] = []
        var values: [String] = []
        if builtIns != nil {
            for value in use.values {
                let expanded = try expandLevel(value, depth: depth, stack: stack, budget: &budget, segments: &ignored)
                values.append(String(String.UnicodeScalarView(Self.trimmed(expanded[...]))))
            }
        }
        guard let expansion = builtIns?.expansion(of: use.name, values: values) else {
            throw ExpressionMacroError(position: 0, kind: .unknownMacro(use.name))
        }
        budget.uses += 1
        guard budget.uses <= Self.maximumUses else {
            throw ExpressionMacroError(position: 0, kind: .tooLong)
        }
        switch expansion {
        case let .wrongValueCount(expected):
            throw ExpressionMacroError(
                position: 0,
                kind: .wrongValueCount(name: use.name, expected: expected, given: use.values.count)
            )
        case let .text(text):
            let scalars = Array(text.unicodeScalars)
            guard Self.utf8Count(scalars) <= Self.maximumExpandedUTF8Bytes else {
                throw ExpressionMacroError(position: 0, kind: .tooLong)
            }
            if (try? parser.parse(text)) != nil {
                return ["("] + scalars + [")"]
            }
            return scalars
        }
    }

    /// `body` with `$n` replaced by the n-th value; escaped when inside quotes.
    private func substitute(_ body: [Unicode.Scalar], values: [[Unicode.Scalar]]) -> [Unicode.Scalar] {
        var output: [Unicode.Scalar] = []
        var index = 0
        var inQuote = false
        while index < body.count {
            let scalar = body[index]
            if scalar == "$", index + 1 < body.count, Self.isDigit(body[index + 1]) {
                var cursor = index + 1
                var number = 0
                while cursor < body.count, Self.isDigit(body[cursor]), number < 1_000 {
                    number = number * 10 + Int(body[cursor].value - 48)
                    cursor += 1
                }
                let value = number >= 1 && number <= values.count ? values[number - 1] : []
                if inQuote {
                    for character in value {
                        if character == "\\" || character == "\"" {
                            output.append("\\")
                        }
                        output.append(character)
                    }
                } else {
                    output.append(contentsOf: value)
                }
                index = cursor
                continue
            }
            if inQuote, scalar == "\\", index + 1 < body.count {
                output.append(scalar)
                output.append(body[index + 1])
                index += 2
                continue
            }
            if scalar == "\"" {
                inQuote.toggle()
            }
            output.append(scalar)
            index += 1
        }
        return output
    }

    /// Reads one use starting at the `$` at `start`.
    private func parseUse(_ scalars: [Unicode.Scalar], at start: Int) throws -> Use {
        var cursor = start + 1
        let braced = scalars[cursor] == "{"
        if braced {
            cursor += 1
        }
        let nameStart = cursor
        while cursor < scalars.count, Self.isNameCharacter(scalars[cursor]) {
            cursor += 1
        }
        guard cursor > nameStart, Self.isNameStart(scalars[nameStart]) else {
            throw ExpressionMacroError(position: 0, kind: .missingName)
        }
        let name = String(String.UnicodeScalarView(scalars[nameStart ..< cursor]))
        if braced {
            // ${name} or ${name:a;b}
            guard cursor < scalars.count else {
                throw ExpressionMacroError(position: 0, kind: .unclosedValues(brace: true))
            }
            if scalars[cursor] == "}" {
                return Use(name: name, values: [], end: cursor + 1)
            }
            guard scalars[cursor] == ":" else {
                throw ExpressionMacroError(position: 0, kind: .missingName)
            }
            let (values, end) = try readValues(scalars, from: cursor + 1, closing: "}", separator: ";")
            return Use(name: name, values: values, end: end)
        }
        guard cursor < scalars.count, scalars[cursor] == "(" else {
            return Use(name: name, values: [], end: cursor)
        }
        let (values, end) = try readValues(scalars, from: cursor + 1, closing: ")", separator: ",")
        return Use(name: name, values: values, end: end)
    }

    /// Values up to the matching `closing`, split on `separator` outside nested
    /// brackets and quotes. An empty list (`()`) gives no values.
    private func readValues(
        _ scalars: [Unicode.Scalar],
        from start: Int,
        closing: Unicode.Scalar,
        separator: Unicode.Scalar
    )
        throws -> ([[Unicode.Scalar]], Int)
    {
        var values: [[Unicode.Scalar]] = []
        var valueStart = start
        var nesting = 0
        var inQuote = false
        var index = start
        while index < scalars.count {
            let scalar = scalars[index]
            if inQuote {
                if scalar == "\\" {
                    index += 2
                    continue
                }
                if scalar == "\"" {
                    inQuote = false
                }
                index += 1
                continue
            }
            switch scalar {
            case "\"":
                inQuote = true
            case "(",
                 "{":
                nesting += 1
            case ")",
                 "}":
                if nesting == 0, scalar == closing {
                    let last = Self.trimmed(scalars[valueStart ..< index])
                    if !(values.isEmpty && last.isEmpty) {
                        values.append(last)
                    }
                    return (values, index + 1)
                }
                nesting = max(0, nesting - 1)
            default:
                if nesting == 0, scalar == separator {
                    values.append(Self.trimmed(scalars[valueStart ..< index]))
                    valueStart = index + 1
                }
            }
            index += 1
        }
        throw ExpressionMacroError(position: 0, kind: .unclosedValues(brace: closing == "}"))
    }
}

// MARK: - ExpressionMacroValidation

/// Checks a set of macro definitions before it is kept.
nonisolated enum ExpressionMacroValidation {
    enum Problem: Hashable, Sendable {
        case invalidName
        case duplicateName
        case emptyText
        case textTooLong
        case controlCharacter
        case tooManyValues
        case cycle
    }

    static let maximumTextUTF8Bytes = 1_024
    /// Most macros a Project stores — the storage ceiling. How many may be
    /// *added* is the injected policy's ``AppPolicy/maxExpressionMacros``.
    static let maximumMacros = ProjectLimits.maximumExpressionMacros

    /// Problems by macro ID; a valid set yields an empty dictionary.
    static func problems(in macros: [ExpressionMacro]) -> [UUID: Problem] {
        var problems: [UUID: Problem] = [:]
        var seen: Set<String> = []
        for macro in macros {
            if !ExpressionMacro.isValidName(macro.name) {
                problems[macro.id] = .invalidName
            } else if !seen.insert(macro.name).inserted {
                problems[macro.id] = .duplicateName
            } else if let problem = textProblem(macro.text) {
                problems[macro.id] = problem
            }
        }
        for id in macrosInCycles(macros) where problems[id] == nil {
            problems[id] = .cycle
        }
        return problems
    }

    static func textProblem(_ text: String) -> Problem? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            return .emptyText
        }
        if text.utf8.count > maximumTextUTF8Bytes {
            return .textTooLong
        }
        if text.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            return .controlCharacter
        }
        if ExpressionMacroExpander.placeholders(in: Array(text.unicodeScalars)).contains(where: {
            $0 < 1 || $0 > ExpressionMacro.maximumPlaceholder
        }) {
            return .tooManyValues
        }
        return nil
    }

    /// Macros that can reach themselves through the macros their text uses.
    static func macrosInCycles(_ macros: [ExpressionMacro]) -> Set<UUID> {
        var byName: [String: ExpressionMacro] = [:]
        for macro in macros where byName[macro.name] == nil {
            byName[macro.name] = macro
        }
        let edges = byName.mapValues { Set(ExpressionMacroExpander.referencedNames(in: $0.text)) }
        var result: Set<UUID> = []
        for (name, macro) in byName {
            // Bounded walk: at most every macro once.
            var visited: Set<String> = []
            var pending = Array(edges[name] ?? [])
            while let next = pending.popLast() {
                if next == name {
                    result.insert(macro.id)
                    break
                }
                guard visited.insert(next).inserted else {
                    continue
                }
                pending.append(contentsOf: edges[next] ?? [])
            }
        }
        return result
    }

    static func message(for problem: Problem) -> String {
        switch problem {
        case .invalidName:
            String(
                localized: "Name a macro with letters, digits and underscores, starting with a letter or underscore."
            )
        case .duplicateName:
            String(localized: "Another macro already has this name.")
        case .emptyText:
            String(localized: "Enter the expression this macro stands for.")
        case .textTooLong:
            String(localized: "Keep a macro within \(maximumTextUTF8Bytes) bytes.")
        case .controlCharacter:
            String(localized: "Remove the control character from this macro.")
        case .tooManyValues:
            String(localized: "Use $1 to $9 for the values a macro takes.")
        case .cycle:
            String(localized: "This macro uses itself, directly or through another macro.")
        }
    }
}
