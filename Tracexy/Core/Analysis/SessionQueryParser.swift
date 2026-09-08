import Foundation

// This file declares the bounded, pure text front end for the already-frozen typed
// investigation query engine. It is deliberately *not* a Wireshark display-filter
// interpreter: a display filter selects packets and can express packet-wise
// conjunction, direction and repeated-field semantics, none of which survive the
// projection to a session summary. This grammar therefore names its own small
// vocabulary over whole sessions and rejects packet-field spellings outright rather
// than silently reinterpreting them.
//
// The parser produces an ordinary preconstructed ``InvestigationQuery``. Every
// semantic bound — node count, depth, children per group, text length, three-valued
// finding evaluation — remains owned by ``InvestigationQueryEngine``; nothing here
// reinterprets or relaxes it. The parser only guards its own input: a UTF-8 byte
// ceiling checked before any whole-input allocation, a token ceiling, and a recursion
// ceiling checked *before* descending. Long `and`/`or` runs are gathered iteratively
// into one flat group instead of a left-nested chain.

// MARK: - SessionQueryParseError

/// A typed, positioned reason a session expression was rejected. Every case fails
/// closed: a rejected expression never yields a partial AST, a guessed field, or a
/// silently dropped term.
nonisolated struct SessionQueryParseError: Error, Hashable, Sendable {
    /// Why the expression was rejected. Name-carrying cases echo only the offending
    /// token (truncated), never the whole input.
    enum Reason: Hashable, Sendable {
        /// The input held no tokens at all.
        case emptyExpression
        /// The raw input exceeded the enforced UTF-8 byte ceiling.
        case inputTooLong(limit: Int)
        /// The token count exceeded the enforced ceiling.
        case tokenLimitExceeded(limit: Int)
        /// Parenthesis or `not` nesting exceeded the enforced recursion ceiling.
        case depthLimitExceeded(limit: Int)
        /// A scalar that cannot begin any token appeared outside a quoted string.
        case unexpectedCharacter
        /// A quoted string reached the end of the input without a closing quote.
        case unterminatedString
        /// A backslash escape other than `\"` or `\\`.
        case unsupportedEscape
        /// A control scalar appeared inside a quoted string.
        case controlCharacterInText
        /// A name that is not a protocol keyword, session field, or finding value.
        case unknownName(String)
        /// An operator this grammar deliberately does not support (`!=`, regular
        /// expressions, arithmetic, bare `=`/`<`/`>`).
        case unsupportedOperator(String)
        /// A supported operator that this particular field does not accept.
        case operatorNotSupportedForField(field: String, operatorText: String)
        /// The operand after a field/operator pair was missing or the wrong shape.
        case expectedValue
        /// A term or parenthesized group was expected at this position.
        case expectedExpression
        /// A closing parenthesis was expected at this position.
        case unbalancedParenthesis
        /// Input remained after one complete expression.
        case unexpectedTrailingInput
        /// An `ip` operand was not a standalone IPv4/IPv6 address.
        case invalidIPAddress
        /// An `ip in` operand was not a valid CIDR block.
        case invalidCIDR
        /// A port operand was not a decimal `0 ... 65535`.
        case invalidPort
        /// A `bytes` operand was not a non-negative decimal `Int`.
        case invalidByteCount
    }

    /// 1-based Unicode-scalar offset the diagnostic points at. End-of-input errors
    /// carry `scalarCount + 1`, so a position is always reportable.
    let position: Int
    let reason: Reason
}

// MARK: - SessionQueryParser

/// A pure, stateless recursive-descent parser from bounded session-expression text to
/// a preconstructed ``InvestigationQuery``. It performs no IO, retains nothing, is
/// locale-independent, uses no regular expression, and never touches the `@MainActor`.
///
/// Grammar (precedence `not` > `and` > `or`, parentheses group):
///
/// ```text
/// expression  := or
/// or          := and ( ("or" | "||") and )*
/// and         := unary ( ("and" | "&&") unary )*
/// unary       := ("not" | "!") unary | primary
/// primary     := "(" expression ")" | term
/// term        := protocolKeyword | comparison
/// comparison  := ("ip" | "source.ip" | "destination.ip") ("==" address | "in" cidr)
///              | ("port" | "source.port" | "destination.port") "==" number
///              | ("host" | "process") "contains" string
///              | "bytes" ("==" | ">=" | "<=") number
///              | "finding" "==" findingName
/// ```
nonisolated struct SessionQueryParser: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    /// Injectable input bounds. Each is clamped into `1 ... productionCeiling`, so a
    /// configuration can only *lower* a ceiling, never raise it.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxUTF8Bytes: Int = Configuration.productionMaxUTF8Bytes,
            maxTokens: Int = Configuration.productionMaxTokens,
            maxDepth: Int = Configuration.productionMaxDepth
        ) {
            self.maxUTF8Bytes = min(Self.productionMaxUTF8Bytes, max(1, maxUTF8Bytes))
            self.maxTokens = min(Self.productionMaxTokens, max(1, maxTokens))
            self.maxDepth = min(Self.productionMaxDepth, max(1, maxDepth))
        }

        // MARK: Internal

        /// The frozen production ceilings. A `Configuration` can never exceed these.
        static let productionMaxUTF8Bytes = 4_096
        static let productionMaxTokens = 256
        static let productionMaxDepth = 8

        let maxUTF8Bytes: Int
        let maxTokens: Int
        let maxDepth: Int
    }

    /// The protocol keywords this grammar accepts, deliberately lower-case and
    /// deliberately excluding outer framing (`ethernet`, `linuxCooked`) and `other`.
    static let protocolKeywords: [String: ProtocolKind] = [
        "ipv4": .ipv4,
        "ipv6": .ipv6,
        "arp": .arp,
        "icmp": .icmp,
        "icmpv6": .icmpv6,
        "tcp": .tcp,
        "udp": .udp,
        "dns": .dns,
        "tls": .tls,
        "http": .http,
        "http2": .http2,
        "quic": .quic,
        "websocket": .websocket,
        "stun": .stun,
    ]

    /// The accepted finding value names, mapped to the existing typed projection.
    static let findingNames: [String: QueryFindingKind] = [
        "reset": .reset,
        "retransmission": .retransmission,
        "overlap": .overlap,
        "outOfOrder": .outOfOrder,
        "dnsTruncation": .dnsTruncation,
    ]

    let configuration: Configuration

    /// Parse one complete session expression. Throws the first
    /// ``SessionQueryParseError`` encountered; partial input is never accepted, and
    /// the returned query is still subject to ``InvestigationQueryEngine/compile(_:)``.
    func parse(_ text: String) throws -> InvestigationQuery {
        // Guard the byte ceiling by bounded iteration, before any whole-input
        // allocation, so a pathological paste is rejected without being materialized.
        guard !exceedsUTF8Limit(text) else {
            throw SessionQueryParseError(
                position: 1,
                reason: .inputTooLong(limit: configuration.maxUTF8Bytes)
            )
        }
        let scalars = Array(text.unicodeScalars)
        let tokens = try tokenize(scalars)
        guard !tokens.isEmpty else {
            throw SessionQueryParseError(position: 1, reason: .emptyExpression)
        }
        var cursor = Cursor(tokens: tokens, endPosition: scalars.count + 1)
        let query = try parseOr(&cursor, depth: 1)
        // Complete consumption is required: a trailing term is an error, never a
        // silently dropped conjunct.
        guard cursor.index == tokens.count else {
            throw SessionQueryParseError(
                position: cursor.position,
                reason: .unexpectedTrailingInput
            )
        }
        return query
    }

    // MARK: Private

    private enum TokenKind: Hashable {
        /// An identifier, number, or address-like run of word scalars.
        case word(String)
        /// The already-unescaped contents of a quoted string.
        case text(String)
        case equal
        case greaterOrEqual
        case lessOrEqual
        case and
        case or
        case not
        case leftParen
        case rightParen
    }

    private struct Token: Hashable {
        let kind: TokenKind
        /// 1-based Unicode-scalar offset of the token's first scalar.
        let position: Int
    }

    /// A bounded read cursor over the already-tokenized input.
    private struct Cursor {
        let tokens: [Token]
        /// Position reported for an end-of-input diagnostic.
        let endPosition: Int
        var index = 0

        var current: Token? {
            index < tokens.count ? tokens[index] : nil
        }

        /// The position a diagnostic should point at right now.
        var position: Int {
            current?.position ?? endPosition
        }

        mutating func advance() {
            index += 1
        }

        mutating func match(_ kind: TokenKind) -> Bool {
            guard let current, current.kind == kind else {
                return false
            }
            index += 1
            return true
        }
    }

    /// Scalars this grammar rejects as an operator it deliberately does not offer
    /// (arithmetic, regular-expression, and shell-ish punctuation).
    private static let unsupportedOperatorScalars: Set<Unicode.Scalar> = [
        "+", "-", "*", "%", "^", "~", "?", "$", "#",
    ]

    /// Address/port fields and the endpoint scope each reads.
    private static let addressFields: [String: EndpointScope] = [
        "ip": .either,
        "source.ip": .source,
        "destination.ip": .destination,
    ]

    private static let portFields: [String: EndpointScope] = [
        "port": .either,
        "source.port": .source,
        "destination.port": .destination,
    ]

    /// A short, bounded rendering of a token for a diagnostic. Quoted text is never
    /// echoed back.
    private static func describe(_ kind: TokenKind) -> String {
        switch kind {
        case let .word(text): truncated(text)
        case .text: "text"
        case .equal: "=="
        case .greaterOrEqual: ">="
        case .lessOrEqual: "<="
        case .and: "and"
        case .or: "or"
        case .not: "not"
        case .leftParen: "("
        case .rightParen: ")"
        }
    }

    /// Bound an echoed name so a diagnostic can never reproduce a long input.
    private static func truncated(_ name: String) -> String {
        let limit = 32
        guard name.unicodeScalars.count > limit else {
            return name
        }
        return String(String.UnicodeScalarView(name.unicodeScalars.prefix(limit))) + "…"
    }

    private static func isSeparator(_ scalar: Unicode.Scalar) -> Bool {
        scalar == " " || scalar == "\t" || scalar == "\n" || scalar == "\r"
    }

    /// Word scalars: ASCII alphanumerics plus `_ . : /`, so a dotted field name, a
    /// decimal number, an IPv6 address, and a CIDR block are each one token.
    private static func isWordScalar(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        if value >= 97, value <= 122 {
            return true
        }
        if value >= 65, value <= 90 {
            return true
        }
        if value >= 48, value <= 57 {
            return true
        }
        return scalar == "_" || scalar == "." || scalar == ":" || scalar == "/"
    }

    private static func isASCIIDecimal(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
    }

    private static func wordKind(_ text: String) -> TokenKind {
        switch text {
        case "and": .and
        case "or": .or
        case "not": .not
        default: .word(text)
        }
    }

    private static func operatorError(field: String, token: Token) -> SessionQueryParseError {
        SessionQueryParseError(
            position: token.position,
            reason: .operatorNotSupportedForField(
                field: field,
                operatorText: describe(token.kind)
            )
        )
    }

    /// Count UTF-8 bytes with an early exit, so an oversized input is rejected without
    /// materializing an array of it.
    private func exceedsUTF8Limit(_ text: String) -> Bool {
        var count = 0
        for _ in text.utf8 {
            count += 1
            if count > configuration.maxUTF8Bytes {
                return true
            }
        }
        return false
    }

    // MARK: Tokenizing

    private func tokenize(_ scalars: [Unicode.Scalar]) throws -> [Token] {
        var tokens: [Token] = []
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            let position = index + 1
            guard !Self.isSeparator(scalar) else {
                index += 1
                continue
            }
            let token: Token
            if scalar == "(" {
                token = Token(kind: .leftParen, position: position)
                index += 1
            } else if scalar == ")" {
                token = Token(kind: .rightParen, position: position)
                index += 1
            } else if scalar == "\"" {
                let scanned = try scanText(scalars, from: index)
                token = Token(kind: .text(scanned.value), position: position)
                index = scanned.next
            } else if Self.isWordScalar(scalar) {
                var end = index
                while end < scalars.count, Self.isWordScalar(scalars[end]) {
                    end += 1
                }
                let text = String(String.UnicodeScalarView(scalars[index ..< end]))
                token = Token(kind: Self.wordKind(text), position: position)
                index = end
            } else {
                let scanned = try scanOperator(scalars, from: index)
                token = Token(kind: scanned.kind, position: position)
                index += scanned.width
            }
            tokens.append(token)
            guard tokens.count <= configuration.maxTokens else {
                throw SessionQueryParseError(
                    position: position,
                    reason: .tokenLimitExceeded(limit: configuration.maxTokens)
                )
            }
        }
        return tokens
    }

    /// Scan one punctuation operator. Every unsupported spelling — `!=`, a bare `=`,
    /// `<`, `>`, `&`, `|`, and arithmetic/regex punctuation — is named explicitly.
    private func scanOperator(
        _ scalars: [Unicode.Scalar],
        from index: Int
    )
        throws -> (kind: TokenKind, width: Int)
    {
        let scalar = scalars[index]
        let position = index + 1
        let next: Unicode.Scalar? = index + 1 < scalars.count ? scalars[index + 1] : nil
        switch scalar {
        case "=":
            guard next == "=" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator("="))
            }
            return (.equal, 2)
        case ">":
            guard next == "=" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator(">"))
            }
            return (.greaterOrEqual, 2)
        case "<":
            guard next == "=" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator("<"))
            }
            return (.lessOrEqual, 2)
        case "&":
            guard next == "&" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator("&"))
            }
            return (.and, 2)
        case "|":
            guard next == "|" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator("|"))
            }
            return (.or, 2)
        case "!":
            guard next != "=" else {
                throw SessionQueryParseError(position: position, reason: .unsupportedOperator("!="))
            }
            return (.not, 1)
        default:
            if Self.unsupportedOperatorScalars.contains(scalar) {
                throw SessionQueryParseError(
                    position: position,
                    reason: .unsupportedOperator(String(Character(scalar)))
                )
            }
            throw SessionQueryParseError(position: position, reason: .unexpectedCharacter)
        }
    }

    /// Scan one quoted string. Only `\"` and `\\` are escapes; any control scalar is
    /// rejected, while ordinary Unicode text is carried through for the engine's own
    /// normalization and byte ceiling to judge.
    private func scanText(
        _ scalars: [Unicode.Scalar],
        from start: Int
    )
        throws -> (value: String, next: Int)
    {
        var value = String.UnicodeScalarView()
        var index = start + 1
        while index < scalars.count {
            let scalar = scalars[index]
            if scalar == "\"" {
                return (String(value), index + 1)
            }
            if scalar == "\\" {
                let escapePosition = index + 1
                guard index + 1 < scalars.count else {
                    throw SessionQueryParseError(position: escapePosition, reason: .unsupportedEscape)
                }
                let escaped = scalars[index + 1]
                guard escaped == "\"" || escaped == "\\" else {
                    throw SessionQueryParseError(position: escapePosition, reason: .unsupportedEscape)
                }
                value.append(escaped)
                index += 2
                continue
            }
            guard !CharacterSet.controlCharacters.contains(scalar) else {
                throw SessionQueryParseError(position: index + 1, reason: .controlCharacterInText)
            }
            value.append(scalar)
            index += 1
        }
        throw SessionQueryParseError(position: start + 1, reason: .unterminatedString)
    }

    // MARK: Parsing

    /// Disjunction. A run of `or` operands is gathered iteratively into one flat
    /// `any` group, so a long expression never builds a left-nested chain.
    private func parseOr(_ cursor: inout Cursor, depth: Int) throws -> InvestigationQuery {
        let first = try parseAnd(&cursor, depth: depth)
        var operands = [first]
        while cursor.match(.or) {
            let next = try parseAnd(&cursor, depth: depth)
            operands.append(next)
        }
        return operands.count == 1 ? first : .any(operands)
    }

    /// Conjunction, gathered iteratively for the same reason as ``parseOr(_:depth:)``.
    private func parseAnd(_ cursor: inout Cursor, depth: Int) throws -> InvestigationQuery {
        let first = try parseUnary(&cursor, depth: depth)
        var operands = [first]
        while cursor.match(.and) {
            let next = try parseUnary(&cursor, depth: depth)
            operands.append(next)
        }
        return operands.count == 1 ? first : .all(operands)
    }

    /// Negation. This is the existing three-valued AST `not`: it is handed to the
    /// engine unchanged and never reinterprets indeterminate evidence.
    private func parseUnary(_ cursor: inout Cursor, depth: Int) throws -> InvestigationQuery {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedExpression)
        }
        guard token.kind == .not else {
            return try parsePrimary(&cursor, depth: depth)
        }
        guard depth < configuration.maxDepth else {
            throw SessionQueryParseError(
                position: token.position,
                reason: .depthLimitExceeded(limit: configuration.maxDepth)
            )
        }
        cursor.advance()
        let child = try parseUnary(&cursor, depth: depth + 1)
        return .not(child)
    }

    private func parsePrimary(_ cursor: inout Cursor, depth: Int) throws -> InvestigationQuery {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedExpression)
        }
        switch token.kind {
        case .leftParen:
            guard depth < configuration.maxDepth else {
                throw SessionQueryParseError(
                    position: token.position,
                    reason: .depthLimitExceeded(limit: configuration.maxDepth)
                )
            }
            cursor.advance()
            let inner = try parseOr(&cursor, depth: depth + 1)
            guard cursor.match(.rightParen) else {
                throw SessionQueryParseError(position: cursor.position, reason: .unbalancedParenthesis)
            }
            return inner
        case let .word(name):
            cursor.advance()
            let predicate = try parseTerm(name, at: token.position, cursor: &cursor)
            return .leaf(predicate)
        default:
            throw SessionQueryParseError(position: token.position, reason: .expectedExpression)
        }
    }

    /// Resolve one name to a protocol keyword or a field comparison. An unrecognized
    /// name — including a packet-field spelling such as `ip.addr`, `tcp.port`, or
    /// `http.host` — is rejected here by name rather than guessed at.
    private func parseTerm(
        _ name: String,
        at position: Int,
        cursor: inout Cursor
    )
        throws -> QueryPredicate
    {
        if let kind = Self.protocolKeywords[name] {
            return .protocolStackContains(kind)
        }
        if let scope = Self.addressFields[name] {
            return try parseAddress(name, scope: scope, cursor: &cursor)
        }
        if let scope = Self.portFields[name] {
            return try parsePort(name, scope: scope, cursor: &cursor)
        }
        switch name {
        case "host":
            return try .hostContains(parseContainsText(name, cursor: &cursor))
        case "process":
            return try .processContains(parseContainsText(name, cursor: &cursor))
        case "bytes":
            return try parseBytes(cursor: &cursor)
        case "finding":
            return try parseFinding(cursor: &cursor)
        default:
            throw SessionQueryParseError(position: position, reason: .unknownName(Self.truncated(name)))
        }
    }

    private func parseAddress(
        _ field: String,
        scope: EndpointScope,
        cursor: inout Cursor
    )
        throws -> QueryPredicate
    {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        switch token.kind {
        case .equal:
            cursor.advance()
            let operand = try consumeWord(&cursor)
            guard let address = IPAddressValue(parsing: operand.text) else {
                throw SessionQueryParseError(position: operand.position, reason: .invalidIPAddress)
            }
            return .ipEquals(address, scope: scope)
        case .word("in"):
            cursor.advance()
            let operand = try consumeWord(&cursor)
            guard let cidr = CIDRValue(parsing: operand.text) else {
                throw SessionQueryParseError(position: operand.position, reason: .invalidCIDR)
            }
            return .cidrContains(cidr, scope: scope)
        default:
            throw Self.operatorError(field: field, token: token)
        }
    }

    private func parsePort(
        _ field: String,
        scope: EndpointScope,
        cursor: inout Cursor
    )
        throws -> QueryPredicate
    {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        guard token.kind == .equal else {
            throw Self.operatorError(field: field, token: token)
        }
        cursor.advance()
        let operand = try consumeWord(&cursor)
        guard Self.isASCIIDecimal(operand.text), let port = UInt16(operand.text) else {
            throw SessionQueryParseError(position: operand.position, reason: .invalidPort)
        }
        return .portInRange(lower: port, upper: port, scope: scope)
    }

    /// `bytes` maps to the engine's closed total-byte range: `==` is a point range,
    /// `>=` is open to `Int.max`, `<=` is anchored at zero.
    private func parseBytes(cursor: inout Cursor) throws -> QueryPredicate {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        let comparison = token.kind
        switch comparison {
        case .equal,
             .greaterOrEqual,
             .lessOrEqual:
            cursor.advance()
        default:
            throw Self.operatorError(field: "bytes", token: token)
        }
        let operand = try consumeWord(&cursor)
        guard Self.isASCIIDecimal(operand.text), let value = Int(operand.text) else {
            throw SessionQueryParseError(position: operand.position, reason: .invalidByteCount)
        }
        switch comparison {
        case .greaterOrEqual: return .totalBytesInRange(lower: value, upper: Int.max)
        case .lessOrEqual: return .totalBytesInRange(lower: 0, upper: value)
        default: return .totalBytesInRange(lower: value, upper: value)
        }
    }

    private func parseFinding(cursor: inout Cursor) throws -> QueryPredicate {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        guard token.kind == .equal else {
            throw Self.operatorError(field: "finding", token: token)
        }
        cursor.advance()
        let operand = try consumeWord(&cursor)
        guard let kind = Self.findingNames[operand.text] else {
            throw SessionQueryParseError(
                position: operand.position,
                reason: .unknownName(Self.truncated(operand.text))
            )
        }
        return .findingKind(kind)
    }

    private func parseContainsText(_ field: String, cursor: inout Cursor) throws -> String {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        guard token.kind == .word("contains") else {
            throw Self.operatorError(field: field, token: token)
        }
        cursor.advance()
        guard let valueToken = cursor.current, case let .text(value) = valueToken.kind else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        cursor.advance()
        return value
    }

    private func consumeWord(_ cursor: inout Cursor) throws -> (text: String, position: Int) {
        guard let token = cursor.current, case let .word(text) = token.kind else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        cursor.advance()
        return (text, token.position)
    }
}
