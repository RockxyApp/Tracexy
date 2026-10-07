import Foundation

// MARK: - Numeric comparisons

extension SessionQueryParser {
    /// `+ - * %` are tokens only so a numeric comparison can use them. Anywhere else
    /// (`port == -1`, `ip in {not-an-address}`) the first one is still reported as
    /// an unsupported operator at its own position, exactly as before.
    static func rejectStrayArithmetic(in tokens: [Token]) throws {
        for (index, token) in tokens.enumerated() {
            guard case let .arithmetic(operation) = token.kind else {
                continue
            }
            var back = index - 1
            while back >= 0, isArithmeticOperand(tokens[back].kind) {
                back -= 1
            }
            let isInValue = back >= 1
                && [.equal, .greaterOrEqual, .lessOrEqual].contains(tokens[back].kind)
                && isNumericFieldWord(tokens[back - 1].kind)
            guard isInValue else {
                throw SessionQueryParseError(
                    position: token.position,
                    reason: .unsupportedOperator(operation.rawValue)
                )
            }
        }
    }

    /// `field (== | >= | <=) arithmetic`. A value with no field in it folds to a
    /// constant: `bytes` then keeps its closed total-byte range, so existing
    /// expressions compile exactly as they did.
    func parseNumericComparison(
        _ field: QueryNumericField,
        cursor: inout Cursor,
        depth: Int
    )
        throws -> QueryPredicate
    {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        let relation: QueryNumericComparison.Relation
        switch token.kind {
        case .equal: relation = .equal
        case .greaterOrEqual: relation = .greaterOrEqual
        case .lessOrEqual: relation = .lessOrEqual
        default: throw Self.operatorError(field: field.rawValue, token: token)
        }
        cursor.advance()
        let valuePosition = cursor.position
        let value = try parseSum(field, cursor: &cursor, depth: depth)
        if field == .bytes, !value.readsFields {
            guard let bound = value.constantValue, bound >= 0 else {
                throw SessionQueryParseError(position: valuePosition, reason: .invalidByteCount)
            }
            switch relation {
            case .greaterOrEqual: return .totalBytesInRange(lower: bound, upper: Int.max)
            case .lessOrEqual: return .totalBytesInRange(lower: 0, upper: bound)
            case .equal: return .totalBytesInRange(lower: bound, upper: bound)
            }
        }
        if !value.readsFields, value.constantValue == nil {
            throw SessionQueryParseError(position: valuePosition, reason: .invalidNumber)
        }
        return .numericCompare(QueryNumericComparison(field: field, relation: relation, value: value))
    }

    // MARK: Private

    private static func isArithmeticOperand(_ kind: TokenKind) -> Bool {
        switch kind {
        case .word,
             .arithmetic,
             .leftBrace,
             .rightBrace: true
        default: false
        }
    }

    private static func isNumericFieldWord(_ kind: TokenKind) -> Bool {
        if case let .word(name) = kind {
            return QueryNumericField(rawValue: name) != nil
        }
        return false
    }

    private func parseSum(_ field: QueryNumericField, cursor: inout Cursor, depth: Int) throws -> QueryArithmetic {
        var value = try parseProduct(field, cursor: &cursor, depth: depth)
        while let token = cursor.current, case let .arithmetic(operation) = token.kind,
              operation == .add || operation == .subtract
        {
            cursor.advance()
            value = try .binary(operation, value, parseProduct(field, cursor: &cursor, depth: depth))
        }
        return value
    }

    private func parseProduct(_ field: QueryNumericField, cursor: inout Cursor, depth: Int) throws -> QueryArithmetic {
        var value = try parseFactor(field, cursor: &cursor, depth: depth)
        while let token = cursor.current {
            let operation: QueryArithmeticOperator
            switch token.kind {
            case .arithmetic(.multiply): operation = .multiply
            case .arithmetic(.remainder): operation = .remainder
            case .word("/"): operation = .divide
            default: return value
            }
            cursor.advance()
            value = try .binary(operation, value, parseFactor(field, cursor: &cursor, depth: depth))
        }
        return value
    }

    private func parseFactor(_ field: QueryNumericField, cursor: inout Cursor, depth: Int) throws -> QueryArithmetic {
        guard let token = cursor.current else {
            throw SessionQueryParseError(position: cursor.position, reason: .expectedValue)
        }
        switch token.kind {
        case .leftBrace:
            guard depth < configuration.maxDepth else {
                throw SessionQueryParseError(
                    position: token.position,
                    reason: .depthLimitExceeded(limit: configuration.maxDepth)
                )
            }
            cursor.advance()
            let inner = try parseSum(field, cursor: &cursor, depth: depth + 1)
            guard cursor.match(.rightBrace) else {
                throw SessionQueryParseError(position: cursor.position, reason: .unbalancedBrace)
            }
            return inner
        case let .word(text) where Self.isASCIIDecimal(text):
            cursor.advance()
            guard let number = Int(text) else {
                throw SessionQueryParseError(
                    position: token.position,
                    reason: field == .bytes ? .invalidByteCount : .invalidNumber
                )
            }
            return .number(number)
        case let .word(text):
            guard let operand = QueryNumericField(rawValue: text) else {
                throw SessionQueryParseError(
                    position: token.position,
                    reason: field == .bytes ? .invalidByteCount : .invalidNumber
                )
            }
            cursor.advance()
            return .field(operand)
        case let .arithmetic(operation):
            // No unary minus: every session measure is a count.
            throw SessionQueryParseError(position: token.position, reason: .unsupportedOperator(operation.rawValue))
        default:
            throw SessionQueryParseError(position: token.position, reason: .expectedValue)
        }
    }
}
