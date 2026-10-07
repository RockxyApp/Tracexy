import Foundation

// MARK: - QueryNumericField

/// A whole-number session measure an expression can compare and compute with.
/// "Sent" is what the session's source sent; "received" is what it got back.
nonisolated enum QueryNumericField: String, Hashable, Sendable, CaseIterable {
    case bytes
    case bytesSent = "bytes.sent"
    case bytesReceived = "bytes.received"
    case frames
    case framesSent = "frames.sent"
    case framesReceived = "frames.received"

    // MARK: Internal

    /// The measure for one session: `nil` when the session does not know it (a
    /// summary with bytes but no frame counts predates them).
    func value(of session: SessionSummary) -> Int? {
        let framesKnown = session.packetsUp + session.packetsDown > 0 || session.totalBytes == 0
        return switch self {
        case .bytes: session.bytesUp.addingReportingOverflow(session.bytesDown).overflow ? nil : session.totalBytes
        case .bytesSent: session.bytesUp
        case .bytesReceived: session.bytesDown
        case .frames: framesKnown ? session.packetsUp + session.packetsDown : nil
        case .framesSent: framesKnown ? session.packetsUp : nil
        case .framesReceived: framesKnown ? session.packetsDown : nil
        }
    }
}

// MARK: - QueryArithmeticOperator

nonisolated enum QueryArithmeticOperator: String, Hashable, Sendable {
    case add = "+"
    case subtract = "-"
    case multiply = "*"
    case divide = "/"
    case remainder = "%"

    // MARK: Internal

    /// Whole-number result; `nil` on overflow or a zero divisor. Division truncates
    /// toward zero, as a Wireshark display filter does for integer fields.
    func apply(_ lhs: Int, _ rhs: Int) -> Int? {
        switch self {
        case .add: lhs.addingReportingOverflow(rhs).overflow ? nil : lhs + rhs
        case .subtract: lhs.subtractingReportingOverflow(rhs).overflow ? nil : lhs - rhs
        case .multiply: lhs.multipliedReportingOverflow(by: rhs).overflow ? nil : lhs * rhs
        case .divide: rhs == 0 || lhs.dividedReportingOverflow(by: rhs).overflow ? nil : lhs / rhs
        case .remainder: rhs == 0 || lhs.remainderReportingOverflow(dividingBy: rhs).overflow ? nil : lhs % rhs
        }
    }
}

// MARK: - QueryArithmetic

/// The right-hand side of a numeric comparison: whole numbers, session measures and
/// the five operators, grouped with braces as in a Wireshark display filter.
nonisolated indirect enum QueryArithmetic: Hashable, Sendable {
    case number(Int)
    case field(QueryNumericField)
    case binary(QueryArithmeticOperator, QueryArithmetic, QueryArithmetic)

    // MARK: Internal

    /// Nodes in the tree, for the compiler's bound.
    var nodeCount: Int {
        switch self {
        case .number,
             .field: 1
        case let .binary(_, lhs, rhs): 1 + lhs.nodeCount + rhs.nodeCount
        }
    }

    /// The value when no session measure is involved; `nil` otherwise or when the
    /// constant overflows or divides by zero.
    var constantValue: Int? {
        switch self {
        case let .number(value): value
        case .field: nil
        case let .binary(operation, lhs, rhs):
            lhs.constantValue.flatMap { left in rhs.constantValue.flatMap { operation.apply(left, $0) } }
        }
    }

    var readsFields: Bool {
        switch self {
        case .number: false
        case .field: true
        case let .binary(_, lhs, rhs): lhs.readsFields || rhs.readsFields
        }
    }

    /// The value for one session. `unknown` when a measure is unknown; `undefined`
    /// on overflow or a zero divisor.
    func evaluate(for session: SessionSummary) -> ArithmeticOutcome {
        switch self {
        case let .number(value):
            return .value(value)
        case let .field(field):
            return field.value(of: session).map(ArithmeticOutcome.value) ?? .unknown
        case let .binary(operation, lhs, rhs):
            let left = lhs.evaluate(for: session)
            let right = rhs.evaluate(for: session)
            guard case let .value(leftValue) = left, case let .value(rightValue) = right else {
                return left == .unknown || right == .unknown ? .unknown : .undefined
            }
            return operation.apply(leftValue, rightValue).map(ArithmeticOutcome.value) ?? .undefined
        }
    }
}

// MARK: - ArithmeticOutcome

nonisolated enum ArithmeticOutcome: Hashable, Sendable {
    case value(Int)
    case unknown
    case undefined
}

// MARK: - QueryNumericComparison

/// `field (== | >= | <=) arithmetic`, for example `bytes.received >= {10 * bytes.sent}`.
nonisolated struct QueryNumericComparison: Hashable, Sendable {
    enum Relation: String, Hashable, Sendable {
        case equal = "=="
        case greaterOrEqual = ">="
        case lessOrEqual = "<="
    }

    /// The most arithmetic nodes one comparison may hold.
    static let maximumNodes = 64

    let field: QueryNumericField
    let relation: Relation
    let value: QueryArithmetic

    /// Three-valued: an unknown measure is indeterminate; an overflow or a zero
    /// divisor is no match, as a Wireshark filter treats a failed computation.
    func truth(for session: SessionSummary) -> QueryTruth {
        guard let lhs = field.value(of: session) else {
            return .indeterminate
        }
        switch value.evaluate(for: session) {
        case .unknown:
            return .indeterminate
        case .undefined:
            return .noMatch
        case let .value(rhs):
            let holds = switch relation {
            case .equal: lhs == rhs
            case .greaterOrEqual: lhs >= rhs
            case .lessOrEqual: lhs <= rhs
            }
            return holds ? .match : .noMatch
        }
    }
}
