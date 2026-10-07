import Foundation

// MARK: - ExpressionLibraryPreprocessing

/// The pure half of macro expansion before parsing, shared by the controller and
/// its tests.
nonisolated enum ExpressionLibraryPreprocessing {
    /// `expression` with its macros expanded. A macro mistake, or a parse error in
    /// the expanded text, is positioned in the text the user wrote.
    static func preprocess(
        _ expression: String,
        macros: [ExpressionMacro],
        builtIns: (any ExpressionMacroBuiltIns)? = nil
    )
        -> Result<String, InvestigationQueryDraftError>
    {
        guard ExpressionMacroExpander.mayUseMacros(expression) else {
            return .success(expression)
        }
        let expansion: ExpressionMacroExpansion
        do {
            expansion = try ExpressionMacroExpander(macros: macros, builtIns: builtIns).expand(expression)
        } catch let error as ExpressionMacroError {
            return .failure(InvestigationQueryDraftError(rowID: nil, reason: .expression(error.parseError)))
        } catch {
            return .success(expression)
        }
        guard expansion.usedMacros else {
            return .success(expression)
        }
        do {
            _ = try SessionQueryParser().parse(expansion.text)
        } catch let error as SessionQueryParseError {
            let mapped = SessionQueryParseError(
                position: expansion.originalPosition(for: error.position),
                reason: error.reason
            )
            return .failure(InvestigationQueryDraftError(rowID: nil, reason: .expression(mapped)))
        } catch {
            return .success(expansion.text)
        }
        return .success(expansion.text)
    }

    /// The expanded text when `expression` uses macros that expand; `nil` otherwise.
    static func expandedText(
        _ expression: String,
        macros: [ExpressionMacro],
        builtIns: (any ExpressionMacroBuiltIns)? = nil
    )
        -> String?
    {
        guard ExpressionMacroExpander.mayUseMacros(expression),
              let expansion = try? ExpressionMacroExpander(macros: macros, builtIns: builtIns).expand(expression),
              expansion.usedMacros else
        {
            return nil
        }
        return expansion.text
    }

    /// Whether `expression` compiles as a Session Expression with `macros`.
    static func compiles(_ expression: String, macros: [ExpressionMacro]) -> Bool {
        guard case let .success(text) = preprocess(expression, macros: macros),
              let query = try? SessionQueryParser().parse(text) else
        {
            return false
        }
        return (try? InvestigationQueryEngine().compile(query)) != nil
    }
}
