import Foundation

// MARK: - SessionExpressionPreprocessor

/// Rewrites Session Expression text before it is compiled. The expression library
/// holds at most one; with none installed, text is compiled exactly as typed.
///
/// A preprocessor only changes what is compiled. The text the user wrote is still
/// the draft that is accepted, shown and remembered in Recent.
@MainActor
protocol SessionExpressionPreprocessor: AnyObject {
    /// The text to compile in place of `expression`, or `expression` unchanged. A
    /// failure is reported through the ordinary expression error path, positioned
    /// in `expression`.
    func preprocess(_ expression: String) -> Result<String, InvestigationQueryDraftError>
}

// MARK: - SessionExpressionLibrary + preprocessing

extension SessionExpressionLibrary {
    /// `draft` as it should be compiled. Row drafts and libraries without a
    /// preprocessor pass through untouched.
    func compilable(_ draft: InvestigationQueryDraft) -> Result<InvestigationQueryDraft, InvestigationQueryDraftError> {
        guard draft.mode == .expression, let preprocessor else {
            return .success(draft)
        }
        return preprocessor.preprocess(draft.expression).map { text in
            var prepared = draft
            prepared.expression = text
            return prepared
        }
    }
}
