import Foundation

// MARK: - HistoryAutomationService

/// A pure, read-only automation boundary over an injected ``SessionStore``. It
/// exposes exactly two one-page operations — newest-first captures and
/// ordinal-ascending sessions for one explicit capture — and never opens a path,
/// reads settings, touches `@MainActor`, starts capture, controls the helper or
/// creates a listener.
///
/// Every request validates a caller page size in the exact `1...500` bound and
/// reads exactly one store page; it never clamps or internally scans multiple
/// pages. Filtering is applied only to that one examined bounded page, and the
/// result reports how many rows were examined plus an opaque typed next cursor so
/// zero matches never imply end-of-capture.
///
/// Cancellation is checked before each store read, after it returns and while
/// projecting each bounded row. Request validation and a missing capture surface
/// as typed ``AutomationError`` values; underlying ``HistoryStoreError`` and
/// `CancellationError` failures propagate unchanged to the in-process caller.
nonisolated struct HistoryAutomationService: Sendable {
    // MARK: Lifecycle

    /// Inject the store and, for deterministic tests, a cancellation predicate.
    init(store: SessionStore, isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }) {
        self.store = store
        self.isCancelled = isCancelled
    }

    // MARK: Internal

    /// Read one newest-first page of captures.
    func capturePage(_ request: AutomationCapturePageRequest) async throws -> AutomationCapturePage {
        try request.validatePageSize()
        let cursor = try request.cursor?.storageCursor()

        try checkCancellation()
        let page = try await store.captures(after: cursor, limit: request.pageSize)
        try checkCancellation()

        var values: [AutomationCaptureValue] = []
        values.reserveCapacity(page.captures.count)
        for stored in page.captures {
            try checkCancellation()
            values.append(AutomationCaptureValue(stored))
        }

        return AutomationCapturePage(
            captures: values,
            nextCursor: page.nextCursor.map { AutomationCaptureCursor($0) },
            pageSize: request.pageSize
        )
    }

    /// Read one ordinal-ascending page of a capture's sessions, filtered on that
    /// single page. A non-existent capture is a typed ``AutomationError``; an
    /// existing capture with no matching rows returns an empty page that still
    /// carries the examined count and (if the page was full) a resume cursor.
    func sessionPage(_ request: AutomationSessionPageRequest) async throws -> AutomationSessionPage {
        let filter = try request.validated()
        let cursor = try request.cursor?.storageCursor()

        try checkCancellation()
        guard try await store.capture(id: request.captureID) != nil else {
            throw AutomationError.captureNotFound(request.captureID)
        }
        try checkCancellation()

        let page = try await store.sessions(captureID: request.captureID, after: cursor, limit: request.pageSize)
        try checkCancellation()

        var matched: [AutomationSessionValue] = []
        for record in page.sessions {
            try checkCancellation()
            if filter.matches(record) {
                matched.append(AutomationSessionValue(record, disclosure: request.disclosure))
            }
        }

        return AutomationSessionPage(
            captureID: request.captureID,
            sessions: matched,
            examinedCount: page.sessions.count,
            nextCursor: page.nextCursor.map { AutomationSessionCursor($0) },
            pageSize: request.pageSize,
            disclosure: request.disclosure
        )
    }

    // MARK: Private

    private let store: SessionStore
    private let isCancelled: @Sendable () -> Bool

    private func checkCancellation() throws {
        if isCancelled() {
            throw CancellationError()
        }
    }
}
