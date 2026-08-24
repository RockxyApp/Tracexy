import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryAutomationServiceTests

@Suite("History automation service: bounds, cursors, filtering, disclosure and cancellation")
struct HistoryAutomationServiceTests {
    // MARK: Internal

    // MARK: Internal — capture page bounds and ordering

    @Test("A page size outside 1...500 is a typed error and never touches the store")
    func capturePageSizeBounds() async throws {
        let service = try HistoryAutomationService(store: SessionStore())
        await #expect(throws: AutomationError.invalidPageSize(0)) {
            _ = try await service.capturePage(.init(pageSize: 0))
        }
        await #expect(throws: AutomationError.invalidPageSize(501)) {
            _ = try await service.capturePage(.init(pageSize: 501))
        }
        // The exact bounds are accepted.
        _ = try await service.capturePage(.init(pageSize: 1))
        _ = try await service.capturePage(.init(pageSize: HistoryLimits.maxReadPageSize))
    }

    @Test("The session page enforces the same 1...500 bound before touching the store")
    func sessionPageSizeBounds() async throws {
        let service = try HistoryAutomationService(store: SessionStore())
        // The page bound is validated ahead of capture existence, so a bogus ID
        // still surfaces the size error rather than a not-found error.
        await #expect(throws: AutomationError.invalidPageSize(0)) {
            _ = try await service.sessionPage(.init(captureID: UUID(), pageSize: 0))
        }
        await #expect(throws: AutomationError.invalidPageSize(501)) {
            _ = try await service.sessionPage(.init(captureID: UUID(), pageSize: 501))
        }
    }

    @Test("Captures page newest-first and the cursor round-trips across pages")
    func capturePagingNewestFirst() async throws {
        let store = try SessionStore()
        // endedAt ascending on insert; newest-first read must reverse it.
        let ids = try await Self.seedCaptures(store, endedAt: [1_000, 1_001, 1_002, 1_003, 1_004])
        let service = HistoryAutomationService(store: store)

        var collected: [UUID] = []
        var cursor: AutomationCaptureCursor?
        while true {
            let page = try await service.capturePage(.init(pageSize: 2, cursor: cursor))
            collected.append(contentsOf: page.captures.map(\.captureID))
            guard let next = page.nextCursor else {
                break
            }
            // Round-trip the opaque cursor through JSON to prove it is portable.
            let data = try JSONEncoder().encode(next)
            cursor = try JSONDecoder().decode(AutomationCaptureCursor.self, from: data)
        }
        #expect(collected == ids.reversed())
    }

    // MARK: Internal — session page ordering and cursors

    @Test("Sessions page in stable store ordinal order, never resorted by start time")
    func sessionStableOrdering() async throws {
        let store = try SessionStore()
        // Insert with descending start times; ordinal (insert) order must win.
        let sessions = [
            Self.session(startTime: 5_000),
            Self.session(startTime: 1_000),
            Self.session(startTime: 3_000),
        ]
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: sessions)
        let service = HistoryAutomationService(store: store)

        let page = try await service.sessionPage(.init(captureID: capture.captureID, pageSize: 500))
        #expect(page.sessions.map(\.sessionID) == sessions.map(\.sessionID))
    }

    @Test("Session cursor round-trips and continues paging")
    func sessionCursorRoundTrip() async throws {
        let store = try SessionStore()
        let sessions = (0 ..< 5).map { _ in Self.session() }
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: sessions)
        let service = HistoryAutomationService(store: store)

        var collected: [UUID] = []
        var cursor: AutomationSessionCursor?
        while true {
            let page = try await service.sessionPage(.init(captureID: capture.captureID, pageSize: 2, cursor: cursor))
            collected.append(contentsOf: page.sessions.map(\.sessionID))
            guard let next = page.nextCursor else {
                break
            }
            let data = try JSONEncoder().encode(next)
            cursor = try JSONDecoder().decode(AutomationSessionCursor.self, from: data)
        }
        #expect(collected == sessions.map(\.sessionID))
    }

    // MARK: Internal — one-page-only filtering and continuation

    @Test("Filtering examines exactly one page; zero matches still report count and a resume cursor")
    func onePageFilteringWithContinuation() async throws {
        let store = try SessionStore()
        // Five hosts, none matching the filter; a full page means the store still
        // returns a resume cursor even though no rows matched.
        let sessions = (0 ..< 5).map { index in Self.session(host: "keep-\(index).example.com") }
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: sessions)
        let service = HistoryAutomationService(store: store)

        let page = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 5,
            filter: .init(hostSubstring: "no-such-host"),
            disclosure: .init(includesHost: true)
        ))
        #expect(page.sessions.isEmpty)
        #expect(page.examinedCount == 5)
        #expect(page.nextCursor == AutomationSessionCursor(ordinal: 4))
    }

    @Test("An AND filter matches only rows satisfying every predicate, case-folded")
    func andFilterMatches() async throws {
        let store = try SessionStore()
        let target = Self.session(
            processName: "Curl",
            host: "API.Example.com",
            protocols: ["tcp", "tls"],
            status: .warning,
            bytesUp: 100,
            bytesDown: 200
        )
        let sessions = [
            target,
            Self.session(processName: "curl", host: "other.example.com", status: .warning),
            Self.session(processName: "wget", host: "api.example.com", status: .warning),
        ]
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: sessions)
        let service = HistoryAutomationService(store: store)

        let page = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 500,
            filter: .init(
                processSubstring: "curl",
                hostSubstring: "api.example",
                protocolEquals: "TLS",
                status: .warning,
                totalBytesAtLeast: 300,
                totalBytesAtMost: 300
            ),
            disclosure: .init(includesProcess: true, includesHost: true)
        ))
        #expect(page.sessions.map(\.sessionID) == [target.sessionID])
        #expect(page.examinedCount == 3)
    }

    // MARK: Internal — filter validation errors

    @Test("Empty, oversized and control-containing operands are rejected")
    func operandValidation() async throws {
        let service = try HistoryAutomationService(store: SessionStore())
        let id = UUID()

        await #expect(throws: AutomationError.emptyFilterOperand(field: .host)) {
            _ = try await service.sessionPage(.init(
                captureID: id,
                pageSize: 10,
                filter: .init(hostSubstring: "   "),
                disclosure: .init(includesHost: true)
            ))
        }
        let long = String(repeating: "a", count: AutomationText.maxOperandUTF8Bytes + 1)
        await #expect(throws: AutomationError.filterOperandTooLong(field: .host, byteCount: long.utf8.count)) {
            _ = try await service.sessionPage(.init(
                captureID: id,
                pageSize: 10,
                filter: .init(hostSubstring: long),
                disclosure: .init(includesHost: true)
            ))
        }
        await #expect(throws: AutomationError.filterOperandContainsControlCharacter(field: .host)) {
            _ = try await service.sessionPage(.init(
                captureID: id,
                pageSize: 10,
                filter: .init(hostSubstring: "a\u{0007}b"),
                disclosure: .init(includesHost: true)
            ))
        }
    }

    @Test("Non-finite and out-of-order numeric bounds are rejected")
    func numericBoundValidation() async throws {
        let service = try HistoryAutomationService(store: SessionStore())
        let id = UUID()

        await #expect(throws: AutomationError.nonFiniteFilterBound(field: .startTime)) {
            _ = try await service.sessionPage(.init(captureID: id, pageSize: 10, filter: .init(startTimeAtLeast: .nan)))
        }
        await #expect(throws: AutomationError.filterBoundsOutOfOrder(field: .startTime)) {
            _ = try await service.sessionPage(.init(
                captureID: id,
                pageSize: 10,
                filter: .init(startTimeAtLeast: 10, startTimeAtMost: 5)
            ))
        }
        await #expect(throws: AutomationError.negativeByteBound(field: .totalBytes)) {
            _ = try await service.sessionPage(.init(captureID: id, pageSize: 10, filter: .init(totalBytesAtLeast: -1)))
        }
        await #expect(throws: AutomationError.filterBoundsOutOfOrder(field: .totalBytes)) {
            _ = try await service.sessionPage(.init(
                captureID: id,
                pageSize: 10,
                filter: .init(totalBytesAtLeast: 10, totalBytesAtMost: 5)
            ))
        }
    }

    @Test("Total-byte filtering is overflow-safe and saturates to Int64.max")
    func overflowSafeByteTotals() async throws {
        let store = try SessionStore()
        let target = Self.session(bytesUp: Int64.max, bytesDown: 10)
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [target, Self.session(bytesUp: 1, bytesDown: 1)])
        let service = HistoryAutomationService(store: store)

        // The saturated total (Int64.max) satisfies an at-least bound of Int64.max
        // without trapping on the overflowing addition.
        let page = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 500,
            filter: .init(totalBytesAtLeast: Int64.max)
        ))
        #expect(page.sessions.map(\.sessionID) == [target.sessionID])
    }

    // MARK: Internal — disclosure

    @Test("Minimum disclosure omits process, host and both endpoints by construction")
    func minimumDisclosureOmitsSensitiveFields() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])
        let service = HistoryAutomationService(store: store)

        let page = try await service.sessionPage(.init(captureID: capture.captureID, pageSize: 10))
        let value = try #require(page.sessions.first)
        #expect(value.processName == nil)
        #expect(value.host == nil)
        #expect(value.sourceEndpoint == nil)
        #expect(value.destinationEndpoint == nil)
        // Non-sensitive fields are always present.
        #expect(value.protocols == ["tcp", "tls"])
        #expect(value.status == .ok)
    }

    @Test("Each disclosure family independently exposes only its own stored values")
    func disclosureOptIns() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session(
            processName: "curl",
            host: "example.com",
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: "93.184.216.34:443"
        )])
        let service = HistoryAutomationService(store: store)

        let processOnly = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 10,
            disclosure: .init(includesProcess: true)
        )).sessions.first
        #expect(processOnly?.processName == "curl")
        #expect(processOnly?.host == nil)
        #expect(processOnly?.sourceEndpoint == nil)

        let hostOnly = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 10,
            disclosure: .init(includesHost: true)
        )).sessions.first
        #expect(hostOnly?.host == "example.com")
        #expect(hostOnly?.processName == nil)
        #expect(hostOnly?.destinationEndpoint == nil)

        let endpointsOnly = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 10,
            disclosure: .init(includesEndpoints: true)
        )).sessions.first
        #expect(endpointsOnly?.sourceEndpoint == "10.0.0.1:5000")
        #expect(endpointsOnly?.destinationEndpoint == "93.184.216.34:443")
        #expect(endpointsOnly?.processName == nil)
        #expect(endpointsOnly?.host == nil)
    }

    @Test("A disclosed but stored-nil process stays nil")
    func disclosedNilProcessStaysNil() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session(processName: nil)])
        let service = HistoryAutomationService(store: store)

        let value = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 10,
            disclosure: .init(includesProcess: true)
        )).sessions.first
        #expect(value?.processName == nil)
    }

    // MARK: Internal — disclosure oracle

    @Test("Process/host filtering without the matching disclosure is rejected")
    func filterOracleRejection() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])
        let service = HistoryAutomationService(store: store)

        await #expect(throws: AutomationError.filterRequiresDisclosure(field: .process)) {
            _ = try await service.sessionPage(.init(
                captureID: capture.captureID,
                pageSize: 10,
                filter: .init(processSubstring: "curl"),
                disclosure: .minimum
            ))
        }
        await #expect(throws: AutomationError.filterRequiresDisclosure(field: .host)) {
            _ = try await service.sessionPage(.init(
                captureID: capture.captureID,
                pageSize: 10,
                filter: .init(hostSubstring: "example"),
                disclosure: .minimum
            ))
        }
        // Protocol/status/time/byte predicates carry no oracle and need no disclosure.
        _ = try await service.sessionPage(.init(
            captureID: capture.captureID,
            pageSize: 10,
            filter: .init(protocolEquals: "tls", status: .ok, startTimeAtLeast: 0, totalBytesAtLeast: 0),
            disclosure: .minimum
        ))
    }

    // MARK: Internal — capture existence and cursors

    @Test("A missing capture is a typed error; an existing empty capture returns an empty page")
    func missingVersusEmptyCapture() async throws {
        let store = try SessionStore()
        let service = HistoryAutomationService(store: store)
        let missing = UUID()
        await #expect(throws: AutomationError.captureNotFound(missing)) {
            _ = try await service.sessionPage(.init(captureID: missing, pageSize: 10))
        }

        let empty = Self.capture()
        try await store.replaceCapture(empty, sessions: [])
        let page = try await service.sessionPage(.init(captureID: empty.captureID, pageSize: 10))
        #expect(page.sessions.isEmpty)
        #expect(page.examinedCount == 0)
        #expect(page.nextCursor == nil)
    }

    @Test("Invalid cursors are rejected before any store read")
    func invalidCursorsRejected() async throws {
        let service = try HistoryAutomationService(store: SessionStore())
        await #expect(throws: AutomationError.invalidCursor(field: "ordinal")) {
            _ = try await service.sessionPage(.init(captureID: UUID(), pageSize: 10, cursor: .init(ordinal: -1)))
        }
        await #expect(throws: AutomationError.invalidCursor(field: "endedAt")) {
            _ = try await service.capturePage(.init(pageSize: 10, cursor: .init(endedAt: .infinity, captureID: UUID())))
        }
    }

    // MARK: Internal — cancellation boundaries

    @Test("Cancellation is honored before the store read")
    func cancellationBeforeRead() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session()])
        let gate = CountingCancel(cancelAt: 1)
        let service = HistoryAutomationService(store: store, isCancelled: { gate.shouldCancel() })

        await #expect(throws: CancellationError.self) {
            _ = try await service.capturePage(.init(pageSize: 10))
        }
    }

    @Test("Cancellation is honored while projecting a bounded row")
    func cancellationDuringProjection() async throws {
        let store = try SessionStore()
        let capture = Self.capture()
        try await store.replaceCapture(capture, sessions: [Self.session(), Self.session()])
        // Order of checks: before capture read (1), after (2), after sessions read
        // (3), then once per examined row (4, 5). Cancelling on call 4 lands inside
        // per-row projection.
        let gate = CountingCancel(cancelAt: 4)
        let service = HistoryAutomationService(store: store, isCancelled: { gate.shouldCancel() })

        await #expect(throws: CancellationError.self) {
            _ = try await service.sessionPage(.init(captureID: capture.captureID, pageSize: 10))
        }
    }

    // MARK: Private

    // MARK: Private — fixtures

    private static func capture(
        captureID: UUID = UUID(),
        startedAt: Double = 1_000,
        endedAt: Double = 2_000,
        sourceKind: HistorySourceKind = .live,
        completeness: HistoryCompleteness = .complete
    )
        -> HistoryCaptureRecord
    {
        HistoryCaptureRecord(
            captureID: captureID,
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: sourceKind,
            completeness: completeness
        )
    }

    private static func session(
        sessionID: UUID = UUID(),
        startTime: Double = 1_000,
        duration: Double = 5,
        processName: String? = "curl",
        host: String = "example.com",
        sourceEndpoint: String = "10.0.0.1:5000",
        destinationEndpoint: String = "93.184.216.34:443",
        protocols: [String] = ["tcp", "tls"],
        status: HistorySessionStatus = .ok,
        latencyMilliseconds: Double? = 12.5,
        bytesUp: Int64 = 100,
        bytesDown: Int64 = 200
    )
        -> HistorySessionRecord
    {
        HistorySessionRecord(
            sessionID: sessionID,
            startTime: startTime,
            duration: duration,
            processName: processName,
            host: host,
            sourceEndpoint: sourceEndpoint,
            destinationEndpoint: destinationEndpoint,
            protocols: protocols,
            status: status,
            latencyMilliseconds: latencyMilliseconds,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
    }

    private static func seedCaptures(_ store: SessionStore, endedAt: [Double]) async throws -> [UUID] {
        var ids: [UUID] = []
        for value in endedAt {
            let record = capture(startedAt: value - 1, endedAt: value)
            try await store.replaceCapture(record, sessions: [session()])
            ids.append(record.captureID)
        }
        return ids
    }
}

// MARK: - CountingCancel

/// A thread-safe cancellation predicate that reports cancelled on and after its
/// `cancelAt`-th invocation, making a specific service cancellation boundary
/// deterministic.
private final class CountingCancel: @unchecked Sendable {
    // MARK: Lifecycle

    init(cancelAt: Int) {
        self.cancelAt = cancelAt
    }

    // MARK: Internal

    func shouldCancel() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        count += 1
        return count >= cancelAt
    }

    // MARK: Private

    private let cancelAt: Int
    private let lock = NSLock()
    private var count = 0
}
