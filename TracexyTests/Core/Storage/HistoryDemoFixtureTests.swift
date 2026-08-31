import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryDemoFixtureTests

@Suite("HistoryDemoFixture deterministic demo seed and retention tiers")
struct HistoryDemoFixtureTests {
    // MARK: Internal

    // MARK: Shape

    @Test("Reset seeds four captures with the expected session counts and kinds")
    func fixtureShape() async throws {
        let store = try SessionStore()
        try await HistoryDemoFixture.reset(into: store, now: Self.clock)

        let captures = try await store.captures(after: nil, limit: 500).captures
        #expect(captures.count == 4)
        // Newest-first paging.
        #expect(captures.map(\.sessionCount) == [3, 2, 4, 2])
        #expect(captures.map(\.record.sourceKind) == [.live, .saved, .live, .saved])
        #expect(captures.map(\.record.completeness) == [.complete, .complete, .incomplete, .complete])

        let statuses = try await Set(Self.allSessions(store).map(\.status))
        #expect(statuses == [.ok, .warning, .error])
        #expect(try await Self.allSessions(store).count == 11)
    }

    // MARK: Fixed identity and content

    @Test("A fixed clock yields fixed capture IDs and byte-identical session content")
    func fixedIdentityAndContent() async throws {
        let store = try SessionStore()
        try await HistoryDemoFixture.reset(into: store, now: Self.clock)

        let captures = try await store.captures(after: nil, limit: 500).captures
        #expect(captures.map(\.record.captureID) == Self.expectedCaptureIDsNewestFirst)

        // A specific recent session round-trips with the exact fixed content.
        let recentID = try #require(UUID(uuidString: "0A000000-0000-4000-8000-0000000000C1"))
        let sessions = try await store.sessions(captureID: recentID, after: nil, limit: 500).sessions
        let first = try #require(sessions.first)
        #expect(first.sessionID == UUID(uuidString: "0B000000-0000-4000-8000-000000000001"))
        #expect(first.host == "example.com")
        #expect(first.processName == "Safari")
        #expect(first.protocols == ["tcp", "tls", "http"])
        #expect(first.status == .ok)
        #expect(first.latencyMilliseconds == 18.4)
        #expect(first.bytesUp == 2_048)
        #expect(first.bytesDown == 40_960)

        // Two independent seeds with the same clock produce identical stores.
        let other = try SessionStore()
        try await HistoryDemoFixture.reset(into: other, now: Self.clock)
        try await Self.expectStoresEqual(store, other)
    }

    // MARK: Privacy-safe reserved values

    @Test("Every host is under example.* and every literal endpoint is documentation-only")
    func privacySafeReservedValues() async throws {
        let store = try SessionStore()
        try await HistoryDemoFixture.reset(into: store, now: Self.clock)

        for session in try await Self.allSessions(store) {
            #expect(Self.isExampleHost(session.host), "unexpected host \(session.host)")
            #expect(Self.isDocumentationEndpoint(session.sourceEndpoint), "unexpected source \(session.sourceEndpoint)")
            #expect(
                Self.isDocumentationEndpoint(session.destinationEndpoint),
                "unexpected destination \(session.destinationEndpoint)"
            )
            if let processName = session.processName {
                // No user paths leak through a process label.
                #expect(!processName.contains("/"))
            }
        }
    }

    // MARK: Reset replaces and reseeds idempotently

    @Test("Reset clears pre-existing unrelated rows before seeding")
    func resetReplacesPreExistingRows() async throws {
        let store = try SessionStore()
        // A pre-existing, unrelated capture with an ID outside the fixture set.
        let stale = HistoryCaptureRecord(
            captureID: UUID(),
            startedAt: 1_000,
            endedAt: 2_000,
            sourceKind: .saved,
            completeness: .complete
        )
        try await store.replaceCapture(stale, sessions: [])

        try await HistoryDemoFixture.reset(into: store, now: Self.clock)

        let captures = try await store.captures(after: nil, limit: 500).captures
        #expect(captures.count == 4)
        #expect(!captures.map(\.record.captureID).contains(stale.captureID))
    }

    @Test("Reseeding with the same clock is idempotent")
    func idempotentReseed() async throws {
        let store = try SessionStore()
        try await HistoryDemoFixture.reset(into: store, now: Self.clock)
        let firstPass = try await store.captures(after: nil, limit: 500).captures

        try await HistoryDemoFixture.reset(into: store, now: Self.clock)
        let secondPass = try await store.captures(after: nil, limit: 500).captures

        #expect(firstPass == secondPass)
        #expect(secondPass.count == 4)
    }

    // MARK: Retention tiers

    @Test("Auto-clear tiers retain Never=4, 24h=3, 1h=2, 15m=1")
    func retentionTierCounts() async throws {
        #expect(try await Self.remaining(after: .never) == 4)
        #expect(try await Self.remaining(after: .hours24) == 3)
        #expect(try await Self.remaining(after: .hour1) == 2)
        #expect(try await Self.remaining(after: .minutes15) == 1)
    }

    // MARK: Private

    /// A fixed injected clock; every timestamp derives from it.
    private static let clock = Date(timeIntervalSince1970: 1_700_000_000)

    private static let expectedCaptureIDsNewestFirst: [UUID] = [
        UUID(uuidString: "0A000000-0000-4000-8000-0000000000C1"),
        UUID(uuidString: "0A000000-0000-4000-8000-0000000000C2"),
        UUID(uuidString: "0A000000-0000-4000-8000-0000000000C3"),
        UUID(uuidString: "0A000000-0000-4000-8000-0000000000C4"),
    ].compactMap { $0 }

    /// Seed a fresh store, apply the tier's interval as a strict end-date cutoff, and
    /// return how many captures survive. `.never` applies no retention.
    private static func remaining(after autoClear: AutoClear) async throws -> Int {
        let store = try SessionStore()
        try await HistoryDemoFixture.reset(into: store, now: clock)
        if let interval = autoClear.retentionInterval {
            let cutoff = clock.addingTimeInterval(-interval).timeIntervalSince1970
            _ = try await store.applyRetention(HistoryRetentionPolicy(oldestAllowedEndDate: cutoff))
        }
        return try await store.captures(after: nil, limit: 500).captures.count
    }

    /// Every stored session across every capture, in paging order.
    private static func allSessions(_ store: SessionStore) async throws -> [HistorySessionRecord] {
        let captures = try await store.captures(after: nil, limit: 500).captures
        var sessions: [HistorySessionRecord] = []
        for capture in captures {
            let page = try await store.sessions(captureID: capture.record.captureID, after: nil, limit: 500)
            sessions.append(contentsOf: page.sessions)
        }
        return sessions
    }

    private static func expectStoresEqual(_ lhs: SessionStore, _ rhs: SessionStore) async throws {
        let lhsCaptures = try await lhs.captures(after: nil, limit: 500).captures
        let rhsCaptures = try await rhs.captures(after: nil, limit: 500).captures
        #expect(lhsCaptures == rhsCaptures)
        for capture in lhsCaptures {
            let id = capture.record.captureID
            let lhsSessions = try await lhs.sessions(captureID: id, after: nil, limit: 500).sessions
            let rhsSessions = try await rhs.sessions(captureID: id, after: nil, limit: 500).sessions
            #expect(lhsSessions == rhsSessions)
        }
    }

    private static func isExampleHost(_ host: String) -> Bool {
        let roots = ["example.com", "example.net", "example.org"]
        return roots.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    /// True when the endpoint's address is in an IPv4 documentation range or IPv6
    /// `2001:db8::/32`. Bracketed IPv6 endpoints look like `[2001:db8::10]:443`.
    private static func isDocumentationEndpoint(_ endpoint: String) -> Bool {
        if endpoint.hasPrefix("[") {
            return endpoint.hasPrefix("[2001:db8:")
        }
        let ipv4DocumentationPrefixes = ["192.0.2.", "198.51.100.", "203.0.113."]
        return ipv4DocumentationPrefixes.contains { endpoint.hasPrefix($0) }
    }
}
