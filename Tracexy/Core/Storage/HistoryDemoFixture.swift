import Foundation

// MARK: - HistoryDemoFixture

/// A bounded, deterministic synthetic History seed for development/demo use only.
///
/// It exists so an operator can populate an *injected* ``SessionStore`` with a
/// credible, varied History table and exercise the Auto-clear retention tiers
/// immediately, without a live capture. It is deliberately:
///
/// - **Path-agnostic** — it never resolves or opens the production History file. The
///   caller injects whatever store it wants seeded (the app composes it only with an
///   in-memory store behind `--dum-data`).
/// - **Settings-agnostic** — it reads no `UserDefaults` and applies no policy; it
///   only clears and rewrites the injected store.
/// - **Clock-injected & deterministic** — every capture/session timestamp derives
///   from the injected `now`, and every identity is a fixed UUID, so the same clock
///   always yields byte-identical records.
/// - **Privacy-safe** — every hostname is under `example.com`/`example.net`/
///   `example.org` and every literal address is in an IPv4 documentation range
///   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or IPv6 `2001:db8::/32`.
///   It carries no credentials, payloads, user paths, live endpoints or raw bytes.
enum HistoryDemoFixture {
    // MARK: Internal

    /// A fixed synthetic UUID string could not be parsed. This fails the reset
    /// deterministically rather than silently substituting a random identity, so a
    /// typo in a fixed ID can never produce nondeterministic demo data.
    enum FixtureError: Error, Equatable {
        case malformedFixedID(String)
    }

    /// Clear `store` and reseed it with the deterministic demo set anchored to `now`.
    ///
    /// This *replaces* whatever the injected store held: it first deletes every
    /// existing capture (the zero-retention clear primitive), then writes the four
    /// fixed-ID synthetic captures. Reseeding with the same `now` is idempotent —
    /// the store converges to the identical rows regardless of prior contents.
    static func reset(into store: SessionStore, now: Date) async throws {
        // Clear only the injected store — never a resolved production path.
        _ = try await store.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 0))
        for demo in try demoCaptures(now: now) {
            try await store.replaceCapture(demo.record, sessions: demo.sessions)
        }
    }

    // MARK: Private

    /// One synthetic capture and its ordered sessions, ready to write.
    private struct DemoCapture {
        let record: HistoryCaptureRecord
        let sessions: [HistorySessionRecord]
    }

    /// The neutral content of one synthetic session, independent of timing (start
    /// time and duration are derived from the enclosing capture window).
    private struct SessionSpec {
        let id: String
        let processName: String?
        let host: String
        let source: String
        let destination: String
        let protocols: [String]
        let status: HistorySessionStatus
        let latencyMilliseconds: Double?
        let bytesUp: Int64
        let bytesDown: Int64
    }

    /// One synthetic capture: its identity, age before the injected clock, kind,
    /// fidelity, and ordered session content.
    private struct CaptureSpec {
        let id: String
        /// Seconds before the injected clock at which this capture ended. Every value
        /// is comfortably clear of the shipped Auto-clear cutoffs (900 / 3_600 /
        /// 86_400 s), so strict retention comparisons never land on a boundary.
        let age: TimeInterval
        let sourceKind: HistorySourceKind
        let completeness: HistoryCompleteness
        let sessions: [SessionSpec]
    }

    /// Every capture spans this many seconds; sessions are spaced inside the window
    /// so their timestamps stay internally coherent with the capture lifetime.
    private static let captureSpan: TimeInterval = 120

    /// The four fixed captures, newest-first by age. The ages map each capture to a
    /// distinct retention tier: ~5 min survives every interval; ~30 min survives 1h
    /// and 24h; ~3 h survives only 24h; ~30 h never survives an enabled interval.
    private static let captureSpecs: [CaptureSpec] = [
        CaptureSpec(
            id: "0A000000-0000-4000-8000-0000000000C1",
            age: 5 * 60,
            sourceKind: .live,
            completeness: .complete,
            sessions: [
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000001",
                    processName: "Safari",
                    host: "example.com",
                    source: "192.0.2.10:52344",
                    destination: "198.51.100.20:443",
                    protocols: ["tcp", "tls", "http"],
                    status: .ok,
                    latencyMilliseconds: 18.4,
                    bytesUp: 2_048, bytesDown: 40_960
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000002",
                    processName: "Mail",
                    host: "example.net",
                    source: "[2001:db8::10]:51000",
                    destination: "[2001:db8:1::20]:443",
                    protocols: ["tcp", "tls"],
                    status: .warning,
                    latencyMilliseconds: 240.0,
                    bytesUp: 512, bytesDown: 1_024
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000003",
                    processName: nil,
                    host: "example.org",
                    source: "203.0.113.5:49200",
                    destination: "203.0.113.80:80",
                    protocols: ["tcp", "http"],
                    status: .error,
                    latencyMilliseconds: nil,
                    bytesUp: 0, bytesDown: 0
                ),
            ]
        ),
        CaptureSpec(
            id: "0A000000-0000-4000-8000-0000000000C2",
            age: 30 * 60,
            sourceKind: .saved,
            completeness: .complete,
            sessions: [
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000004",
                    processName: "curl",
                    host: "api.example.com",
                    source: "192.0.2.30:53000",
                    destination: "198.51.100.40:443",
                    protocols: ["tcp", "tls", "http"],
                    status: .ok,
                    latencyMilliseconds: 33.2,
                    bytesUp: 8_192, bytesDown: 131_072
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000005",
                    processName: "Music",
                    host: "cdn.example.net",
                    source: "192.0.2.31:53100",
                    destination: "198.51.100.41:443",
                    protocols: ["tcp", "tls", "http"],
                    status: .ok,
                    latencyMilliseconds: 12.0,
                    bytesUp: 1_024, bytesDown: 262_144
                ),
            ]
        ),
        CaptureSpec(
            id: "0A000000-0000-4000-8000-0000000000C3",
            age: 3 * 60 * 60,
            sourceKind: .live,
            completeness: .incomplete,
            sessions: [
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000006",
                    processName: "Safari",
                    host: "example.com",
                    source: "192.0.2.50:60000",
                    destination: "198.51.100.50:443",
                    protocols: ["udp", "quic"],
                    status: .ok,
                    latencyMilliseconds: 22.5,
                    bytesUp: 4_096, bytesDown: 20_480
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000007",
                    processName: "mDNSResponder",
                    host: "dns.example.net",
                    source: "192.0.2.51:5353",
                    destination: "198.51.100.51:53",
                    protocols: ["udp", "dns"],
                    status: .ok,
                    latencyMilliseconds: 8.7,
                    bytesUp: 128, bytesDown: 256
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000008",
                    processName: "ssh",
                    host: "example.org",
                    source: "203.0.113.10:49000",
                    destination: "203.0.113.90:22",
                    protocols: ["tcp"],
                    status: .warning,
                    latencyMilliseconds: 95.0,
                    bytesUp: 3_072, bytesDown: 4_096
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-000000000009",
                    processName: nil,
                    host: "mail.example.org",
                    source: "192.0.2.52:50500",
                    destination: "198.51.100.52:587",
                    protocols: ["tcp", "tls"],
                    status: .error,
                    latencyMilliseconds: nil,
                    bytesUp: 256, bytesDown: 0
                ),
            ]
        ),
        CaptureSpec(
            id: "0A000000-0000-4000-8000-0000000000C4",
            age: 30 * 60 * 60,
            sourceKind: .saved,
            completeness: .complete,
            sessions: [
                SessionSpec(
                    id: "0B000000-0000-4000-8000-00000000000A",
                    processName: "com.example.sync",
                    host: "example.net",
                    source: "[2001:db8::100]:52000",
                    destination: "[2001:db8:2::200]:443",
                    protocols: ["tcp", "tls", "http"],
                    status: .ok,
                    latencyMilliseconds: 45.1,
                    bytesUp: 16_384, bytesDown: 524_288
                ),
                SessionSpec(
                    id: "0B000000-0000-4000-8000-00000000000B",
                    processName: "wget",
                    host: "legacy.example.org",
                    source: "203.0.113.20:48000",
                    destination: "203.0.113.200:8080",
                    protocols: ["tcp", "http"],
                    status: .warning,
                    latencyMilliseconds: 310.5,
                    bytesUp: 640, bytesDown: 2_048
                ),
            ]
        ),
    ]

    /// Realize the fixed capture specs against the injected clock, deriving coherent
    /// capture windows and per-session timestamps.
    private static func demoCaptures(now: Date) throws -> [DemoCapture] {
        let clock = now.timeIntervalSince1970
        return try captureSpecs.map { spec in
            let end = clock - spec.age
            let start = end - captureSpan
            let record = try HistoryCaptureRecord(
                captureID: fixedID(spec.id),
                startedAt: start,
                endedAt: end,
                sourceKind: spec.sourceKind,
                completeness: spec.completeness
            )
            let sessions = try spec.sessions.enumerated().map { slot, session in
                try HistorySessionRecord(
                    sessionID: fixedID(session.id),
                    // Space sessions inside the window so start + duration <= end.
                    startTime: start + 1 + Double(slot) * 10,
                    duration: 6.5,
                    processName: session.processName,
                    host: session.host,
                    sourceEndpoint: session.source,
                    destinationEndpoint: session.destination,
                    protocols: session.protocols,
                    status: session.status,
                    latencyMilliseconds: session.latencyMilliseconds,
                    bytesUp: session.bytesUp,
                    bytesDown: session.bytesDown
                )
            }
            return DemoCapture(record: record, sessions: sessions)
        }
    }

    /// Parse a fixed synthetic UUID, failing closed on a malformed literal so a demo
    /// identity is never silently randomized.
    private static func fixedID(_ string: String) throws -> UUID {
        guard let uuid = UUID(uuidString: string) else {
            throw FixtureError.malformedFixedID(string)
        }
        return uuid
    }
}
