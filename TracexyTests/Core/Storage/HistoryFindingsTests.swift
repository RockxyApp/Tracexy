import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryFindingsStoreTests

/// A stored capture carries its evidence-linked findings, replaced
/// and deleted with it; v2 files upgrade in place, and a read-only reader of a v2
/// file still reads captures and says findings were not recorded.
struct HistoryFindingsStoreTests {
    // MARK: Internal

    @Test
    func findingsRoundTripReplaceAndCascade() async throws {
        let store = try SessionStore()
        #expect(await store.recordsFindings)
        let captureID = UUID()
        let sessions = [Self.session(), Self.session()]
        let findings = [
            Self.finding(session: sessions[0].sessionID, kind: "retransmission"),
            Self.finding(session: sessions[1].sessionID, kind: "dnsNameError", first: nil),
            Self.finding(session: sessions[0].sessionID, kind: "reset"),
        ]
        try await store.replaceCapture(Self.capture(captureID), sessions: sessions, findings: findings)

        let page = try await store.findings(captureID: captureID, after: nil, limit: 2)
        #expect(page.findings.map(\.kind) == ["retransmission", "dnsNameError"])
        #expect(page.findings[1].firstCitedAt == nil)
        let rest = try await store.findings(captureID: captureID, after: page.nextCursor, limit: 2)
        #expect(rest.findings.map(\.kind) == ["reset"])
        #expect(rest.nextCursor == nil)
        let first = try await store.findings(
            captureID: captureID,
            sessionID: sessions[0].sessionID,
            after: nil,
            limit: 10
        )
        #expect(first.findings.map(\.kind) == ["retransmission", "reset"])

        try await store.replaceCapture(Self.capture(captureID), sessions: sessions, findings: [findings[1]])
        #expect(try await store.findings(captureID: captureID, after: nil, limit: 10).findings.map(\.kind)
            == ["dnsNameError"])

        _ = try await store.applyRetention(HistoryRetentionPolicy(maxCaptureCount: 0))
        #expect(try await store.findings(captureID: captureID, after: nil, limit: 10).findings.isEmpty)
    }

    @Test
    func invalidFindingsAreRefusedBeforeAnyWrite() async throws {
        let store = try SessionStore()
        let session = Self.session()
        let long = Self.finding(session: session.sessionID, kind: String(repeating: "k", count: 65))
        await #expect(throws: HistoryStoreError.stringTooLong(field: "finding kind", byteCount: 65)) {
            try await store.replaceCapture(Self.capture(UUID()), sessions: [session], findings: [long])
        }
        #expect(try await store.captures(after: nil, limit: 10).captures.isEmpty)
    }

    @Test
    func v2FilesUpgradeAndReadOnlyReadersStillRead() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("history-v2-\(UUID().uuidString).sqlite")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let captureID = UUID()
        let sessionID = UUID()
        try Self.installV2Database(at: url, captureID: captureID, sessionID: sessionID)

        let reader = try SessionStore(configuration: .init(location: .file(url), readOnly: true))
        #expect(await reader.schemaVersion == 2)
        #expect(try await reader.capture(id: captureID)?.sessionCount == 1)
        await #expect(throws: HistoryStoreError.findingsNotRecorded) {
            _ = try await reader.findings(captureID: captureID, after: nil, limit: 10)
        }

        let writer = try SessionStore(configuration: .init(location: .file(url)))
        #expect(await writer.schemaVersion == 3)
        #expect(try await writer.sessions(captureID: captureID, after: nil, limit: 10).sessions.map(\.sessionID)
            == [sessionID])
        #expect(try await writer.findings(captureID: captureID, after: nil, limit: 10).findings.isEmpty)
    }

    @Test
    func projectionKeepsOnlyFindingsOfStoredSessionsOnce() {
        let kept = Self.finding(session: UUID(), kind: "reset")
        let summary = SessionSummary(
            id: kept.sessionID, startTime: nil, duration: nil, processName: nil, host: "h",
            sourceEndpoint: "—", destinationEndpoint: "—", protocolStack: [.tcp], status: .ok,
            latencyMilliseconds: nil, bytesUp: 1, bytesDown: 1
        )
        let output = HistoryRecordProjection.project(.init(
            captureID: UUID(), startedAt: 1, endedAt: 2, sourceKind: .saved, completeness: .complete,
            sessions: [summary],
            findings: [kept, kept, Self.finding(session: UUID(), kind: "orphan")],
            maskIPAddresses: false
        ))
        #expect(output.findings.map(\.kind) == ["reset"])
    }

    // MARK: Private

    private static func capture(_ id: UUID) -> HistoryCaptureRecord {
        HistoryCaptureRecord(
            captureID: id, startedAt: 1_760_000_000, endedAt: 1_760_000_060, sourceKind: .saved, completeness: .complete
        )
    }

    private static func session() -> HistorySessionRecord {
        HistorySessionRecord(
            sessionID: UUID(), startTime: 1_760_000_000, duration: 1, processName: nil, host: "example.test",
            sourceEndpoint: "192.0.2.1:50000", destinationEndpoint: "198.51.100.1:443", protocols: ["tcp"],
            status: .ok, latencyMilliseconds: nil, bytesUp: 1, bytesDown: 2
        )
    }

    private static func finding(session: UUID, kind: String, first: Double? = 1_760_000_001) -> HistoryFindingRecord {
        HistoryFindingRecord(
            findingID: UUID(), sessionID: session, kind: kind, severity: .warning,
            coverage: "boundedNoKnownOmission", citedObservationCount: 2, omittedCitationCount: 0, firstCitedAt: first
        )
    }

    /// The exact v2 DDL this build shipped before findings, with one capture and
    /// one session.
    private static func installV2Database(at url: URL, captureID: UUID, sessionID: UUID) throws {
        let database = try SQLiteDatabase(path: url.path, readOnly: false)
        defer { database.close() }
        try database.execute("""
        CREATE TABLE captures (
            id TEXT PRIMARY KEY, started_at REAL NOT NULL, ended_at REAL NOT NULL, source_kind INTEGER NOT NULL,
            completeness INTEGER NOT NULL, session_count INTEGER NOT NULL, time_basis INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE sessions (
            capture_id TEXT NOT NULL, session_id TEXT NOT NULL, ordinal INTEGER NOT NULL, start_time REAL NULL,
            duration REAL NULL, process_name TEXT NULL, host TEXT NOT NULL, source_endpoint TEXT NOT NULL,
            destination_endpoint TEXT NOT NULL, status INTEGER NOT NULL, latency_ms REAL NULL,
            bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL,
            PRIMARY KEY(capture_id, session_id), UNIQUE(capture_id, ordinal),
            FOREIGN KEY(capture_id) REFERENCES captures(id) ON DELETE CASCADE
        );
        CREATE TABLE session_protocols (
            capture_id TEXT NOT NULL, session_id TEXT NOT NULL, protocol_ordinal INTEGER NOT NULL, value TEXT NOT NULL,
            PRIMARY KEY(capture_id, session_id, protocol_ordinal),
            FOREIGN KEY(capture_id, session_id) REFERENCES sessions(capture_id, session_id) ON DELETE CASCADE
        );
        CREATE INDEX idx_captures_ended ON captures(ended_at, id);
        INSERT INTO captures VALUES ('\(captureID.uuidString)', 1760000000, 1760000060, 1, 0, 1, 0);
        INSERT INTO sessions VALUES ('\(captureID.uuidString)', '\(sessionID.uuidString)', 0, 1760000000, 1, NULL,
            'example.test', '192.0.2.1:50000', '198.51.100.1:443', 0, NULL, 1, 2);
        PRAGMA user_version = 2;
        """)
    }
}

// MARK: - HistoryFindingsFlowTests

/// Opening a capture writes its findings to the Project's History under the
/// public kind names the Session Expression uses.
@MainActor
struct HistoryFindingsFlowTests {
    @Test
    func aSavedCapturesFindingsReachHistory() async throws {
        let environment = ProjectIsolationEnvironment(name: "history-findings")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("nxdomain.pcap")
        let query = FollowDatagramReaderTests.dnsMessage(
            id: 7,
            flags: 0x0100,
            name: "missing.example.test",
            answers: []
        )
        let answer = FollowDatagramReaderTests.dnsMessage(
            id: 7,
            flags: 0x8183,
            name: "missing.example.test",
            answers: []
        )
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "10.0.0.5", dst: "10.0.0.1",
                payload: PacketBuilder.udp(srcPort: 53_001, dstPort: 53, payload: query)
            ),
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "10.0.0.1", dst: "10.0.0.5",
                payload: PacketBuilder.udp(srcPort: 53, dstPort: 53_001, payload: answer)
            ),
        ]
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: frames.enumerated().map { index, bytes in
                CapturedFrame(
                    bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(index) * 0.03),
                    originalLength: bytes.count
                )
            },
            to: url
        )
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "nxdomain", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        await coordinator.historyMutationTask?.value

        let store = try #require(coordinator.sessionStore)
        let capture = try #require(try await store.captures(after: nil, limit: 5).captures.first)
        let findings = try await store.findings(captureID: capture.id, after: nil, limit: 10).findings
        #expect(findings.map(\.kind) == ["dnsNameError"])
        #expect(findings.first?.severity == .note)
        #expect(findings.first?.firstCitedAt == 1_800_000_000.03)
    }
}
