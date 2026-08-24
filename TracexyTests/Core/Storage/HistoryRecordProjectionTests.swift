import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryRecordProjectionTests

@Suite("HistoryRecordProjection neutral mapping, bounds and masking")
struct HistoryRecordProjectionTests {
    // MARK: Internal

    @Test("Status, protocol order, byte and latency fields map explicitly")
    func mapsNeutralFields() throws {
        let session = Self.summary(
            protocolStack: [.tcp, .tls, .http],
            status: .warning,
            latencyMilliseconds: 42.5,
            bytesUp: 111,
            bytesDown: 222
        )
        let output = HistoryRecordProjection.project(Self.input(sessions: [session], sourceKind: .live))

        #expect(output.capture.sourceKind == .live)
        let record = try #require(output.sessions.first)
        #expect(record.sessionID == session.id)
        #expect(record.status == .warning)
        // Protocol order is preserved verbatim.
        #expect(record.protocols == ["tcp", "tls", "http"])
        #expect(record.latencyMilliseconds == 42.5)
        #expect(record.bytesUp == 111)
        #expect(record.bytesDown == 222)
    }

    @Test("Every SessionStatus maps to its storage-owned counterpart")
    func statusMapping() {
        let pairs: [(SessionStatus, HistorySessionStatus)] = [(.ok, .ok), (.warning, .warning), (.error, .error)]
        for (uiStatus, stored) in pairs {
            let output = HistoryRecordProjection.project(
                Self.input(sessions: [Self.summary(status: uiStatus)], sourceKind: .live)
            )
            #expect(output.sessions.first?.status == stored)
        }
    }

    @Test("Protocol values are bounded to the per-session cap, preserving order")
    func protocolsBounded() {
        let deep = Array(repeating: ProtocolKind.tcp, count: HistoryLimits.maxProtocolsPerSession + 4)
        let output = HistoryRecordProjection.project(
            Self.input(sessions: [Self.summary(protocolStack: deep)], sourceKind: .saved)
        )
        #expect(output.sessions.first?.protocols.count == HistoryLimits.maxProtocolsPerSession)
    }

    @Test("Negative byte counts clamp to zero; non-finite/negative latency becomes nil")
    func clampsInvalidNumbers() {
        let output = HistoryRecordProjection.project(Self.input(
            sessions: [
                Self.summary(latencyMilliseconds: -1, bytesUp: -5, bytesDown: -9),
                Self.summary(latencyMilliseconds: .nan),
            ],
            sourceKind: .live
        ))
        #expect(output.sessions[0].bytesUp == 0)
        #expect(output.sessions[0].bytesDown == 0)
        #expect(output.sessions[0].latencyMilliseconds == nil)
        #expect(output.sessions[1].latencyMilliseconds == nil)
    }

    @Test("endedAt never precedes startedAt even for inverted inputs")
    func endNeverBeforeStart() {
        let output = HistoryRecordProjection.project(Self.input(
            sessions: [],
            sourceKind: .saved,
            startedAt: 100,
            endedAt: 40
        ))
        #expect(output.capture.startedAt == 100)
        #expect(output.capture.endedAt == 100)
        #expect(output.sessions.isEmpty)
    }

    @Test("Masking off leaves host and endpoints verbatim")
    func maskingOff() {
        let session = Self.summary(
            host: "93.184.216.34",
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: "93.184.216.34:443"
        )
        let output = HistoryRecordProjection.project(
            Self.input(sessions: [session], sourceKind: .live, maskIPAddresses: false)
        )
        let record = output.sessions.first
        #expect(record?.host == "93.184.216.34")
        #expect(record?.sourceEndpoint == "10.0.0.1:5000")
        #expect(record?.destinationEndpoint == "93.184.216.34:443")
    }

    @Test("Masking on applies the same address/endpoint semantics as protected export")
    func maskingOn() {
        let session = Self.summary(
            host: "93.184.216.34",
            sourceEndpoint: "10.0.0.1:5000",
            destinationEndpoint: "example.com:443"
        )
        let output = HistoryRecordProjection.project(
            Self.input(sessions: [session], sourceKind: .live, maskIPAddresses: true)
        )
        let record = output.sessions.first
        // A bare IP host is masked; a port is preserved; a hostname is untouched.
        #expect(record?.host == "[masked-ip]")
        #expect(record?.sourceEndpoint == "[masked-ip]:5000")
        #expect(record?.destinationEndpoint == "example.com:443")
    }

    @Test("Projected records satisfy the store's own validation and round-trip")
    func roundTripsThroughStore() async throws {
        let store = try SessionStore()
        let output = HistoryRecordProjection.project(Self.input(
            sessions: [Self.summary(), Self.summary()],
            sourceKind: .saved,
            startedAt: 1_000,
            endedAt: 1_050
        ))
        try await store.replaceCapture(output.capture, sessions: output.sessions)
        #expect(try await store.capture(id: output.capture.captureID)?.sessionCount == 2)
    }

    // MARK: Private

    private static func input(
        sessions: [SessionSummary],
        sourceKind: HistorySourceKind,
        completeness: HistoryCompleteness = .complete,
        startedAt: Double = 1_000,
        endedAt: Double = 2_000,
        maskIPAddresses: Bool = false
    )
        -> HistoryRecordProjection.Input
    {
        HistoryRecordProjection.Input(
            captureID: UUID(),
            startedAt: startedAt,
            endedAt: endedAt,
            sourceKind: sourceKind,
            completeness: completeness,
            sessions: sessions,
            maskIPAddresses: maskIPAddresses
        )
    }

    private static func summary(
        host: String = "example.com",
        sourceEndpoint: String = "10.0.0.1:5000",
        destinationEndpoint: String = "93.184.216.34:443",
        protocolStack: [ProtocolKind] = [.tcp, .tls],
        status: SessionStatus = .ok,
        latencyMilliseconds: Double? = 12.5,
        bytesUp: Int = 100,
        bytesDown: Int = 200
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_000),
            duration: 5,
            processName: "curl",
            host: host,
            sourceEndpoint: sourceEndpoint,
            destinationEndpoint: destinationEndpoint,
            protocolStack: protocolStack,
            status: status,
            latencyMilliseconds: latencyMilliseconds,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
    }
}
