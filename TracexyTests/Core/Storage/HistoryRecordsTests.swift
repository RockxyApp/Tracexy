import Foundation
import Testing
@testable import Tracexy

// MARK: - HistoryRecordsTests

@Suite("History record validation bounds and finite values")
struct HistoryRecordsTests {
    // MARK: Internal

    @Test("A well-formed capture and session validate")
    func wellFormedRecordsValidate() throws {
        try Self.capture().validate()
        try Self.session().validate()
    }

    @Test("Capture rejects non-finite timestamps")
    func captureRejectsNonFiniteTimestamps() {
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "startedAt")) {
            try Self.capture(startedAt: .nan).validate()
        }
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "endedAt")) {
            try Self.capture(endedAt: .infinity).validate()
        }
    }

    @Test("Capture rejects an end before its start")
    func captureRejectsEndBeforeStart() {
        #expect(throws: HistoryStoreError.endBeforeStart) {
            try Self.capture(startedAt: 100, endedAt: 99).validate()
        }
    }

    @Test("Capture accepts an end exactly equal to its start")
    func captureAcceptsEqualStartAndEnd() throws {
        try Self.capture(startedAt: 100, endedAt: 100).validate()
    }

    @Test("Session rejects non-finite start, duration and latency")
    func sessionRejectsNonFiniteNumbers() {
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "startTime")) {
            try Self.session(startTime: .infinity).validate()
        }
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "duration")) {
            try Self.session(duration: .nan).validate()
        }
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "latencyMilliseconds")) {
            try Self.session(latencyMilliseconds: .nan).validate()
        }
    }

    @Test("Session rejects negative duration, latency and byte counts")
    func sessionRejectsNegativeValues() {
        #expect(throws: HistoryStoreError.negativeValue(field: "duration")) {
            try Self.session(duration: -1).validate()
        }
        #expect(throws: HistoryStoreError.negativeValue(field: "latencyMilliseconds")) {
            try Self.session(latencyMilliseconds: -0.5).validate()
        }
        #expect(throws: HistoryStoreError.negativeValue(field: "bytesUp")) {
            try Self.session(bytesUp: -1).validate()
        }
        #expect(throws: HistoryStoreError.negativeValue(field: "bytesDown")) {
            try Self.session(bytesDown: -1).validate()
        }
    }

    @Test("Session accepts a nil latency and zero byte counts")
    func sessionAcceptsNilLatencyAndZeroBytes() throws {
        try Self.session(latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0).validate()
    }

    @Test("Session rejects more than the protocol bound")
    func sessionRejectsTooManyProtocols() {
        let tooMany = (0 ... HistoryLimits.maxProtocolsPerSession).map { "p\($0)" }
        #expect(throws: HistoryStoreError.tooManyProtocols(count: tooMany.count)) {
            try Self.session(protocols: tooMany).validate()
        }
    }

    @Test("Session accepts exactly the protocol bound")
    func sessionAcceptsProtocolBound() throws {
        let exact = (0 ..< HistoryLimits.maxProtocolsPerSession).map { "p\($0)" }
        try Self.session(protocols: exact).validate()
    }

    @Test("Session rejects an oversized string but accepts the exact byte bound")
    func sessionEnforcesStringByteBound() throws {
        let atBound = String(repeating: "a", count: HistoryLimits.maxStringUTF8Bytes)
        try Self.session(host: atBound).validate()

        let overBound = String(repeating: "a", count: HistoryLimits.maxStringUTF8Bytes + 1)
        #expect(throws: HistoryStoreError.stringTooLong(field: "host", byteCount: overBound.utf8.count)) {
            try Self.session(host: overBound).validate()
        }
    }

    @Test("String bound is measured in UTF-8 bytes, not characters")
    func stringBoundCountsUTF8Bytes() {
        // A 3-byte UTF-8 scalar repeated past the byte bound but under the
        // character bound must still be rejected.
        let count = (HistoryLimits.maxStringUTF8Bytes / 3) + 1
        let multibyte = String(repeating: "あ", count: count)
        #expect(multibyte.count < HistoryLimits.maxStringUTF8Bytes)
        #expect(throws: HistoryStoreError.self) {
            try Self.session(destinationEndpoint: multibyte).validate()
        }
    }

    @Test("Retention policy rejects negative bounds and a non-finite date")
    func retentionPolicyValidatesBounds() {
        #expect(throws: HistoryStoreError.negativeValue(field: "maxCaptureCount")) {
            try HistoryRetentionPolicy(maxCaptureCount: -1).validate()
        }
        #expect(throws: HistoryStoreError.negativeValue(field: "maxTotalSessionCount")) {
            try HistoryRetentionPolicy(maxTotalSessionCount: -1).validate()
        }
        #expect(throws: HistoryStoreError.nonFiniteValue(field: "oldestAllowedEndDate")) {
            try HistoryRetentionPolicy(oldestAllowedEndDate: .nan).validate()
        }
    }

    @Test("An empty retention policy validates")
    func emptyRetentionPolicyValidates() throws {
        try HistoryRetentionPolicy().validate()
    }

    // MARK: Private

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
}
