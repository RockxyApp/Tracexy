import Foundation
import Testing
@testable import Tracexy

// MARK: - AutomationExportTests

@Suite("Automation export: deterministic JSON and RFC-4180 CSV")
struct AutomationExportTests {
    // MARK: Internal

    // MARK: Internal — JSON

    @Test("Session-page JSON is deterministic with sorted keys and full page metadata")
    func sessionJSONIsDeterministic() throws {
        let page = Self.sessionPage(
            sessions: [Self.value(host: "example.com")],
            examinedCount: 1,
            nextCursor: AutomationSessionCursor(ordinal: 0),
            disclosure: .init(includesHost: true)
        )
        let first = try AutomationExport.json(sessionPage: page)
        let second = try AutomationExport.json(sessionPage: page)
        #expect(first == second)

        let text = try #require(String(data: first, encoding: .utf8))
        // Page metadata and cursor are present.
        #expect(text.contains("\"examinedCount\":1"))
        #expect(text.contains("\"pageSize\":10"))
        #expect(text.contains("\"nextCursor\""))
        #expect(text.contains("\"ordinal\":0"))
        #expect(text.contains("\"disclosure\""))
        // Sorted keys: within the session object, bytesDown precedes bytesUp.
        let down = try #require(text.range(of: "bytesDown"))
        let up = try #require(text.range(of: "bytesUp"))
        #expect(down.lowerBound < up.lowerBound)
    }

    @Test("Capture-page JSON encodes captures, cursor and page size")
    func captureJSONIncludesMetadata() throws {
        let capture = AutomationCaptureValue(HistoryStoredCapture(
            record: HistoryCaptureRecord(
                captureID: UUID(),
                startedAt: 1_000,
                endedAt: 2_000,
                sourceKind: .live,
                completeness: .complete
            ),
            sessionCount: 3
        ))
        let page = AutomationCapturePage(
            captures: [capture],
            nextCursor: AutomationCaptureCursor(endedAt: 2_000, captureID: capture.captureID),
            pageSize: 25
        )
        let text = try #require(String(data: AutomationExport.json(capturePage: page), encoding: .utf8))
        #expect(text.contains("\"pageSize\":25"))
        #expect(text.contains("\"sessionCount\":3"))
        #expect(text.contains("\"sourceKind\":\"live\""))
        #expect(text.contains("\"nextCursor\""))
    }

    @Test("Minimum-disclosure JSON omits process, host and endpoints entirely")
    func minimumDisclosureJSONOmitsSensitiveKeys() throws {
        let page = Self.sessionPage(
            sessions: [Self.value(host: "example.com", disclosure: .minimum)],
            examinedCount: 1,
            nextCursor: nil,
            disclosure: .minimum
        )
        let text = try #require(String(data: AutomationExport.json(sessionPage: page), encoding: .utf8))
        #expect(!text.contains("\"host\""))
        #expect(!text.contains("\"processName\""))
        #expect(!text.contains("\"sourceEndpoint\""))
        #expect(!text.contains("\"destinationEndpoint\""))
    }

    // MARK: Internal — CSV

    @Test("CSV emits the fixed header and locale-independent numbers")
    func csvHeaderAndNumbers() throws {
        let page = Self.sessionPage(
            sessions: [Self.value(startTime: 1_000, duration: 5, latency: 12.5, bytesUp: 100, bytesDown: 200)],
            examinedCount: 1,
            nextCursor: nil,
            disclosure: .minimum
        )
        let text = try #require(String(data: AutomationExport.csv(sessionPage: page), encoding: .utf8))
        let lines = text.components(separatedBy: "\r\n")
        #expect(lines.first == AutomationExport.sessionCSVHeader.joined(separator: ","))
        // Row fields: numeric spellings are dot-decimal with no separators.
        let row = try #require(lines.dropFirst().first)
        #expect(row.contains("1000.0"))
        #expect(row.contains("5.0"))
        #expect(row.contains("12.5"))
        #expect(row.contains(",100,200,"))
    }

    @Test("Undisclosed and absent values become empty CSV cells")
    func csvEmptyCells() throws {
        let page = Self.sessionPage(
            sessions: [Self.value(latency: nil, disclosure: .minimum)],
            examinedCount: 1,
            nextCursor: nil,
            disclosure: .minimum
        )
        let text = try #require(String(data: AutomationExport.csv(sessionPage: page), encoding: .utf8))
        let row = try #require(text.components(separatedBy: "\r\n").dropFirst().first)
        let cells = row.components(separatedBy: ",")
        // 12 columns; the trailing four (process/host/src/dst) plus latency are empty.
        #expect(cells.count == 12)
        #expect(cells[5].isEmpty) // latency_ms
        #expect(cells[8].isEmpty) // process_name
        #expect(cells[9].isEmpty) // host
        #expect(cells[10].isEmpty) // source_endpoint
        #expect(cells[11].isEmpty) // destination_endpoint
    }

    @Test("CSV quotes and escapes commas, quotes and embedded newlines per RFC 4180")
    func csvAdversarialEscaping() throws {
        let hostile = "a,\"b\"\nc"
        let page = Self.sessionPage(
            sessions: [Self.value(host: hostile)],
            examinedCount: 1,
            nextCursor: nil,
            disclosure: .init(includesHost: true)
        )
        let text = try #require(String(data: AutomationExport.csv(sessionPage: page), encoding: .utf8))
        // The host cell is wrapped in quotes with the embedded quote doubled; the
        // embedded LF survives inside the quotes, so the record is not split.
        #expect(text.contains("\"a,\"\"b\"\"\nc\""))
        // Exactly one header + one data record terminator pair (the newline inside
        // the quoted field is not a record separator).
        #expect(text.hasSuffix("\r\n"))
        let recordCount = text.components(separatedBy: "\r\n").filter { !$0.isEmpty }.count
        #expect(recordCount == 2)
    }

    @Test("CSV neutralizes spreadsheet formulas in disclosed capture-derived text")
    func csvNeutralizesSpreadsheetFormulas() throws {
        let page = Self.sessionPage(
            sessions: [Self.value(
                processName: "=cmd|'/C calc'!A0",
                host: "  +SUM(1,1)",
                sourceEndpoint: "@malicious",
                destinationEndpoint: "-1+1"
            )],
            examinedCount: 1,
            nextCursor: nil,
            disclosure: .init(includesProcess: true, includesHost: true, includesEndpoints: true)
        )
        let text = try #require(String(data: AutomationExport.csv(sessionPage: page), encoding: .utf8))

        #expect(text.contains("'=cmd|'/C calc'!A0"))
        #expect(text.contains("\"'  +SUM(1,1)\""))
        #expect(text.contains("'@malicious"))
        #expect(text.contains("'-1+1"))
    }

    // MARK: Internal — structural scan

    @Test("The automation sources import nothing forbidden and reference no rich types/fields")
    func structuralScanRejectsForbiddenSurface() throws {
        let root = Self.repositoryRoot()
        let directory = root
            .appendingPathComponent("Tracexy")
            .appendingPathComponent("Core")
            .appendingPathComponent("Automation")

        let forbiddenLiterals = [
            "import SwiftUI",
            "import AppKit",
            "import SQLite3",
            "import SwiftData",
            "SessionSummary",
            "InvestigationSnapshot",
            "InvestigationQuery",
            "CapturedFrame",
            "DecodedPacket",
            "PacketBuffer",
            "FollowStream",
            "rawBytes",
            "dnsAnswers",
            "dnsQuery",
            "infoSummary",
            "Finding",
        ]
        for name in ["AutomationValues", "HistoryAutomationService", "AutomationExport"] {
            let url = directory.appendingPathComponent("\(name).swift")
            let source = try String(contentsOf: url, encoding: .utf8)
            for literal in forbiddenLiterals {
                #expect(!source.contains(literal), "\(name).swift must not contain \(literal)")
            }
        }
    }

    @Test("The host field documents its possible SNI/DNS derivation")
    func hostCopyAcknowledgesDerivation() throws {
        let url = Self.repositoryRoot()
            .appendingPathComponent("Tracexy/Core/Automation/AutomationValues.swift")
        let source = try String(contentsOf: url, encoding: .utf8)
        #expect(source.contains("SNI"))
        #expect(source.contains("DNS"))
    }

    // MARK: Private

    private static func value(
        sessionID: UUID = UUID(),
        startTime: Double = 1_000,
        duration: Double = 5,
        processName: String? = "curl",
        host: String = "example.com",
        sourceEndpoint: String = "10.0.0.1:5000",
        destinationEndpoint: String = "93.184.216.34:443",
        protocols: [String] = ["tcp", "tls"],
        status: HistorySessionStatus = .ok,
        latency: Double? = 12.5,
        bytesUp: Int64 = 100,
        bytesDown: Int64 = 200,
        disclosure: AutomationDisclosure = .init(includesProcess: true, includesHost: true, includesEndpoints: true)
    )
        -> AutomationSessionValue
    {
        let record = HistorySessionRecord(
            sessionID: sessionID,
            startTime: startTime,
            duration: duration,
            processName: processName,
            host: host,
            sourceEndpoint: sourceEndpoint,
            destinationEndpoint: destinationEndpoint,
            protocols: protocols,
            status: status,
            latencyMilliseconds: latency,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
        return AutomationSessionValue(record, disclosure: disclosure)
    }

    private static func sessionPage(
        sessions: [AutomationSessionValue],
        examinedCount: Int,
        nextCursor: AutomationSessionCursor?,
        disclosure: AutomationDisclosure
    )
        -> AutomationSessionPage
    {
        AutomationSessionPage(
            captureID: UUID(),
            sessions: sessions,
            examinedCount: examinedCount,
            nextCursor: nextCursor,
            pageSize: 10,
            disclosure: disclosure
        )
    }

    /// Resolve the repository root from this test's compile-time path:
    /// `.../TracexyTests/Core/Automation/AutomationExportTests.swift`.
    private static func repositoryRoot(file: StaticString = #filePath) -> URL {
        URL(fileURLWithPath: "\(file)")
            .deletingLastPathComponent() // Automation
            .deletingLastPathComponent() // Core
            .deletingLastPathComponent() // TracexyTests
            .deletingLastPathComponent() // repo root
    }
}
