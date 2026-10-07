import Foundation
import Testing
@testable import Tracexy

// MARK: - InvestigationExportTests

/// The sessions-in-view exports: RFC 4180 CSV with formula-injection guards and
/// honest empty cells, sorted-key JSON with the scope that produced it, and a
/// Markdown report whose tables cannot be broken by capture text.
@MainActor
struct InvestigationExportTests {
    // MARK: Internal

    @Test
    func sessionsCSVGuardsFormulasAndKeepsUnknownTimingEmpty() throws {
        let csv = try #require(String(bytes: InvestigationExport.sessionsCSV(Self.input), encoding: .utf8))
        let rows = csv.components(separatedBy: "\r\n").filter { !$0.isEmpty }
        #expect(rows.count == 3)
        #expect(rows[0] == InvestigationExport.sessionHeader.joined(separator: ","))
        // A host that looks like a formula is neutralized with a leading quote.
        #expect(rows[1].contains("'=cmd|' /C calc'!A1"))
        #expect(rows[1].contains("TCP reset observed"))
        #expect(rows[1].hasSuffix(",true"))
        // Unknown start time and duration are empty cells, never 0.
        let untimed = rows[2].components(separatedBy: ",")
        #expect(untimed[1].isEmpty)
        #expect(untimed[2].isEmpty)
        #expect(rows[2].hasSuffix(",false"))
    }

    @Test
    func findingsCSVListsCitations() throws {
        let csv = try #require(String(bytes: InvestigationExport.findingsCSV(Self.input), encoding: .utf8))
        let rows = csv.components(separatedBy: "\r\n").filter { !$0.isEmpty }
        #expect(rows.count == 2)
        #expect(rows[1].contains(",warning,TCP reset observed,"))
        #expect(rows[1].contains(",3 9,2"))
    }

    @Test
    func jsonCarriesScopeSessionsFindingsAndNotes() throws {
        let object = try #require(
            JSONSerialization.jsonObject(with: InvestigationExport.json(Self.input)) as? [String: Any]
        )
        #expect(object["formatVersion"] as? Int == 1)
        let scope = try #require(object["scope"] as? [String: Any])
        #expect(scope["sessionsInView"] as? Int == 2)
        #expect(scope["sessionsInCapture"] as? Int == 7)
        #expect(scope["expression"] as? String == "tcp")
        let sessions = try #require(object["sessions"] as? [[String: Any]])
        #expect(sessions.count == 2)
        #expect((sessions[0]["notes"] as? [[String: Any]])?.first?["text"] as? String == "Check the proxy")
        #expect(sessions[1]["notes"] == nil)
        #expect(sessions[1]["startTimeUTC"] == nil)
        let findings = try #require(object["findings"] as? [[String: Any]])
        #expect(findings.first?["citedFrames"] as? [Int] == [3, 9])
    }

    @Test
    func reportHasScopeFindingsNotesAndEscapedTables() {
        let report = InvestigationExport.report(Self.input)
        #expect(report.hasPrefix("# Investigation: fixture"))
        #expect(report.contains("- Sessions in this report: 2 of 7"))
        #expect(report.contains("- Session expression: `tcp`"))
        #expect(report.contains("## Findings (1)"))
        #expect(report.contains("| warning | TCP reset observed |"))
        #expect(report.contains("3, 9 (+2 not listed)"))
        #expect(report.contains("## Notes"))
        #expect(report.contains("> Check the proxy"))
        // A pipe in capture text cannot split a table row.
        #expect(report.contains("=cmd\\|' /C calc'!A1"))
        #expect(report.contains("| unknown |"))
        #expect(report.contains("not proof that nothing happened"))
    }

    /// Privacy ▸ Mask IP addresses reaches every text an Investigation export
    /// writes, including an `address:port` endpoint in the middle of prose.
    @Test
    func maskedInputHidesEveryAddressAndKeepsPorts() throws {
        #expect(PrivacyMask.maskingAddresses(in: "from 192.0.2.10:51000 to 198.51.100.5.")
            == "from [masked-ip]:51000 to [masked-ip].")
        #expect(PrivacyMask.maskingAddresses(in: "seen at 10.0.0.1: reset") == "seen at [masked-ip]: reset")
        #expect(PrivacyMask.maskingAddresses(in: "v6 2001:db8::1 ok") == "v6 [masked-ip] ok")
        // Not an address: a version string and a time stay as written.
        #expect(PrivacyMask.maskingAddresses(in: "TLS 1.3 at 12:30") == "TLS 1.3 at 12:30")

        var input = Self.input
        input = InvestigationExportInput(
            captureName: "capture 203.0.113.9", generatedAt: input.generatedAt,
            totalSessionCount: input.totalSessionCount, expression: "ip == 192.0.2.10",
            hasOtherFilters: false,
            sessions: input.sessions.map { entry in
                .init(
                    session: entry.session, findingTitles: entry.findingTitles,
                    notes: [SessionExportNote(
                        subject: "session", findingTitle: nil, text: "Proxy 198.51.100.5:3128 answered",
                        updatedAt: Date(timeIntervalSince1970: 0)
                    )]
                )
            },
            findings: input.findings
        )
        let masked = input.maskingAddresses()
        let csv = try #require(String(bytes: InvestigationExport.sessionsCSV(masked), encoding: .utf8))
        let json = try #require(try String(bytes: InvestigationExport.json(masked), encoding: .utf8))
        let text = InvestigationExport.report(masked) + csv + json
        for address in ["192.0.2.10", "198.51.100.5", "198.51.100.6", "203.0.113.9"] {
            #expect(!text.contains(address), "\(address) leaked")
        }
        #expect(text.contains("[masked-ip]:51000"))
        #expect(text.contains("Proxy [masked-ip]:3128 answered"))
        #expect(masked.expression == "ip == [masked-ip]")
    }

    @Test
    func coordinatorSnapshotsTheSessionsInView() async throws {
        let isolation = ProjectIsolationEnvironment(name: "investigation-export")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        #expect(!coordinator.canExportInvestigation)
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("export-scope.pcap")
        try PcapWriter.write(
            linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url
        )
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "export-scope", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        #expect(coordinator.canExportInvestigation)

        let all = coordinator.investigationExportInput(now: Date(timeIntervalSince1970: 0))
        #expect(all.captureName == "export-scope")
        #expect(all.sessions.count == coordinator.presentedSessions.count)
        #expect(all.expression == nil)
        #expect(!all.hasOtherFilters)

        coordinator.applySessionExpression("tcp")
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        let narrowed = coordinator.investigationExportInput()
        #expect(narrowed.expression == "tcp")
        #expect(narrowed.sessions.allSatisfy { $0.session.protocolStack.contains(.tcp) })
        #expect(narrowed.totalSessionCount == all.sessions.count)
        #expect(!narrowed.hasOtherFilters)
    }

    // MARK: Private

    private static var input: InvestigationExportInput {
        let timed = SessionSummary(
            id: SessionBuilder.stableID("export-a"),
            startTime: Date(timeIntervalSince1970: 1_800_000_000),
            duration: 1.5,
            processName: "curl",
            host: "=cmd|' /C calc'!A1",
            sourceEndpoint: "192.0.2.10:51000",
            destinationEndpoint: "198.51.100.5:443",
            protocolStack: [.tcp, .tls],
            status: .warning,
            latencyMilliseconds: 12,
            bytesUp: 100,
            bytesDown: 200
        )
        let untimed = SessionSummary(
            id: SessionBuilder.stableID("export-b"),
            startTime: nil,
            duration: nil,
            processName: nil,
            host: "b.example.test",
            sourceEndpoint: "192.0.2.10:51001",
            destinationEndpoint: "198.51.100.6:80",
            protocolStack: [.tcp],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 1,
            bytesDown: 2
        )
        let note = SessionExportNote(
            subject: "session", findingTitle: nil, text: "Check the proxy",
            updatedAt: Date(timeIntervalSince1970: 1_800_000_100)
        )
        return InvestigationExportInput(
            captureName: "fixture",
            generatedAt: Date(timeIntervalSince1970: 1_800_000_200),
            totalSessionCount: 7,
            expression: "tcp",
            hasOtherFilters: false,
            sessions: [
                .init(session: timed, findingTitles: ["TCP reset observed"], notes: [note]),
                .init(session: untimed, findingTitles: [], notes: []),
            ],
            findings: [
                .init(
                    id: SessionBuilder.stableID("finding-a"),
                    sessionID: timed.id,
                    severity: "warning",
                    title: "TCP reset observed",
                    detail: "2 cited observations",
                    citedFrameOrdinals: [3, 9],
                    omittedCitationCount: 2,
                    sessionHost: timed.host
                ),
            ]
        )
    }
}
