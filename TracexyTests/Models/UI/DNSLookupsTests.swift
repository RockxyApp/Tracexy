import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ DNS Lookups: names from unicast DNS sessions, outcomes from the datagram
/// findings (no such name first), a measured median response time, mDNS left out,
/// and a row that shows that name's sessions.
@MainActor
struct DNSLookupsTests {
    // MARK: Internal

    @Test
    func namesCarryOutcomesAndResponseTimes() async throws {
        let environment = ProjectIsolationEnvironment(name: "dns-lookups")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("dns.pcap")
        let frames: [(bytes: [UInt8], seconds: Double)] = [
            (Self.dns(client: true, port: 53_001, id: 1, flags: 0x0100, name: "ok.example.test"), 0.000),
            (
                Self
                    .dns(
                        client: false,
                        port: 53_001,
                        id: 1,
                        flags: 0x8180,
                        name: "ok.example.test",
                        answers: ["192.0.2.10"]
                    ),
                0.012
            ),
            (Self.dns(client: true, port: 53_002, id: 2, flags: 0x0100, name: "missing.example.test"), 1.000),
            (Self.dns(client: false, port: 53_002, id: 2, flags: 0x8183, name: "missing.example.test"), 1.030),
        ]
        try PcapWriter.write(
            linkType: LinkType.ethernet,
            frames: frames.map {
                CapturedFrame(
                    bytes: $0.bytes,
                    timestamp: Date(timeIntervalSince1970: 1_800_000_000 + $0.seconds),
                    originalLength: $0.bytes.count
                )
            },
            to: url
        )
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "dns", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let rows = DNSLookups.rows(
            sessions: coordinator.visibleSessions,
            findings: coordinator.datagramAnalysisSnapshot.findings,
            responseTimes: coordinator.timingSnapshot.measurements
        )
        #expect(rows.map(\.name) == ["missing.example.test", "ok.example.test"])
        let missing = try #require(rows.first)
        #expect(missing.noSuchNameCount == 1)
        #expect(missing.outcome == "1 no such name")
        let ok = try #require(rows.last)
        #expect(ok.answeredCount == 1)
        #expect(ok.addressCount == 1)
        #expect(ok.outcome == "1 answered")
        #expect(ok.medianResponseTime.map { abs($0 - 0.012) < 0.0005 } == true)

        coordinator.selectHost("missing.example.test")
        #expect(coordinator.visibleSessions.allSatisfy { $0.host == "missing.example.test" })
        #expect(!coordinator.visibleSessions.isEmpty)
    }

    @Test
    func theOutcomeAccountsForEveryLookup() {
        let row = DNSLookupRow(
            name: "x.example.test", lookupCount: 3, answeredCount: 0, noSuchNameCount: 1, failedCount: 0,
            unansweredCount: 0, addressCount: 0, medianResponseTime: nil
        )
        #expect(row.outcome == "1 no such name, 2 without an answer")
        let quiet = DNSLookupRow(
            name: "y.example.test", lookupCount: 2, answeredCount: 0, noSuchNameCount: 0, failedCount: 0,
            unansweredCount: 0, addressCount: 0, medianResponseTime: nil
        )
        #expect(quiet.outcome == "No answer retained")
    }

    @Test
    func rowsKeepTheSpellingTheSessionsCarry() {
        var mixed = SessionSummary(
            id: SessionBuilder.stableID("dns-lookups-case"), startTime: nil, duration: nil, processName: nil,
            host: "API.Example.test", sourceEndpoint: "10.0.0.5:53001", destinationEndpoint: "10.0.0.1:53",
            protocolStack: [.udp, .dns], status: .ok, latencyMilliseconds: nil, bytesUp: 1, bytesDown: 0
        )
        mixed.dnsQuery = "API.Example.test"
        #expect(DNSLookups.rows(sessions: [mixed], findings: [], responseTimes: []).first?.name == "API.Example.test")
    }

    @Test
    func multicastNamesAreLeftToResolvedAddresses() {
        var mdns = SessionSummary(
            id: SessionBuilder.stableID("dns-lookups-mdns"), startTime: nil, duration: nil, processName: nil,
            host: "printer.local", sourceEndpoint: "192.0.2.9:5353", destinationEndpoint: "224.0.0.251:5353",
            protocolStack: [.udp, .mdns], status: .ok, latencyMilliseconds: nil, bytesUp: 1, bytesDown: 0
        )
        mdns.dnsQuery = "printer.local"
        mdns.dnsAnswers = ["192.0.2.9"]
        #expect(DNSLookups.rows(sessions: [mdns], findings: [], responseTimes: []).isEmpty)
    }

    // MARK: Private

    private static func dns(
        client: Bool, port: UInt16, id: UInt16, flags: UInt16, name: String, answers: [String] = []
    )
        -> [UInt8]
    {
        let payload = FollowDatagramReaderTests.dnsMessage(id: id, flags: flags, name: name, answers: answers)
        return PacketBuilder.ethernetIPv4(
            proto: 17,
            src: client ? "10.0.0.5" : "10.0.0.1",
            dst: client ? "10.0.0.1" : "10.0.0.5",
            payload: PacketBuilder.udp(srcPort: client ? port : 53, dstPort: client ? 53 : port, payload: payload)
        )
    }
}
