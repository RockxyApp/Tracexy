import Foundation
import Testing
@testable import Tracexy

// MARK: - ResolvedAddressesTests

/// Resolved Addresses: every name DNS and mDNS answers gave an address, led back to
/// the earliest session that carried it, with conflicting names flagged, the user's
/// own names beside them, and routes into the main window.
@MainActor
struct ResolvedAddressesTests {
    // MARK: Internal

    @Test
    func rowsNameEachAddressFromTheEarliestAnswer() throws {
        let early = Self.dnsSession(
            "a",
            query: "api.example.test",
            answers: ["192.0.2.10", "CNAME edge.test"],
            ordinal: 3
        )
        let late = Self.dnsSession("b", query: "api.example.test", answers: ["192.0.2.10"], ordinal: 9)
        let other = Self.dnsSession("c", query: "cdn.example.test", answers: ["192.0.2.10", "2001:db8::1"], ordinal: 5)
        let bonjour = Self.dnsSession("d", query: "printer.local", answers: ["192.0.2.9"], ordinal: 7, mdns: true)
        let rows = ResolvedAddresses.rows(
            sessions: [late, other, early, bonjour], namedAddresses: ["192.0.2.200": "Lab router"]
        )
        // IPv4 in numeric order before IPv6; CNAME targets are not addresses.
        #expect(rows.map(\.address) == ["192.0.2.9", "192.0.2.10", "192.0.2.10", "192.0.2.200", "2001:db8::1"])
        let api = try #require(rows.first { $0.name == "api.example.test" })
        #expect(api.sessionID == early.id)
        #expect(api.answerCount == 2)
        #expect(api.hasOtherNames)
        #expect(api.source == .dns)
        #expect(rows.first { $0.address == "192.0.2.9" }?.source == .mdns)
        #expect(rows.first { $0.address == "192.0.2.9" }?.hasOtherNames == false)
        let named = try #require(rows.first { $0.source == .named })
        #expect(named.name == "Lab router")
        #expect(named.sessionID == nil)
        #expect(ResolvedAddressSource.named.label == "Named by you")
    }

    @Test
    func filterMatchesAddressOrName() {
        let row = ResolvedAddressRow(
            address: "192.0.2.10", name: "api.example.test", source: .dns, sessionID: nil,
            answerCount: 1, hasOtherNames: false
        )
        #expect(ResolvedAddresses.matches(row, filter: ""))
        #expect(ResolvedAddresses.matches(row, filter: "0.2.1"))
        #expect(ResolvedAddresses.matches(row, filter: "EXAMPLE"))
        #expect(!ResolvedAddresses.matches(row, filter: "cdn"))
    }

    @Test
    func coordinatorRowsAndRoutesFollowTheCapture() async throws {
        let isolation = ProjectIsolationEnvironment(name: "resolved-addresses")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("names.pcap")
        let frames = [
            PacketBuilder.dnsQueryFrame(name: "api.example.test", src: "10.0.0.5", dst: "10.0.0.1"),
            PacketBuilder.dnsResponseFrame(
                name: "api.example.test", answers: ["192.0.2.10"], src: "10.0.0.1", dst: "10.0.0.5"
            ),
            PacketBuilder.tcpSynFrame(src: "10.0.0.5", dst: "192.0.2.10", srcPort: 50_000, dstPort: 443),
            PacketBuilder.tcpSynFrame(src: "10.0.0.5", dst: "198.51.100.7", srcPort: 50_001, dstPort: 443),
        ].enumerated().map { index, bytes in
            CapturedFrame(
                bytes: bytes,
                timestamp: Date(timeIntervalSince1970: 1_000 + Double(index)),
                originalLength: bytes.count
            )
        }
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "names", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let row = try #require(coordinator.resolvedAddressRows.first { $0.address == "192.0.2.10" })
        #expect(row.name == "api.example.test")
        let dnsID = try #require(row.sessionID)

        // Hidden by a scope: the answering session is revealed by a recorded drill-in.
        coordinator.selectIP("198.51.100.7")
        #expect(!coordinator.visibleSessions.contains { $0.id == dnsID })
        coordinator.showSessionThatResolved(dnsID)
        #expect(coordinator.visibleSessions.contains { $0.id == dnsID })
        #expect(coordinator.activeWorkspace.selectedSessionID == dnsID)
        #expect(coordinator.canReturnToPreviousSessionScope)

        // Show Sessions narrows to every session to or from the address.
        coordinator.selectIP(row.address)
        #expect(coordinator.visibleSessions.contains { $0.destinationEndpoint.hasPrefix("192.0.2.10") })
    }

    // MARK: Private

    private static func dnsSession(
        _ seed: String, query: String, answers: [String], ordinal: UInt64, mdns: Bool = false
    )
        -> SessionSummary
    {
        var session = SessionSummary(
            id: SessionBuilder.stableID("resolved-\(seed)"),
            startTime: nil,
            duration: nil,
            processName: nil,
            host: query,
            sourceEndpoint: "10.0.0.5:5\(ordinal)",
            destinationEndpoint: mdns ? "224.0.0.251:5353" : "10.0.0.1:53",
            protocolStack: [.udp, mdns ? .mdns : .dns],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: 60,
            bytesDown: 90
        )
        session.dnsQuery = query
        session.dnsAnswers = answers
        session.firstCaptureOrdinal = ordinal
        return session
    }
}
