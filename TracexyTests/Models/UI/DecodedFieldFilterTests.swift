import Foundation
import Testing
@testable import Tracexy

/// Apply as Filter and Prepare as Filter from the decode tree turn a field into
/// the Session Expression term that finds its sessions, joined to the editor's
/// expression in Wireshark's six ways; a field with no session-level term offers none.
@MainActor
struct DecodedFieldFilterTests {
    @Test
    func fieldsBecomeTermsThatParse() {
        let term = DecodedFieldFilter.term(proto:field:value:)
        #expect(term(.ethernet, "Source", "04:04:04:04:04:04") == "mac == 04:04:04:04:04:04")
        #expect(term(.ipv4, "Destination", "198.51.100.80") == "ip == 198.51.100.80")
        #expect(term(.ipv6, "Source", "2001:db8::1") == "ip == 2001:db8::1")
        #expect(term(.tcp, "Destination Port", "443") == "port == 443")
        #expect(term(.udp, "Source Port", "53") == "port == 53")
        #expect(term(.http, "Request", "GET /a HTTP/1.1") == "http.method == GET")
        #expect(term(.http, "Status", "404 Not Found") == "http.status == 404")
        #expect(term(.http, "Host", "example.test:8080") == "host matches \"example.test\"")
        #expect(term(.tls, "server_name", "www.example.test") == "host matches \"www.example.test\"")
        #expect(term(.dns, "Query", "web.example.test") == "host matches \"web.example.test\"")
        #expect(term(.dhcp, "Message type", "Offer") == "dhcp.message == Offer")
        #expect(DecodedFieldFilter.term(for: .tls) == "tls")

        // No session-level term: offer nothing rather than a filter that cannot parse.
        #expect(term(.tcp, "Window", "65535") == nil)
        #expect(term(.ipv4, "Source", "not an address") == nil)
        #expect(term(.ethernet, "Type", "IPv4 (0x0800)") == nil)
        #expect(term(.dhcp, "Message type", "type 13") == nil)
    }

    @Test
    func combinationsJoinAsWiresharkDoes() throws {
        let term = "port == 53"
        let existing = "tcp or udp"
        let expected: [DecodedFieldFilter.Combination: String] = [
            .selected: "port == 53",
            .notSelected: "not (port == 53)",
            .andSelected: "(tcp or udp) and port == 53",
            .orSelected: "tcp or udp or port == 53",
            .andNotSelected: "(tcp or udp) and not (port == 53)",
            .orNotSelected: "tcp or udp or not (port == 53)",
        ]
        for combination in DecodedFieldFilter.Combination.allCases {
            let expression = combination.combine(existing, term)
            #expect(expression == expected[combination])
            _ = try SessionQueryParser().parse(expression)
        }
        #expect(DecodedFieldFilter.Combination.andSelected.combine("  ", term) == term)
        #expect(DecodedFieldFilter.Combination.orNotSelected.combine("", "tls") == "not tls")
    }

    @Test
    func applyNarrowsAndPrepareOpensTheEditor() async throws {
        let isolation = ProjectIsolationEnvironment(name: "field-filter")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("field-filter.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "field-filter", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        let workspace = coordinator.activeWorkspace
        let tcp = try #require(coordinator.sessions.first { $0.protocolStack.contains(.tcp) })
        let port = try #require(tcp.destinationEndpointValue?.port)

        coordinator.filterSessions(with: "port == \(port)", combination: .selected, applying: true)
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.acceptedInvestigationDraft?.expression == "port == \(port)")
        #expect(workspace.investigationMatchedSessionIDs.contains(tcp.id))
        #expect(workspace.sidebarSelection == .sessions)

        coordinator.filterSessions(with: "tcp", combination: .andNotSelected, applying: false)
        #expect(workspace.investigationDraft.expression == "port == \(port) and not tcp")
        #expect(workspace.isInvestigationEditorPresented)
        // Prepared, not applied: the accepted expression is unchanged.
        #expect(workspace.acceptedInvestigationDraft?.expression == "port == \(port)")
    }
}
