import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Protocol Hierarchy: sessions counted once per prefix of their protocol
/// stack, bytes summed, leaves without children, largest first, and a row that
/// narrows the list to the sessions carrying its whole path.
@MainActor
struct ProtocolHierarchyTests {
    // MARK: Internal

    @Test
    func sessionsCountOncePerPrefix() throws {
        let sessions = [
            Self.session("a", [.tcp, .tls], bytes: 500),
            Self.session("b", [.tcp, .tls], bytes: 300),
            Self.session("c", [.tcp], bytes: 100),
            Self.session("d", [.udp, .dns], bytes: 50),
        ]
        let roots = ProtocolHierarchy.roots(of: sessions)
        #expect(roots.map(\.protocolKind) == [.tcp, .udp])
        let tcp = try #require(roots.first)
        #expect(tcp.sessionCount == 3)
        #expect(tcp.byteCount == 900)
        #expect(tcp.endingSessionCount == 1)
        let tls = try #require(tcp.children?.first)
        #expect(tls.path == [.tcp, .tls])
        #expect(tls.sessionCount == 2)
        #expect(tls.children == nil)
        #expect(roots.last?.children?.first?.id == "udp/dns")
        #expect(ProtocolHierarchy.roots(of: []).isEmpty)
    }

    @Test
    func tunnelledSessionsCountUnderTheirInnerProtocolsAndTheTunnel() throws {
        let roots = ProtocolHierarchy.roots(of: [
            Self.session("plain", [.tcp, .tls], bytes: 10),
            Self.session("inner", [.vxlan, .tcp, .tls], bytes: 20),
        ])
        let tcp = try #require(roots.first { $0.protocolKind == .tcp })
        #expect(tcp.sessionCount == 2)
        #expect(tcp.children?.first?.sessionCount == 2)
        let vxlan = try #require(roots.first { $0.protocolKind == .vxlan })
        #expect(vxlan.sessionCount == 1)
        #expect(vxlan.byteCount == 20)
        #expect(vxlan.children == nil)
    }

    @Test
    func aRowNarrowsToItsPathAsOneDrillIn() async throws {
        let environment = ProjectIsolationEnvironment(name: "protocol-hierarchy")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("conv.pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: ReplayCorpus.conversationCapturedFrames(), to: url)
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "conv", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let roots = ProtocolHierarchy.roots(of: coordinator.visibleSessions)
        let udp = try #require(roots.first { $0.protocolKind == .udp })
        let dns = try #require(udp.children?.first { $0.protocolKind == .dns })
        coordinator.showSessionsForProtocolPath(dns.path)
        #expect(coordinator.visibleSessions.count == dns.sessionCount)
        #expect(coordinator.visibleSessions
            .allSatisfy { $0.protocolStack.contains(.udp) && $0.protocolStack.contains(.dns) })
        #expect(coordinator.canReturnToPreviousSessionScope)
        #expect(coordinator.activeWorkspace.sessionScopeReturnStack.count == 1)
    }

    // MARK: Private

    private static func session(_ seed: String, _ stack: [ProtocolKind], bytes: Int) -> SessionSummary {
        SessionSummary(
            id: SessionBuilder.stableID("hierarchy-\(seed)"),
            startTime: nil,
            duration: nil,
            processName: nil,
            host: seed,
            sourceEndpoint: "10.0.0.5:5000",
            destinationEndpoint: "192.0.2.1:443",
            protocolStack: stack,
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: bytes,
            bytesDown: 0
        )
    }
}
