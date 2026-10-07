import Foundation
import Testing
@testable import Tracexy

// MARK: - DisplayFilterTranslatorTests

/// Wireshark display filters from a `dfilters` file become Session Expressions
/// where they have a session meaning; everything else is refused with its reason.
struct DisplayFilterTranslatorTests {
    @Test(arguments: [
        ("ip.addr == 192.0.2.1", "ip == 192.0.2.1"),
        ("ip.addr eq 10.0.0.0/8", "ip in 10.0.0.0/8"),
        ("ipv6.dst == 2001:db8::1", "destination.ip == 2001:db8::1"),
        ("tcp.port == 443 && ip.src == 192.0.2.10", "(tcp and port == 443) and source.ip == 192.0.2.10"),
        ("!(arp || dns)", "not (arp or dns)"),
        ("udp.dstport >= 1024", "(udp and destination.port in 1024..65535)"),
        ("tcp.port in {80 443 8000..8080}", "(tcp and port in {80, 443, 8000..8080})"),
        ("ip.addr != 192.0.2.1", "not ip == 192.0.2.1"),
        ("ssl", "tls"),
        ("bootp or ntp", "dhcp or ntp"),
        ("http.request.method == \"POST\"", "http.method == POST"),
        ("http.response.code >= 400", "http.status in 400..599"),
        ("http.host contains \"example\"", "host contains \"example\""),
        ("tls.handshake.extensions_server_name == \"api.example.com\"", "host matches \"api.example.com\""),
    ])
    func translates(_ filter: String, _ expected: String) {
        #expect(DisplayFilterTranslator.translate(filter) == .translated(expected, approximate: false))
    }

    @Test(arguments: [
        ("tcp.analysis.retransmission", "finding == retransmission"),
        ("dns.flags.rcode == 3", "finding == dnsNameError"),
        ("tcp.flags.reset == 1", "finding == reset"),
        ("icmp.type == 3", "finding in {icmpUnreachable, icmpReportedUnreachable}"),
        ("tcp and tcp.analysis.zero_window", "tcp and finding == zeroWindow"),
    ])
    func findingsAreMarkedApproximate(_ filter: String, _ expected: String) {
        #expect(DisplayFilterTranslator.translate(filter) == .translated(expected, approximate: true))
    }

    @Test(arguments: [
        "frame.len > 1000",
        "eth.addr == 00:11:22:33",
        "eth.addr > 00:11:22:33:44:55",
        "tcp.window_size < 100",
        "http.host matches \"^api\"",
        "tcp.port == 99999",
        "ip.addr == 192.0.2.1 xor dns",
        "http.request.uri contains \"login\"",
        "tcp.port ==",
        "\"unterminated",
    ])
    func refusesWithAReason(_ filter: String) {
        guard case let .untranslatable(reason) = DisplayFilterTranslator.translate(filter) else {
            Issue.record("\(filter) should not translate")
            return
        }
        #expect(!reason.isEmpty)
    }
}

// MARK: - DisplayFilterImportTests

@MainActor
struct DisplayFilterImportTests {
    @Test
    func aDfiltersFileBecomesSavedExpressions() async throws {
        let environment = ProjectIsolationEnvironment(name: "dfilters-import")
        defer { environment.tearDown() }
        try FileManager.default.createDirectory(at: environment.root, withIntermediateDirectories: true)
        let url = environment.root.appendingPathComponent("dfilters")
        try """
        "Web" tcp.port == 443 || tcp.port == 80
        "Retransmissions" tcp.analysis.retransmission
        "Big frames" frame.len > 1400
        "No ARP" !arp
        """.write(to: url, atomically: true, encoding: .utf8)
        let coordinator = environment.makeCoordinator()
        await coordinator.hydrateProjectsOnLaunch()

        let result = try coordinator.importWiresharkDisplayFilters(from: url)
        #expect(result.imported.map(\.name) == ["Web", "Retransmissions", "No ARP"])
        #expect(result.imported.first?.expression == "(tcp and port == 443) or (tcp and port == 80)")
        #expect(result.imported[1].approximate)
        #expect(result.refused.map(\.name) == ["Big frames"])
        #expect(coordinator.expressionLibrary.saved.map(\.name).contains("No ARP"))
        #expect(result.summary.contains("Saved 3 of 4 display filters"))
        #expect(result.summary.contains("“Big frames”"))
    }
}
