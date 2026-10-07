import Foundation
import Testing
@testable import Tracexy

/// HTTP requests by method, responses by status and DHCP messages by
/// type, counted per session in the fold and rolled up for Statistics ▸ Message Counts;
/// each leaf's Session Expression term finds exactly those sessions.
@MainActor
struct ApplicationMessageCountsTests {
    // MARK: Internal

    @Test
    func httpMessagesAreCountedPerSessionAndRolledUp() async throws {
        let environment = ProjectIsolationEnvironment(name: "message-counts")
        defer { environment.tearDown() }
        let directory = environment.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("http.pcap")
        let getA = "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n"
        let okHead = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"
        let getB = "GET /b HTTP/1.1\r\nHost: example.test\r\n\r\n"
        let notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        let post = "POST /c HTTP/1.1\r\nHost: other.test\r\nContent-Length: 0\r\n\r\n"
        let frames: [(bytes: [UInt8], seconds: Double)] = [
            (Self.segment(client: true, port: 51_000, seq: 1_000, getA), 0.000),
            (Self.segment(client: false, port: 51_000, seq: 5_000, okHead), 0.020),
            (Self.segment(client: false, port: 51_000, seq: 5_000 + UInt32(okHead.utf8.count), "lo"), 0.021),
            (Self.segment(client: true, port: 51_000, seq: 1_000 + UInt32(getA.utf8.count), getB), 0.100),
            (
                Self.segment(client: false, port: 51_000, seq: 5_002 + UInt32(okHead.utf8.count), notFound),
                0.150
            ),
            (Self.segment(client: true, port: 51_001, seq: 9_000, post), 0.200),
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
        coordinator.openSavedCapture(SavedCapture(url: url, name: "http", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()

        let sessions = coordinator.visibleSessions
        #expect(sessions.count == 2)
        let roots = ApplicationMessageCounts.roots(of: sessions)
        #expect(roots.map(\.title) == ["HTTP requests", "HTTP responses"])
        let requests = try #require(roots.first)
        #expect(requests.messageCount == 3)
        #expect(requests.sessionCount == 2)
        #expect(requests.children?.map(\.title) == ["GET", "POST"])
        #expect(requests.children?.map(\.messageCount) == [2, 1])
        let responses = try #require(roots.last)
        #expect(responses.messageCount == 2)
        #expect(responses.children?.map(\.title) == ["2xx Success", "4xx Client Error"])
        #expect(responses.children?.last?.children?.map(\.title) == ["404 Not Found"])
        #expect(responses.children?.last?.term == "http.status in 400..499")

        // Each leaf's term finds exactly the sessions it counts.
        coordinator.applySessionExpression("http.method == POST")
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        #expect(coordinator.visibleSessions.count == 1)
        coordinator.applySessionExpression("http.status in 400..499 and http.method == GET")
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        #expect(coordinator.visibleSessions.count == 1)
        coordinator.applySessionExpression("http.status == 500")
        await coordinator.waitForInvestigationQuery(in: coordinator.activeWorkspace)
        #expect(coordinator.visibleSessions.isEmpty)
    }

    @Test
    func tallyParsesAndBounds() {
        #expect(SessionMessageTally.httpMethod(fromRequestLine: "GET / HTTP/1.1") == "GET")
        #expect(SessionMessageTally.httpMethod(fromRequestLine: "get / HTTP/1.1") == nil)
        #expect(SessionMessageTally.httpMethod(fromRequestLine: "GET") == nil)
        #expect(SessionMessageTally.httpStatus(fromStatus: "404 Not Found") == 404)
        #expect(SessionMessageTally.httpStatus(fromStatus: "99") == nil)
        #expect(SessionMessageTally.httpStatus(fromStatus: "700 Weird") == nil)
        #expect(SessionMessageTally.dhcpMessageKind(fromSummary: "DHCP Offer 192.0.2.7") == "Offer")
        #expect(SessionMessageTally.dhcpMessageKind(fromSummary: "DHCP type 13") == "Type 13")
        #expect(SessionMessageTally.dhcpMessageKind(fromSummary: "BOOTP") == nil)

        var tally = SessionMessageTally()
        for index in 0 ..< SessionMessageTally.keyCap + 3 {
            var packet = DecodedPacket(timestamp: nil, originalLength: 0)
            packet.layers = [DecodedLayer(
                proto: .http, title: "Hypertext Transfer Protocol",
                fields: [.init(name: "Request", value: "M\(String(repeating: "X", count: index % 15)) / HTTP/1.1")]
            )]
            tally.record(packet)
        }
        #expect(tally.httpRequests.count <= SessionMessageTally.keyCap)
        #expect(tally.httpRequestCount + tally.omitted == SessionMessageTally.keyCap + 3)

        var dhcp = DecodedPacket(timestamp: nil, originalLength: 0)
        dhcp.layers = [DecodedLayer(
            proto: .dhcp,
            title: "Dynamic Host Configuration Protocol",
            summary: "DHCP Discover"
        )]
        var dhcpTally = SessionMessageTally()
        dhcpTally.record(dhcp)
        dhcpTally.record(dhcp)
        #expect(dhcpTally.dhcpMessages == ["Discover": 2])
        let roots = ApplicationMessageCounts.roots(of: [Self.session(with: dhcpTally)])
        #expect(roots.map(\.title) == ["DHCP messages"])
        #expect(roots.first?.children?.first?.term == "dhcp.message == Discover")
    }

    @Test
    func parserAcceptsTheMessageFields() throws {
        let parser = SessionQueryParser()
        #expect(try parser.parse("http.method == GET") == .leaf(.httpMethodEquals("GET")))
        #expect(try parser.parse("http.status == 404") == .leaf(.httpStatusInRange(lower: 404, upper: 404)))
        #expect(try parser.parse("http.status in 400..499") == .leaf(.httpStatusInRange(lower: 400, upper: 499)))
        #expect(try parser.parse("dhcp.message in {Discover, Offer}") == .any([
            .leaf(.dhcpMessageEquals("Discover")), .leaf(.dhcpMessageEquals("Offer")),
        ]))
        #expect(throws: SessionQueryParseError.self) { try parser.parse("http.status == 900") }
        #expect(throws: SessionQueryParseError.self) { try parser.parse("http.status in 499..400") }
        #expect(throws: SessionQueryParseError.self) { try parser.parse("http.method in GET") }
        #expect(SessionExpressionCompletion.suggestions(for: "http.method == ").candidates.contains("GET"))
    }

    // MARK: Private

    private static func session(with tally: SessionMessageTally) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: nil, duration: nil, processName: nil, host: "dhcp",
            sourceEndpoint: "—", destinationEndpoint: "—", protocolStack: [.udp, .dhcp], status: .ok,
            latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0, messageTally: tally
        )
    }

    private static func segment(client: Bool, port: UInt16, seq: UInt32, _ text: String) -> [UInt8] {
        let (sourcePort, destinationPort) = client ? (port, UInt16(80)) : (UInt16(80), port)
        let (source, destination): ([UInt8], [UInt8]) = client
            ? ([192, 0, 2, 10], [198, 51, 100, 80])
            : ([198, 51, 100, 80], [192, 0, 2, 10])
        var tcp: [UInt8] = []
        tcp += bigEndian(sourcePort) + bigEndian(destinationPort)
        tcp += bigEndian(seq) + bigEndian(UInt32(0))
        tcp += [0x50, 0x18] + bigEndian(UInt16(0xFFFF)) + [0, 0, 0, 0]
        tcp += Array(text.utf8)
        var ip: [UInt8] = [0x45, 0] + bigEndian(UInt16(20 + tcp.count)) + [0, 0, 0, 0, 64, 6, 0, 0]
        ip += source + destination
        return [UInt8](repeating: 2, count: 6) + [UInt8](repeating: 4, count: 6) + [0x08, 0x00] + ip + tcp
    }

    private static func bigEndian(_ value: some FixedWidthInteger) -> [UInt8] {
        withUnsafeBytes(of: value.bigEndian, Array.init)
    }
}
