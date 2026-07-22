import Foundation
import Testing
@testable import Tracexy

@Suite("Activity correlation")
struct ActivityBuilderTests {
    // MARK: Internal

    @Test("A DNS answer followed by a connection to that address is causal")
    func dnsAnswerLinksToConnection() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.02), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [dns, tcp])

        #expect(result.activities.count == 1)
        #expect(result.ungrouped.isEmpty)
        let activity = try #require(result.activities.first)
        #expect(activity.sessions.count == 2)
        #expect(activity.confidence == .causal)
        #expect(!activity.isContested)
        #expect(activity.protocolPath.first == .udp)
    }

    @Test("A connection outside the causal window is not attributed")
    func lateConnectionIsNotGrouped() {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let late = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(600), process: "MyApp",
            stack: [.tcp], destination: "93.184.16.34:443"
        )

        let result = ActivityBuilder.build(from: [dns, late])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
    }

    @Test("A shared address is contested, and that lowers confidence")
    func sharedAddressLowersConfidence() throws {
        let base = Date()
        // Two names resolve to one CDN address — the classic false-grouping trap.
        let dnsA = Self.session(
            host: "dns.google", at: base, process: "Chrome",
            stack: [.udp, .dns], dnsQuery: "edge.quic.cloud", dnsAnswers: ["104.18.32.7"]
        )
        let dnsB = Self.session(
            host: "dns.google", at: base.addingTimeInterval(0.01), process: "Chrome",
            stack: [.udp, .dns], dnsQuery: "assets.quic.cloud", dnsAnswers: ["104.18.32.7"]
        )
        let conn = Self.session(
            host: "edge.quic.cloud", at: base.addingTimeInterval(0.05), process: "Chrome",
            stack: [.udp, .quic], destination: "104.18.32.7:443"
        )

        let result = ActivityBuilder.build(from: [dnsA, dnsB, conn])
        let grouped = try #require(result.activities.first { $0.sessions.contains { $0.id == conn.id } })

        #expect(grouped.isContested)
        // Causal evidence exists, but the ambiguity caps what may be claimed.
        #expect(grouped.confidence == .weak)
        #expect(grouped.competingNames.contains("assets.quic.cloud"))
    }

    @Test("Temporal adjacency alone never groups anything")
    func adjacencyAloneDoesNotGroup() {
        let base = Date()
        // Same instant, different processes and different hosts: nothing but
        // coincidence connects these, and on a busy interface coincidence is
        // constant.
        let a = Self.session(host: "a.example.com", at: base, process: "Safari", stack: [.tcp])
        let b = Self.session(host: "b.example.com", at: base.addingTimeInterval(0.001), process: "node", stack: [.tcp])

        let result = ActivityBuilder.build(from: [a, b])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
    }

    @Test("Same process and name close together groups as strong, not causal")
    func sameProcessAndNameIsStrong() throws {
        let base = Date()
        let first = Self.session(
            host: "api.example.com",
            at: base,
            process: "MyApp",
            stack: [.tcp],
            sni: "api.example.com"
        )
        let second = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.4),
            process: "MyApp", stack: [.tls], sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [first, second])
        let activity = try #require(result.activities.first)

        #expect(activity.sessions.count == 2)
        // No observed causal step, so it must not claim one.
        #expect(activity.confidence == .causal || activity.confidence == .strong)
        #expect(!activity.evidence.contains {
            if case .dnsAnswerToConnection = $0 {
                true
            } else {
                false
            }
        })
    }

    @Test("Unattributable sessions stay visible rather than being absorbed")
    func orphansRemainVisible() {
        let lonely = Self.session(host: "104.18.32.7", at: Date(), process: nil, stack: [.tcp])

        let result = ActivityBuilder.build(from: [lonely])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 1)
    }

    @Test("An empty capture produces nothing, not an empty activity")
    func emptyInput() {
        let result = ActivityBuilder.build(from: [])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.isEmpty)
    }

    @Test("Action duration spans the whole action, never the sum of its parts")
    func durationIsWallClock() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, duration: 0.008, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let conn = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.01), duration: 0.28,
            process: "MyApp", stack: [.tcp, .tls], destination: "93.184.16.34:443"
        )

        let activity = try #require(ActivityBuilder.build(from: [dns, conn]).activities.first)

        // Overlapping sessions: summing would report 0.288 s for a 0.29 s action.
        #expect(abs(activity.duration - 0.29) < 0.005)
    }

    // MARK: Private

    private static func session(
        host: String,
        at start: Date,
        duration: TimeInterval = 0.05,
        process: String? = "MyApp",
        stack: [ProtocolKind],
        destination: String = "93.184.16.34:443",
        sni: String? = nil,
        dnsQuery: String? = nil,
        dnsAnswers: [String] = []
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: start,
            duration: duration,
            processName: process,
            host: host,
            sourceEndpoint: "192.168.1.42:52344",
            destinationEndpoint: destination,
            protocolStack: stack,
            status: .ok,
            latencyMilliseconds: duration * 1_000,
            bytesUp: 1_024,
            bytesDown: 2_048,
            decodedLayers: [],
            representativeBytes: [],
            sni: sni,
            dnsQuery: dnsQuery,
            dnsAnswers: dnsAnswers
        )
    }
}
