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

    @Test("A DNS answer still attributes a connection late in the 30-second window")
    func dnsCausalWindowSpansThirtySeconds() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        // 25 seconds after the answer — well beyond the identity window but still
        // inside the DNS causal window, which is deliberately the longer of the two.
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(25), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [dns, tcp])
        let activity = try #require(result.activities.first)

        #expect(activity.sessions.count == 2)
        #expect(activity.confidence == .causal)
        #expect(result.ungrouped.isEmpty)
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
        #expect(activity.confidence == .strong)
        #expect(!activity.evidence.contains {
            if case .dnsAnswerToConnection = $0 {
                true
            } else {
                false
            }
        })
    }

    @Test("Same process and name within the adjacency window still groups")
    func sameIdentityWithinWindowGroups() throws {
        let base = Date()
        let first = Self.session(
            host: "api.example.com", at: base, process: "MyApp", stack: [.tcp], sni: "api.example.com"
        )
        // Well inside the 2-second identity window.
        let second = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(1.5),
            process: "MyApp", stack: [.tls], sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [first, second])
        let activity = try #require(result.activities.first)

        #expect(activity.sessions.count == 2)
        #expect(result.ungrouped.isEmpty)
    }

    @Test("Same process and name beyond the adjacency window does not group")
    func sameIdentityBeyondWindowDoesNotGroup() {
        let base = Date()
        let first = Self.session(
            host: "api.example.com", at: base, process: "MyApp", stack: [.tcp], sni: "api.example.com"
        )
        // Three seconds apart: outside the identity window, so these are two
        // separate actions even though process and name agree.
        let second = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(3),
            process: "MyApp", stack: [.tls], sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [first, second])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
    }

    @Test("Missing process attribution is never second-pass grouped")
    func missingProcessNeverGroups() {
        let base = Date()
        // Same name, adjacent in time, but no observed process on either session.
        // An absent process is not a matching process.
        let first = Self.session(
            host: "api.example.com", at: base, process: nil, stack: [.tcp], sni: "api.example.com"
        )
        let second = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.2),
            process: nil, stack: [.tls], sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [first, second])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
    }

    @Test("Whitespace-only process attribution is never second-pass grouped")
    func blankProcessNeverGroups() {
        let base = Date()
        let first = Self.session(
            host: "api.example.com", at: base, process: "   ", stack: [.tcp], sni: "api.example.com"
        )
        let second = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.2),
            process: "\t", stack: [.tls], sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [first, second])

        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
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
        let span = try #require(activity.duration)
        #expect(abs(span - 0.29) < 0.005)
    }

    @Test("Rebuilding from the same sessions yields the same activity id")
    func activityIdIsStableAcrossRebuilds() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.02), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        // Same session values (crucially the same ids, as the store hands back on
        // every capture tick) must produce the identical action row identity.
        let first = try #require(ActivityBuilder.build(from: [dns, tcp]).activities.first)
        let second = try #require(ActivityBuilder.build(from: [dns, tcp]).activities.first)

        #expect(first.id == second.id)
    }

    @Test("Adding a later member preserves the activity id while the anchor remains")
    func activityIdSurvivesLaterMember() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.02), process: "MyApp",
            stack: [.tcp], destination: "93.184.16.34:443", sni: "api.example.com"
        )
        let tls = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.05), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let before = try #require(ActivityBuilder.build(from: [dns, tcp]).activities.first)
        // The oldest member (the DNS lookup) is unchanged, so the action keeps its
        // row identity even though a third session joined it.
        let after = try #require(ActivityBuilder.build(from: [dns, tcp, tls]).activities.first)

        #expect(after.sessions.count == 3)
        #expect(before.id == after.id)
    }

    @Test("An activity id never collides with one of its child session ids")
    func activityIdDoesNotCollideWithChildren() throws {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.02), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let activity = try #require(ActivityBuilder.build(from: [dns, tcp]).activities.first)

        // Action roots and disclosure children coexist in one Table hierarchy, so
        // the root id must differ from every member — including the anchor it is
        // derived from.
        #expect(!activity.sessions.contains { $0.id == activity.id })
    }

    @Test("An explicitly supplied id is preserved, not recomputed")
    func explicitIdIsPreserved() {
        let base = Date()
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let tcp = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.02), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443"
        )
        let pinned = UUID()

        // The coordinator recreates filtered survivor activities with the original
        // id; that override must win over the derived identity.
        let activity = Activity(id: pinned, sessions: [dns, tcp], evidence: [])

        #expect(activity.id == pinned)
    }

    @Test("A session with no capture time is never correlated into an action")
    func untimedSessionsAreNeverGrouped() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let dns = Self.session(
            host: "dns.google", at: base, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        // The connection that dialled the answered address, but with no capture
        // time: no causal window can place it after the answer.
        let untimedFollower = Self.session(
            host: "api.example.com", at: nil, duration: nil, process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [dns, untimedFollower])
        #expect(result.activities.isEmpty)
        #expect(Set(result.ungrouped.map(\.id)) == Set([dns.id, untimedFollower.id]))
        // Ungrouped is not "lost": both sessions are reported, unknown-time last.
        #expect(result.ungrouped.last?.startTime == nil)
    }

    @Test("An untimed DNS answer cannot anchor a causal window")
    func untimedDNSAnswerAnchorsNothing() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let dns = Self.session(
            host: "dns.google", at: nil, duration: nil, process: "MyApp",
            stack: [.udp, .dns], dnsQuery: "api.example.com", dnsAnswers: ["93.184.16.34"]
        )
        let follower = Self.session(
            host: "api.example.com", at: base.addingTimeInterval(0.01), process: "MyApp",
            stack: [.tcp, .tls], destination: "93.184.16.34:443", sni: "api.example.com"
        )

        let result = ActivityBuilder.build(from: [dns, follower])
        #expect(result.activities.isEmpty)
        #expect(result.ungrouped.count == 2)
    }

    @Test("Mixed known and unknown members do not imply a complete group time")
    func mixedGroupTiming() {
        let known = Self.session(host: "example.test", at: Date(timeIntervalSince1970: 0), stack: [.tcp])
        let unknown = Self.session(host: "example.test", at: nil, duration: nil, stack: [.tcp])
        let activity = Activity(sessions: [known, unknown], evidence: [])
        #expect(activity.startTime == nil)
        #expect(activity.duration == nil)
        #expect(SessionGroup(kind: .host, key: "example.test", sessions: [known, unknown]).startTime == nil)
        #expect(Activity(sessions: [known], evidence: []).startTime == Date(timeIntervalSince1970: 0))
    }

    // MARK: Private

    private static func session(
        host: String,
        at start: Date?,
        duration: TimeInterval? = 0.05,
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
            latencyMilliseconds: duration.map { $0 * 1_000 },
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
