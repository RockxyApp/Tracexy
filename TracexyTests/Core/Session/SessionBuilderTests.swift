//
//  SessionBuilderTests.swift
//  TracexyTests
//
//  End-to-end: real sample bytes → decode → real sessions. Asserts the UI is
//  fed genuinely-decoded data (host resolution, status, latency), not mocks.
//

import Foundation
import Testing
@testable import Tracexy

@Suite("SessionBuilder end-to-end")
struct SessionBuilderTests {
    // MARK: Internal

    @Test
    func producesRealSessions() {
        let result = sessions()
        #expect(result.count >= 6)
        #expect(result.allSatisfy { $0.totalBytes > 0 })
    }

    @Test
    func tlsSessionResolvesHostFromSNI() {
        guard let api = sessions().first(where: { $0.host == "api.example.com" && $0.protocolStack.contains(.tls) }) else {
            Issue.record("no TLS session for api.example.com")
            return
        }
        #expect(api.sni == "api.example.com")
        #expect(api.protocolStack.contains(.tls))
        #expect(!api.decodedLayers.isEmpty)
        // Layer tree carries the real Ethernet→IP→TCP→TLS decode.
        #expect(api.decodedLayers.contains { $0.title == "Transport Layer Security" })
    }

    @Test
    func resetConnectionIsError() {
        let auth = sessions().first { $0.host == "auth.example.com" }
        #expect(auth?.status == .error)
    }

    @Test
    func incompleteHandshakeIsWarning() {
        let syn = sessions().first { $0.host == "203.0.113.9" }
        #expect(syn?.status == .warning)
    }

    @Test
    func dnsSessionHasMeasuredLatency() {
        let dns = sessions().first { $0.protocolStack.contains(.dns) && $0.latencyMilliseconds != nil }
        #expect(dns != nil)
        #expect((dns?.latencyMilliseconds ?? 0) > 0)
    }

    @Test
    func quicSessionIsDecoded() {
        #expect(sessions().contains { $0.protocolStack.contains(.quic) })
    }

    @Test
    func httpSessionResolvesHostFromHeader() {
        #expect(sessions().contains { $0.host == "registry.npmjs.org" && $0.protocolStack.contains(.http) })
    }

    @Test
    func sessionIDsAreStableAcrossRebuilds() {
        // The same 5-tuple must keep the same id across rebuilds, so the table
        // selection survives when new packets arrive.
        let frames = SampleCapture.frames(now: Date())
        let first = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let second = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(!first.isEmpty)
        #expect(first.map(\.id) == second.map(\.id))
    }

    @Test
    func outputIsChronologicalOldestFirst() {
        // Frames arrive in capture order; the session list must read oldest→newest
        // so the live table appends at the tail instead of shifting downward.
        let result = SessionBuilder.build(from: TwoSessions.batchOne, linkType: LinkType.ethernet)
        #expect(result.count == 2)
        let starts = result.map(\.startTime)
        #expect(starts == starts.sorted())
        #expect(result.first?.sni == "one.example")
        #expect(result.last?.sni == "two.example")
    }

    @Test
    func rebuildKeepsPriorIDsAsPrefixAndAppendsNew() {
        // A later batch that extends an existing five-tuple and introduces a new
        // one must keep the prior ids in the same relative order (a prefix) and
        // place the genuinely new session at the tail.
        let first = SessionBuilder.build(from: TwoSessions.batchOne, linkType: LinkType.ethernet)
        let second = SessionBuilder.build(from: TwoSessions.batchTwo, linkType: LinkType.ethernet)

        let priorIDs = first.map(\.id)
        #expect(priorIDs.count == 2)
        #expect(second.count == 3)
        // Prior ids are an exact prefix of the rebuilt result…
        #expect(Array(second.map(\.id).prefix(2)) == priorIDs)
        // …and the new session lands at the last index.
        #expect(second.last?.sni == "three.example")
        #expect(!priorIDs.contains(second[2].id))
    }

    @Test
    func existingSessionSummaryUpdatesOnRebuild() {
        // Extending an existing five-tuple with a later packet must update its
        // mutable summary in place rather than freezing the first-seen values.
        let first = SessionBuilder.build(from: TwoSessions.batchOne, linkType: LinkType.ethernet)
        let second = SessionBuilder.build(from: TwoSessions.batchTwo, linkType: LinkType.ethernet)

        guard let before = first.first(where: { $0.sni == "one.example" }),
              let after = second.first(where: { $0.sni == "one.example" }) else
        {
            Issue.record("missing one.example session")
            return
        }
        #expect(before.id == after.id)
        // A second packet joined the session: more bytes and a real duration.
        #expect(after.totalBytes > before.totalBytes)
        #expect(before.duration == 0)
        #expect(after.duration > 0)
    }

    // MARK: Private

    /// Two live five-tuples with controlled timestamps, plus a second batch that
    /// extends the first session and introduces a third — enough to prove
    /// chronological ordering and incremental prefix/append stability.
    private enum TwoSessions {
        // MARK: Internal

        static let client = "10.0.0.5"
        static let base = Date(timeIntervalSince1970: 1_700_000_000)

        /// Session one (oldest) then session two.
        static let batchOne: [CapturedFrame] = [
            frame(
                PacketBuilder.tlsClientHelloFrame(
                    sni: "one.example", src: client, dst: "203.0.113.1", srcPort: 40_001
                ),
                at: base
            ),
            frame(
                PacketBuilder.tlsClientHelloFrame(
                    sni: "two.example", src: client, dst: "203.0.113.2", srcPort: 40_002
                ),
                at: base.addingTimeInterval(1)
            ),
        ]

        /// The same two frames, then a later packet for session one (same
        /// five-tuple) and a brand-new session three at the tail.
        static let batchTwo: [CapturedFrame] = batchOne + [
            frame(
                PacketBuilder.tlsClientHelloFrame(
                    sni: "one.example", src: client, dst: "203.0.113.1", srcPort: 40_001
                ),
                at: base.addingTimeInterval(2)
            ),
            frame(
                PacketBuilder.tlsClientHelloFrame(
                    sni: "three.example", src: client, dst: "203.0.113.3", srcPort: 40_003
                ),
                at: base.addingTimeInterval(3)
            ),
        ]

        // MARK: Private

        private static func frame(_ bytes: [UInt8], at timestamp: Date) -> CapturedFrame {
            CapturedFrame(bytes: bytes, timestamp: timestamp, originalLength: bytes.count)
        }
    }

    private func sessions() -> [SessionSummary] {
        SessionBuilder.build(from: SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
    }
}
