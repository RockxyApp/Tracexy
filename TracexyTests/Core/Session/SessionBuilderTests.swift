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

// MARK: - SessionBuilderTests

@Suite("SessionBuilder end-to-end")
struct SessionBuilderTests {
    // MARK: Internal

    @Test("A ClientHello split across TCP segments is reassembled into session metadata")
    func splitTLSClientHello() {
        let payload = PacketBuilder.tlsClientHello(sni: "split.example.com")
        let cut = 3
        let frames = [
            tcpFrame(payload: Array(payload[..<cut]), sequence: 1_000, timestamp: 1),
            tcpFrame(payload: Array(payload[cut...]), sequence: 1_000 + UInt32(cut), timestamp: 2),
        ]

        let session = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first
        #expect(session?.sni == "split.example.com")
        #expect(session?.host == "split.example.com")
        #expect(session?.protocolStack == [.tcp, .tls])
        #expect(session?.decodedLayers.first { $0.proto == .tls }?.byteRange == nil)
    }

    @Test("Out-of-order TCP segments drain deterministically before TLS classification")
    func outOfOrderTLSClientHello() {
        let payload = PacketBuilder.tlsClientHello(sni: "ordered.example.com")
        let firstEnd = 3
        let secondEnd = 18
        let frames = [
            tcpFrame(payload: Array(payload[..<firstEnd]), sequence: 4_000, timestamp: 1),
            tcpFrame(
                payload: Array(payload[secondEnd...]),
                sequence: 4_000 + UInt32(secondEnd),
                timestamp: 2
            ),
            tcpFrame(
                payload: Array(payload[firstEnd ..< secondEnd]),
                sequence: 4_000 + UInt32(firstEnd),
                timestamp: 3
            ),
        ]

        let session = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first
        #expect(session?.sni == "ordered.example.com")
        #expect(session?.protocolStack == [.tcp, .tls])
    }

    @Test("An HTTP header split across TCP segments retains its Host metadata")
    func splitHTTPRequest() {
        let payload = Array("GET /health HTTP/1.1\r\nHost: split-http.example\r\n\r\n".utf8)
        let cut = 2
        let frames = [
            tcpFrame(
                payload: Array(payload[..<cut]), sequence: 6_000, timestamp: 1,
                sourcePort: 51_000, destinationPort: 80
            ),
            tcpFrame(
                payload: Array(payload[cut...]), sequence: 6_000 + UInt32(cut), timestamp: 2,
                sourcePort: 51_000, destinationPort: 80
            ),
        ]

        let session = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first
        #expect(session?.host == "split-http.example")
        #expect(session?.protocolStack == [.tcp, .http])
        #expect(session?.decodedLayers.first { $0.proto == .http }?.byteRange == nil)
    }

    @Test("A length-prefixed DNS query split across TCP segments is reassembled")
    func splitTCPDNSQuery() {
        let dns = PacketBuilder.dnsQuery(name: "split-dns.example")
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let cut = 1
        let frames = [
            tcpFrame(
                payload: Array(payload[..<cut]), sequence: 8_000, timestamp: 1,
                sourcePort: 52_000, destinationPort: 53
            ),
            tcpFrame(
                payload: Array(payload[cut...]), sequence: 8_000 + UInt32(cut), timestamp: 2,
                sourcePort: 52_000, destinationPort: 53
            ),
        ]

        let session = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first
        #expect(session?.dnsQuery == "split-dns.example")
        #expect(session?.host == "split-dns.example")
        #expect(session?.protocolStack == [.tcp, .dns])
        #expect(session?.decodedLayers.first { $0.proto == .dns }?.byteRange == nil)
    }

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
    func bareSynIsVisibleButNotWarned() {
        // A SYN with no response is a real session and must stay visible, but the
        // absence of an application protocol (or any reply) is not evidence of a
        // problem — so it stays `.ok` rather than a fabricated warning.
        let syn = sessions().first { $0.host == "203.0.113.9" }
        #expect(syn != nil)
        #expect(syn?.status == .ok)
    }

    @Test
    func midstreamTCPWithoutAppDataIsNotWarned() {
        // A TCP segment carrying payload we cannot classify — a captured tunnel,
        // an unrecognised binary protocol, or a mid-stream capture that missed the
        // handshake. It is a real session and stays visible, but "no application
        // protocol decoded" is not evidence of a problem, so it stays `.ok`.
        let frame = CapturedFrame(
            bytes: PacketBuilder.ethernetIPv4(
                proto: 6,
                src: "10.0.0.5",
                dst: "198.51.100.20",
                payload: PacketBuilder.tcp(
                    srcPort: 55_000, dstPort: 8_443, flags: 0x18,
                    payload: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
                )
            ),
            timestamp: Date(),
            originalLength: 74
        )
        let result = SessionBuilder.build(from: [frame], linkType: LinkType.ethernet)
        let session = result.first { $0.destinationEndpoint.contains("198.51.100.20") }
        #expect(session != nil)
        #expect(session?.protocolStack.contains(.tcp) == true)
        #expect(session?.status == .ok)
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

    // MARK: - Representative selection signal

    @Test("add reports the session id only when the packet becomes the representative")
    func addReportsRepresentativeSelection() {
        var accumulator = SessionAccumulator()

        let syn = SessionBuilder.decodePacket(
            frame(PacketBuilder.tcpSynFrame(src: "10.0.0.9", dst: "203.0.113.50", srcPort: 44_000, dstPort: 443)),
            linkType: LinkType.ethernet
        )
        // The first packet of a session is always its representative.
        let firstID = accumulator.add(syn)
        let expected = syn.fiveTuple.map(SessionBuilder.sessionID(for:))
        #expect(firstID != nil)
        #expect(firstID == expected)

        // A richer packet on the same five-tuple displaces the representative and is
        // reported again with the same id.
        let hello = SessionBuilder.decodePacket(
            frame(PacketBuilder.tlsClientHelloFrame(
                sni: "rep.example", src: "10.0.0.9", dst: "203.0.113.50", srcPort: 44_000
            )),
            linkType: LinkType.ethernet
        )
        let richerID = accumulator.add(hello)
        #expect(richerID == firstID)
        #expect(accumulator.sessionCount == 1)
    }

    @Test("Plain add is a session-only fold and performs no cross-frame reassembly")
    func plainAddPerformsNoCrossFrameReassembly() {
        // The compatibility `add(_:)` seam folds only already-decoded per-frame
        // metadata: it has no production caller and owns no reassembly ordering
        // store, so a ClientHello split across two frames is NOT recovered.
        let payload = PacketBuilder.tlsClientHello(sni: "plain.example")
        let cut = 3
        let firstHalf = tcpFrame(payload: Array(payload[..<cut]), sequence: 1_000, timestamp: 1)
        let secondHalf = tcpFrame(payload: Array(payload[cut...]), sequence: 1_000 + UInt32(cut), timestamp: 2)

        var accumulator = SessionAccumulator()
        accumulator.add(SessionBuilder.decodePacket(firstHalf, linkType: LinkType.ethernet))
        accumulator.add(SessionBuilder.decodePacket(secondHalf, linkType: LinkType.ethernet))
        // No SNI without cross-frame reassembly — the split record never completes
        // on the session-only seam.
        #expect(accumulator.summaries().first?.sni == nil)

        // The production context overload DOES recover it: reassembly is owned by
        // the connection table and reaches session state only through `add(_:context:)`.
        let viaContext = SessionBuilder.build(from: [firstHalf, secondHalf], linkType: LinkType.ethernet).first
        #expect(viaContext?.sni == "plain.example")
    }

    @Test("add returns nil for a non-representative fold and a packet with no five-tuple")
    func addReturnsNilForNonRepresentativeAndTupleless() {
        var accumulator = SessionAccumulator()

        func syn() -> DecodedPacket {
            SessionBuilder.decodePacket(
                frame(PacketBuilder.tcpSynFrame(src: "10.0.0.5", dst: "198.51.100.4", srcPort: 45_000, dstPort: 443)),
                linkType: LinkType.ethernet
            )
        }
        #expect(accumulator.add(syn()) != nil) // opens the session
        // A second identical SYN adds no richness, so no representative change.
        #expect(accumulator.add(syn()) == nil)

        // An empty/truncated frame has no endpoints and therefore no five-tuple.
        let tupleless = SessionBuilder.decodePacket(frame([]), linkType: LinkType.ethernet)
        #expect(tupleless.fiveTuple == nil)
        #expect(accumulator.add(tupleless) == nil)
    }

    // MARK: - Detailed build (additive common fold)

    @Test("buildDetailed sessions equal build byte-for-byte and additively fold connections")
    func detailedBuildMatchesSessionsAndFoldsConnections() {
        let frames = ReplayCorpus.tcpConnectionCapturedFrames()
        let detailed = SessionBuilder.buildDetailed(from: frames, linkType: LinkType.ethernet)
        // The additive detailed build leaves the session semantics unchanged.
        #expect(detailed.sessions == SessionBuilder.build(from: frames, linkType: LinkType.ethernet))
        // …and additively exposes the folded connection table.
        #expect(!detailed.connections.summaries.isEmpty)
        #expect(detailed.connections.summaries.contains { $0.handshake == .threeWayObserved })
        #expect(detailed.connections.summaries.allSatisfy { $0.lossKnowledge == .unknown })
        #expect(detailed.connections.summaries.allSatisfy { summary in
            summary.events.allSatisfy { event in event.provenance.allSatisfy { $0.locator == nil } }
        })
    }

    @Test("Every accepted frame consumes an ordinal before TCP filtering")
    func tuplelessAndNonTCPFramesStillAdvanceConnectionOrdinals() throws {
        let dnsBytes = PacketBuilder.dnsQueryFrame(
            name: "ordinal.example", src: "198.51.100.40", dst: "203.0.113.53", srcPort: 53_000
        )
        let dns = CapturedFrame(
            bytes: dnsBytes,
            timestamp: Self.foldBase,
            originalLength: dnsBytes.count
        )
        let synBytes = PacketBuilder.tcpSynFrame(
            src: "198.51.100.41", dst: "203.0.113.70", srcPort: 53_001, dstPort: 443
        )
        let syn = CapturedFrame(
            bytes: synBytes,
            timestamp: Self.foldBase.addingTimeInterval(1),
            originalLength: synBytes.count
        )

        let detailed = SessionBuilder.buildDetailed(from: [dns, syn], linkType: LinkType.ethernet)
        let connection = try #require(detailed.connections.summaries.first)
        #expect(connection.firstProvenance.ordinal == FrameOrdinal(2))
    }

    // MARK: - RST status from typed flags

    @Test("Session RST status derives from typed flags; a rendered field cannot spoof it")
    func rstStatusDerivesFromTypedFlags() {
        // A real RST segment: the typed flags carry .rst → error.
        let rstFrame = CapturedFrame(
            bytes: PacketBuilder.ethernetIPv4(
                proto: 6, src: "203.0.113.5", dst: "10.0.0.5",
                payload: PacketBuilder.tcp(srcPort: 443, dstPort: 52_000, flags: 0x04, payload: [])
            ),
            timestamp: Self.foldBase,
            originalLength: 54
        )
        let rstSession = SessionBuilder.build(from: [rstFrame], linkType: LinkType.ethernet).first
        #expect(rstSession?.status == .error)

        // A packet whose rendered "Flags" field says RST but whose typed flags are
        // empty must NOT read as an error — the status derives from the typed bits.
        var spoof = DecodedPacket(timestamp: Self.foldBase, originalLength: 40)
        spoof.transport = .tcp
        let source = IPEndpoint(ip: "10.0.0.9", port: 55_000)
        let destination = IPEndpoint(ip: "203.0.113.9", port: 443)
        spoof.sourceEndpoint = source
        spoof.destinationEndpoint = destination
        spoof.fiveTuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        spoof.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 0, flags: [],
            windowSize: 0, headerLength: 20, payloadSequence: 1, payloadLength: 0,
            options: TCPOptionFacts()
        )
        spoof.layers = [DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol",
            fields: [DecodedField(name: "Flags", value: "RST")]
        )]
        var accumulator = SessionAccumulator()
        accumulator.add(spoof)
        #expect(accumulator.summaries().first?.status == .ok)
    }

    // MARK: - DNS answer publication cap

    @Test("A session publishes at most 64 unique DNS answers, deduped in first-seen order")
    func sessionPublishesBoundedUniqueDNSAnswers() {
        // Two responses on the same five-tuple. Overlapping answers are duplicates
        // (deduped, not omitted); fresh answers past the 64-cap are omitted.
        let first = (1 ... 45).map { "198.51.100.\($0)" }
        let second = (30 ... 90).map { "198.51.100.\($0)" }
        let frames = [
            dnsResponse(answers: first, at: Self.foldBase),
            dnsResponse(answers: second, at: Self.foldBase.addingTimeInterval(1)),
        ]
        let session = try? #require(SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first)
        if let session {
            #expect(session.dnsAnswers.count == 64)
            // First-seen order: all of the first response, then the fresh tail of
            // the second up to the cap.
            let expected = first + (46 ... 64).map { "198.51.100.\($0)" }
            #expect(session.dnsAnswers == expected)
            // 90 unique answers, 64 published → 26 omitted; duplicates uncounted.
            #expect(session.dnsAnswersOmittedCount == 26)
            #expect(session.dnsAnswersTruncated)
        }
    }

    @Test("A below-cap session omits nothing")
    func sessionBelowCapOmitsNothing() {
        let answers = ["203.0.113.5", "203.0.113.6"]
        let session = SessionBuilder.build(
            from: [dnsResponse(answers: answers, at: Self.foldBase)], linkType: LinkType.ethernet
        ).first
        #expect(session?.dnsAnswers == answers)
        #expect(session?.dnsAnswersOmittedCount == 0)
        #expect(session?.dnsAnswersTruncated == false)
    }

    @Test("Decode-time answer omissions are folded into the session omitted count")
    func sessionFoldsPacketOmissions() {
        // A single response with 70 answers: the decoder retains 64 and reports 6
        // omitted, which the session surfaces on its summary.
        let answers = (1 ... 70).map { "198.51.100.\($0)" }
        let session = SessionBuilder.build(
            from: [dnsResponse(answers: answers, at: Self.foldBase)], linkType: LinkType.ethernet
        ).first
        #expect(session?.dnsAnswers.count == 64)
        #expect(session?.dnsAnswersOmittedCount == 6)
    }

    @Test("Split TCP DNS propagates answer omissions from reassembled metadata")
    func splitTCPDNSPropagatesAnswerOmissions() {
        let answers = (1 ... 70).map { "198.51.100.\($0)" }
        let dns = PacketBuilder.dnsResponse(name: "bounded-tcp.example", answers: answers)
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let cut = 31
        let frames = [
            tcpFrame(
                payload: Array(payload[..<cut]), sequence: 12_000, timestamp: 1,
                sourcePort: 53, destinationPort: 52_000
            ),
            tcpFrame(
                payload: Array(payload[cut...]), sequence: 12_000 + UInt32(cut), timestamp: 2,
                sourcePort: 53, destinationPort: 52_000
            ),
        ]

        let session = SessionBuilder.build(from: frames, linkType: LinkType.ethernet).first
        #expect(session?.dnsAnswers == Array(answers.prefix(64)))
        #expect(session?.dnsAnswersOmittedCount == 6)
        #expect(session?.dnsAnswersTruncated == true)
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

    /// Fixed instant for folding representative-selection fixtures.
    private static let foldBase = Date(timeIntervalSince1970: 1_700_000_000)

    /// A DNS response frame on a fixed resolver→client five-tuple, so repeated
    /// calls fold into one session.
    private func dnsResponse(answers: [String], at timestamp: Date) -> CapturedFrame {
        let bytes = PacketBuilder.dnsResponseFrame(
            name: "answers.example", answers: answers, src: "203.0.113.53", dst: "198.51.100.10"
        )
        return CapturedFrame(bytes: bytes, timestamp: timestamp, originalLength: bytes.count)
    }

    private func sessions() -> [SessionSummary] {
        SessionBuilder.build(from: SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
    }

    /// Wrap raw frame bytes in a `CapturedFrame` at a fixed instant for folding.
    private func frame(_ bytes: [UInt8]) -> CapturedFrame {
        CapturedFrame(bytes: bytes, timestamp: Self.foldBase, originalLength: bytes.count)
    }
}

private func tcpFrame(
    payload: [UInt8],
    sequence: UInt32,
    timestamp: TimeInterval,
    sourcePort: UInt16 = 50_000,
    destinationPort: UInt16 = 443
)
    -> CapturedFrame
{
    let bytes = PacketBuilder.ethernetIPv4(
        proto: 6,
        src: "10.0.0.5",
        dst: "93.184.216.34",
        payload: PacketBuilder.tcp(
            srcPort: sourcePort,
            dstPort: destinationPort,
            flags: 0x18,
            payload: payload,
            sequence: sequence
        )
    )
    return CapturedFrame(
        bytes: bytes,
        timestamp: Date(timeIntervalSince1970: timestamp),
        originalLength: bytes.count
    )
}
