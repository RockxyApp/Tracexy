import Testing
@testable import Tracexy

// MARK: - TCPApplicationPrefixProbeTests

/// The bounded, per-direction first-record application probe (N2D2). It reassembles
/// only enough of one direction's TCP byte stream — in `payloadSequence`
/// coordinates, separate from the byte-free `TCPSequenceTracker` — to classify the
/// opening TLS/HTTP/DNS record, then releases the bytes. These tests exercise its
/// observable behavior through classification and its overflow/release contract; the
/// discrete byte mechanics are proven by correct classification of split, reordered,
/// overlapping and wrapping fragments rather than by inspecting private buffers.
@Suite("TCP application prefix probe")
struct TCPApplicationPrefixProbeTests {
    // MARK: In-order / out-of-order / overlap / duplicate / wrap

    @Test("In-order split ClientHello classifies once complete")
    func inOrderSplitTLS() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "inorder.example")
        let cut = 3

        let first = probe.ingest(
            payloadSequence: 1_000, payload: Array(hello[..<cut]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(first.application == nil)

        let second = probe.ingest(
            payloadSequence: 1_000 + UInt32(cut), payload: Array(hello[cut...]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(second.application?.appProtocol == .tls)
        #expect(second.application?.sni == "inorder.example")
    }

    @Test("Out-of-order fragments drain deterministically before classification")
    func outOfOrderSplitTLS() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "ooo.example")
        let firstEnd = 3
        let secondEnd = 18

        _ = probe.ingest(
            payloadSequence: 4_000, payload: Array(hello[..<firstEnd]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        // The tail arrives before the middle: it must buffer, not classify.
        let buffered = probe.ingest(
            payloadSequence: 4_000 + UInt32(secondEnd), payload: Array(hello[secondEnd...]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(buffered.application == nil)
        // The middle connects everything and classifies.
        let drained = probe.ingest(
            payloadSequence: 4_000 + UInt32(firstEnd), payload: Array(hello[firstEnd ..< secondEnd]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(drained.application?.sni == "ooo.example")
    }

    @Test("A conflicting overlap keeps first-observed bytes and never duplicates")
    func conflictingOverlapFirstObserved() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "overlap.example")
        let cut = 4

        _ = probe.ingest(
            payloadSequence: 10, payload: Array(hello[..<cut]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        // A retransmit fully behind the expected sequence carrying different bytes
        // must be ignored (first-observed wins), not corrupt the prefix.
        let garbage = [UInt8](repeating: 0xFF, count: cut)
        let duplicate = probe.ingest(
            payloadSequence: 10, payload: garbage,
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(duplicate.application == nil)
        // The genuine continuation still classifies, proving no duplication/corruption.
        let rest = probe.ingest(
            payloadSequence: 10 + UInt32(cut), payload: Array(hello[cut...]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(rest.application?.sni == "overlap.example")
    }

    @Test("Sequence wrap across the UInt32 boundary preserves order")
    func sequenceWrap() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "wrap.example")
        let cut = 2
        let base = UInt32.max - 1

        _ = probe.ingest(
            payloadSequence: base, payload: Array(hello[..<cut]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        let wrapped = probe.ingest(
            payloadSequence: base &+ UInt32(cut), payload: Array(hello[cut...]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(wrapped.application?.sni == "wrap.example")
    }

    // MARK: SYN+data / FIN+data anchoring

    @Test("SYN+data anchors at payloadSequence exactly once")
    func synDataAnchorsAtPayloadSequence() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "syndata.example")
        let cut = 5
        // A SYN consumes one sequence number; the caller passes payloadSequence
        // (seq + 1) so the payload anchors exactly at the first data byte.
        _ = probe.ingest(
            payloadSequence: 2_001, payload: Array(hello[..<cut]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        let done = probe.ingest(
            payloadSequence: 2_001 + UInt32(cut), payload: Array(hello[cut...]),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(done.application?.sni == "syndata.example")
    }

    // MARK: Protocol coverage

    @Test("A split HTTP request header classifies with its Host")
    func splitHTTP() {
        var probe = TCPApplicationPrefixProbe()
        let payload = Array("GET /health HTTP/1.1\r\nHost: probe-http.example\r\n\r\n".utf8)
        let cut = 2

        _ = probe.ingest(
            payloadSequence: 6_000, payload: Array(payload[..<cut]),
            sourcePort: 51_000, destinationPort: 80, packetIsClassified: false
        )
        let done = probe.ingest(
            payloadSequence: 6_000 + UInt32(cut), payload: Array(payload[cut...]),
            sourcePort: 51_000, destinationPort: 80, packetIsClassified: false
        )
        #expect(done.application?.appProtocol == .http)
    }

    @Test("A split length-prefixed TCP DNS query classifies")
    func splitTCPDNS() {
        var probe = TCPApplicationPrefixProbe()
        let dns = PacketBuilder.dnsQuery(name: "probe-dns.example")
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let cut = 1

        _ = probe.ingest(
            payloadSequence: 8_000, payload: Array(payload[..<cut]),
            sourcePort: 52_000, destinationPort: 53, packetIsClassified: false
        )
        let done = probe.ingest(
            payloadSequence: 8_000 + UInt32(cut), payload: Array(payload[cut...]),
            sourcePort: 52_000, destinationPort: 53, packetIsClassified: false
        )
        #expect(done.application?.appProtocol == .dns)
        #expect(done.application?.dnsQuery == "probe-dns.example")
    }

    // MARK: Release and re-anchor

    @Test("A complete first record releases bytes and stops further probing")
    func completeRecordReleasesAndStops() {
        var probe = TCPApplicationPrefixProbe()
        let hello = PacketBuilder.tlsClientHello(sni: "release.example")
        let outcome = probe.ingest(
            payloadSequence: 100, payload: hello,
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: true
        )
        #expect(outcome.application?.isComplete == true)
        // Once complete, a further contiguous segment yields no new application.
        let after = probe.ingest(
            payloadSequence: 100 + UInt32(hello.count), payload: hello,
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: true
        )
        #expect(after.application == nil)
        #expect(!probe.isDisabled)
    }

    @Test("An opaque prefix re-anchors to a self-classified current packet")
    func reAnchorToClassifiedPacket() {
        var probe = TCPApplicationPrefixProbe()
        // A midstream capture: the first observed bytes are an opaque continuation
        // (unclassifiable) at some sequence.
        let opaque = [UInt8](repeating: 0x5A, count: 6)
        let anchor = probe.ingest(
            payloadSequence: 500, payload: opaque,
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(anchor.application == nil)
        // A later, independently-classified full record at its own boundary must
        // re-anchor away from the opaque prefix and classify.
        let hello = PacketBuilder.tlsClientHello(sni: "reanchor.example")
        let reanchored = probe.ingest(
            payloadSequence: 9_000, payload: hello,
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: true
        )
        #expect(reanchored.application?.sni == "reanchor.example")
    }

    // MARK: Bounds — 16 KiB bytes, 32 fragments, oversized single

    @Test("An oversized single segment overflows, truncates and disables recovery")
    func oversizedSingleSegmentDisables() {
        var probe = TCPApplicationPrefixProbe(maxBufferedBytes: 8, maxFragments: 8)
        let outcome = probe.ingest(
            payloadSequence: 0, payload: [UInt8](repeating: 0xAB, count: 20),
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(outcome.truncated)
        #expect(outcome.application == nil)
        #expect(probe.isDisabled)
        // A disabled probe never revives.
        let later = probe.ingest(
            payloadSequence: 100, payload: [1, 2, 3],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(!later.truncated)
        #expect(later.application == nil)
    }

    @Test("Exceeding the byte bound across fragments overflows and disables")
    func byteBoundOverflowDisables() {
        var probe = TCPApplicationPrefixProbe(maxBufferedBytes: 8, maxFragments: 32)
        _ = probe.ingest(
            payloadSequence: 0, payload: [0, 1],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        let overflow = probe.ingest(
            payloadSequence: 100, payload: [2, 3, 4, 5, 6, 7, 8, 9],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(overflow.truncated)
        #expect(probe.isDisabled)
    }

    @Test("Exceeding the fragment bound overflows and disables")
    func fragmentBoundOverflowDisables() {
        var probe = TCPApplicationPrefixProbe(maxBufferedBytes: 64, maxFragments: 2)
        _ = probe.ingest(
            payloadSequence: 0, payload: [0],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        _ = probe.ingest(
            payloadSequence: 10, payload: [1],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        _ = probe.ingest(
            payloadSequence: 20, payload: [2],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        let overflow = probe.ingest(
            payloadSequence: 30, payload: [3],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(overflow.truncated)
        #expect(probe.isDisabled)
    }

    // MARK: No-op

    @Test("An empty payload is a no-op and never overflows")
    func emptyPayloadIsNoOp() {
        var probe = TCPApplicationPrefixProbe()
        let outcome = probe.ingest(
            payloadSequence: 42, payload: [],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )
        #expect(outcome.application == nil)
        #expect(!outcome.truncated)
        #expect(!probe.isDisabled)
    }

    @Test("An exact serial half-space distance fails closed for the application probe")
    func exactHalfSpaceDisablesOnlyApplicationRecovery() {
        var probe = TCPApplicationPrefixProbe(maxBufferedBytes: 64, maxFragments: 8)
        _ = probe.ingest(
            payloadSequence: 100, payload: [0x16],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )

        let ambiguous = probe.ingest(
            payloadSequence: 101 &+ 0x80000000, payload: [0x03],
            sourcePort: 52_344, destinationPort: 443, packetIsClassified: false
        )

        #expect(ambiguous.application == nil)
        #expect(ambiguous.truncated)
        #expect(probe.isDisabled)
    }
}
