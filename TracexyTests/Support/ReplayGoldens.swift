import Foundation
@testable import Tracexy

// MARK: - ReplayGoldens

/// The frozen expected results for the primary ``ReplayCorpus`` conversation.
///
/// These are the golden values every replay path (batch, live, saved) must
/// reproduce. Typed expectations make common drift legible, while the canonical
/// JSON digest pins every remaining snapshot field and byte range without checking
/// in a large opaque blob. Byte counts stay derived from the fixed fixture bytes
/// rather than from the decoder under test.
///
/// Any change to a host, endpoint, protocol stack, status, SNI, DNS query/answers,
/// latency presence or byte total fails ``verify(sessions:)``. The per-frame
/// decoder matrix pins each frame's stack and classified application protocol.
enum ReplayGoldens {
    // MARK: Session golden

    /// One expected session in first-seen order.
    struct ExpectedSession {
        let label: String
        let host: String
        let source: String
        let destination: String
        let protocolStack: [ProtocolKind]
        let status: SessionStatus
        let sni: String?
        let dnsQuery: String?
        let dnsAnswers: [String]
        let hasLatency: Bool
        let bytesUp: Int
        let bytesDown: Int
    }

    // MARK: Per-frame decoder matrix

    /// One expected single-frame decode. The split TLS segments (corpus indices 5
    /// and 6) are intentionally excluded here — their honesty is asserted by the
    /// reassembly test — so this matrix stays thin and unambiguous.
    struct ExpectedFrame {
        let index: Int
        let label: String
        let protocolStack: [ProtocolKind]
        let appProtocol: ProtocolKind?
    }

    static let frameMatrix: [ExpectedFrame] = [
        ExpectedFrame(index: 0, label: "ARP", protocolStack: [.arp], appProtocol: .arp),
        ExpectedFrame(index: 1, label: "ICMP", protocolStack: [.ipv4, .icmp], appProtocol: .icmp),
        ExpectedFrame(index: 2, label: "DNS query", protocolStack: [.ipv4, .udp, .dns], appProtocol: .dns),
        ExpectedFrame(index: 3, label: "DNS response", protocolStack: [.ipv4, .udp, .dns], appProtocol: .dns),
        ExpectedFrame(index: 4, label: "TCP SYN", protocolStack: [.ipv4, .tcp], appProtocol: nil),
        ExpectedFrame(index: 7, label: "HTTP request", protocolStack: [.ipv4, .tcp, .http], appProtocol: .http),
        ExpectedFrame(index: 8, label: "STUN", protocolStack: [.ipv4, .udp, .stun], appProtocol: .stun),
        ExpectedFrame(index: 9, label: "QUIC", protocolStack: [.ipv4, .udp, .quic], appProtocol: .quic),
        ExpectedFrame(index: 10, label: "IPv6 DNS query", protocolStack: [.ipv6, .udp, .dns], appProtocol: .dns),
        ExpectedFrame(index: 11, label: "IPv6 DNS response", protocolStack: [.ipv6, .udp, .dns], appProtocol: .dns),
    ]

    /// FNV-1a-64 of the complete canonical session JSON. Regenerate only after a
    /// reviewed, intentional decoder/session change and inspect the semantic diff.
    /// N2A adds only `dnsAnswersOmittedCount: 0` to each accepted corpus session.
    /// Removing those fields from the new canonical JSON reproduces the prior
    /// `28faca25e43b5f55` pin exactly. N2D2 must not change this pin: moving TCP
    /// first-record recovery into the connection table leaves every session summary
    /// byte-for-byte identical.
    static let conversationSnapshotDigest = "e387dbd25f5d81e7"

    /// FNV-1a-64 of the complete canonical *connection* JSON for the primary
    /// conversation (N2D2). It is additive to `conversationSnapshotDigest` and
    /// covers the connection fold's application-event fields (`applicationKind`,
    /// `applicationComplete`) for the split-TLS connection.
    ///
    /// Reviewed N2D2 baseline: the TLS availability event is intentionally
    /// incomplete on first recognition, while the HTTP event is complete.
    static let conversationConnectionDigest = "8a780bcf0a4b7885"

    /// FNV-1a-64 digest of a connection-table snapshot's canonical, sorted-key JSON.
    /// Mirrors ``SessionSnapshot/digest(_:)`` so a connection golden pins every
    /// snapshot field compactly without checking in a large blob.
    static func connectionDigest(_ snapshot: ConnectionTableSnapshot) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(snapshot), let text = String(data: data, encoding: .utf8) else {
            return ""
        }
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in text.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(format: "%016llx", hash)
    }

    /// The expected sessions for ``ReplayCorpus/conversation()``, in first-seen
    /// five-tuple order. Byte totals are derived from the fixed corpus frame sizes
    /// (an oracle independent of the decoder/accumulator under test).
    static func conversationExpectations() -> [ExpectedSession] {
        let frames = ReplayCorpus.conversation()
        func size(_ index: Int) -> Int {
            frames[index].bytes.count
        }

        return [
            ExpectedSession(
                label: "ARP",
                host: "198.51.100.1",
                source: "198.51.100.10:0",
                destination: "198.51.100.1:0",
                protocolStack: [.arp],
                status: .ok,
                sni: nil,
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(0),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "ICMP",
                host: "one.example",
                source: "198.51.100.10:0",
                destination: "203.0.113.5:0",
                protocolStack: [.icmp],
                status: .ok,
                sni: nil,
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(1),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "DNS/IPv4",
                host: "one.example",
                source: "198.51.100.10:54000",
                destination: "203.0.113.53:53",
                protocolStack: [.udp, .dns],
                status: .ok,
                sni: nil,
                dnsQuery: "one.example",
                dnsAnswers: ["203.0.113.5"],
                hasLatency: true,
                bytesUp: size(2),
                bytesDown: size(3)
            ),
            ExpectedSession(
                label: "TLS (split ClientHello)",
                host: "secure.example",
                source: "198.51.100.10:52344",
                destination: "203.0.113.5:443",
                protocolStack: [.tcp, .tls],
                status: .ok,
                sni: "secure.example",
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(4) + size(5) + size(6),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "HTTP/1",
                host: "http.example",
                source: "198.51.100.10:52100",
                destination: "203.0.113.6:80",
                protocolStack: [.tcp, .http],
                status: .ok,
                sni: nil,
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(7),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "STUN",
                host: "192.0.2.9",
                source: "198.51.100.10:54321",
                destination: "192.0.2.9:51820",
                protocolStack: [.udp, .stun],
                status: .ok,
                sni: nil,
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(8),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "QUIC",
                host: "192.0.2.10",
                source: "198.51.100.10:55000",
                destination: "192.0.2.10:443",
                protocolStack: [.udp, .quic],
                status: .ok,
                sni: nil,
                dnsQuery: nil,
                dnsAnswers: [],
                hasLatency: false,
                bytesUp: size(9),
                bytesDown: 0
            ),
            ExpectedSession(
                label: "DNS/IPv6",
                host: "six.example",
                source: "2001:db8:0:0:0:0:0:10:45000",
                destination: "2001:db8:0:0:0:0:0:53:53",
                protocolStack: [.udp, .dns],
                status: .ok,
                sni: nil,
                dnsQuery: "six.example",
                dnsAnswers: ["192.0.2.20"],
                hasLatency: true,
                bytesUp: size(10),
                bytesDown: size(11)
            ),
        ]
    }

    /// Compare a produced session list against the golden and return a list of
    /// human-readable mismatches (empty means an exact semantic match). Byte
    /// totals, ordering, host, endpoints, protocol stack, status, SNI, DNS and
    /// latency presence are all checked.
    static func verify(sessions: [SessionSummary]) -> [String] {
        let expected = conversationExpectations()
        var problems: [String] = []
        if sessions.count != expected.count {
            problems.append("session count \(sessions.count) != expected \(expected.count)")
            return problems
        }
        for (index, want) in expected.enumerated() {
            let got = sessions[index]
            func check<Value: Equatable>(_ field: String, _ actual: Value, _ expected: Value) {
                if actual != expected {
                    problems.append("[\(want.label)] \(field): \(actual) != \(expected)")
                }
            }
            check("host", got.host, want.host)
            check("source", got.sourceEndpoint, want.source)
            check("destination", got.destinationEndpoint, want.destination)
            check("protocolStack", got.protocolStack, want.protocolStack)
            check("status", got.status, want.status)
            check("sni", got.sni, want.sni)
            check("dnsQuery", got.dnsQuery, want.dnsQuery)
            check("dnsAnswers", got.dnsAnswers, want.dnsAnswers)
            check("bytesUp", got.bytesUp, want.bytesUp)
            check("bytesDown", got.bytesDown, want.bytesDown)
            check("hasLatency", got.latencyMilliseconds != nil, want.hasLatency)
        }
        return problems
    }
}
