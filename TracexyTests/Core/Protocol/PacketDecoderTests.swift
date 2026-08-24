import Foundation
import Testing
@testable import Tracexy

// MARK: - Helpers

private extension DecodedPacket {
    /// All layer titles, flattened including nested children, for order-independent assertions.
    var allLayerTitles: [String] {
        func flatten(_ layers: [DecodedLayer]) -> [String] {
            layers.flatMap { [$0.title] + flatten($0.children) }
        }
        return flatten(layers)
    }

    /// The first decoded layer for a given protocol, if any (top level only).
    func layer(_ kind: ProtocolKind) -> DecodedLayer? {
        layers.first { $0.proto == kind }
    }
}

private func decodeFrame(_ frame: [UInt8], linkType: UInt32 = LinkType.ethernet) -> DecodedPacket {
    PacketDecoder.decode(
        PacketBuffer(frame),
        linkType: linkType,
        timestamp: Date(timeIntervalSince1970: 1_700_000_000),
        originalLength: frame.count
    )
}

// MARK: - DNSDecodeTests

@Suite("DNS decode")
struct DNSDecodeTests {
    @Test("DNS query frame decodes name, transport, endpoints, and layer stack")
    func dnsQuery() {
        let frame = PacketBuilder.dnsQueryFrame(name: "api.example.com", src: "192.168.1.42", dst: "1.1.1.1")
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .dns)
        #expect(packet.transport == .udp)
        #expect(packet.dnsQuery == "api.example.com")
        #expect(packet.dnsAnswers.isEmpty)

        // Endpoints: 192.168.1.42:54000 (default src port) → 1.1.1.1:53.
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.168.1.42", port: 54_000))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "1.1.1.1", port: 53))

        // Five-tuple is present and canonical-ordered (endpoints collapse to a set).
        let tuple = try? #require(packet.fiveTuple)
        if let tuple {
            #expect(tuple.proto == .udp)
            let endpoints = Set([tuple.a, tuple.b])
            #expect(endpoints == Set([
                IPEndpoint(ip: "192.168.1.42", port: 54_000),
                IPEndpoint(ip: "1.1.1.1", port: 53)
            ]))
        }

        // Protocol stack (excludes ethernet) is IPv4 → UDP → DNS.
        #expect(packet.protocolStack == [.ipv4, .udp, .dns])
        #expect(packet.protocolStack.contains(.dns))

        // Human-facing layer titles for the inspector.
        let titles = packet.allLayerTitles
        #expect(titles.contains("Ethernet II"))
        #expect(titles.contains("Internet Protocol v4"))
        #expect(titles.contains("User Datagram Protocol"))
        #expect(titles.contains("Domain Name System"))
    }

    @Test("DNS response frame surfaces the answer addresses")
    func dnsResponse() {
        let frame = PacketBuilder.dnsResponseFrame(
            name: "example.com",
            answers: ["93.184.16.34"],
            src: "1.1.1.1",
            dst: "192.168.1.42"
        )
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .dns)
        #expect(packet.dnsQuery == "example.com")
        #expect(packet.dnsAnswers == ["93.184.16.34"])

        let dnsLayer = packet.layer(.dns)
        #expect(dnsLayer?.summary == "response")
        #expect(dnsLayer?.fields.contains(DecodedField(name: "Type", value: "Response")) == true)
    }

    @Test("DNS response with multiple A records preserves order")
    func dnsResponseMultipleAnswers() {
        let frame = PacketBuilder.dnsResponseFrame(
            name: "multi.example.com",
            answers: ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            src: "8.8.8.8",
            dst: "192.168.1.42"
        )
        let packet = decodeFrame(frame)
        #expect(packet.dnsAnswers == ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
    }
}

// MARK: - DNSMessageFactsTests

/// Pins the neutral, decode-derived DNS fixed-header facts: the transaction ID, flag
/// bits, opcode/response code, and section counts. These are read once from the fixed
/// 12-byte header and never overwrite existing name/answer/string behavior.
@Suite("DNS message facts")
struct DNSMessageFactsTests {
    @Test("A query fixture pins transaction ID, query bit, zero opcode/rcode, RD, and counts")
    func queryFacts() {
        let frame = PacketBuilder.dnsQueryFrame(name: "api.example.com", src: "192.168.1.42", dst: "1.1.1.1")
        let facts = try? #require(decodeFrame(frame).dnsFacts)
        if let facts {
            #expect(facts.transactionID == 0x1234)
            #expect(facts.isResponse == false)
            #expect(facts.opcode == 0)
            #expect(facts.responseCode == 0)
            #expect(facts.recursionDesired == true)
            #expect(facts.recursionAvailable == false)
            #expect(facts.questionCount == 1)
            #expect(facts.answerCount == 0)
            #expect(facts.authorityCount == 0)
            #expect(facts.additionalCount == 0)
        }
    }

    @Test("A response fixture pins query/response, RD/RA, and the exact section counts")
    func responseFacts() {
        let frame = PacketBuilder.dnsResponseFrame(
            name: "example.com", answers: ["93.184.16.34"], src: "1.1.1.1", dst: "192.168.1.42"
        )
        let facts = try? #require(decodeFrame(frame).dnsFacts)
        if let facts {
            #expect(facts.isResponse == true)
            #expect(facts.recursionDesired == true)
            #expect(facts.recursionAvailable == true)
            #expect(facts.questionCount == 1)
            #expect(facts.answerCount == 1)
        }
    }

    @Test("A custom response pins nonzero opcode/rcode and every retained flag without changing layers")
    func customResponseFactsAndLayers() {
        // Flags 0xA7B3: QR, opcode 4, AA, TC, RD, RA, AD, CD, rcode 3.
        let dns: [UInt8] = [
            0x12, 0x34, // transaction ID
            0xA7, 0xB3, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0x01, 0x61, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00, // "a.test"
            0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
            0xC0, 0x0C, // answer name → pointer to qname
            0x00, 0x01, 0x00, 0x01, // type A, class IN
            0x00, 0x00, 0x01, 0x2C, // TTL 300
            0x00, 0x04, // RDLENGTH 4
            93, 184, 16, 34, // A 93.184.16.34
        ]
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "1.1.1.1", dst: "192.168.1.42",
            payload: PacketBuilder.udp(srcPort: 53, dstPort: 54_000, payload: dns)
        )
        let packet = decodeFrame(frame)
        let facts = try? #require(packet.dnsFacts)
        if let facts {
            #expect(facts.opcode == 4)
            #expect(facts.responseCode == 3)
            #expect(facts.isResponse == true)
            #expect(facts.isAuthoritativeAnswer == true)
            #expect(facts.isTruncated == true)
            #expect(facts.recursionDesired == true)
            #expect(facts.recursionAvailable == true)
            #expect(facts.authenticData == true)
            #expect(facts.checkingDisabled == true)
        }
        // Existing string/layer behavior is unchanged by facts retention.
        #expect(packet.dnsQuery == "a.test")
        #expect(packet.dnsAnswers == ["93.184.16.34"])
        #expect(packet.layer(.dns)?.summary == "response")
    }

    @Test("An intact fixed header with a truncated variable body still retains facts")
    func factsSurviveTruncatedBody() {
        // A 12-byte fixed header declaring one question, with no question body following.
        let header: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "1.1.1.1", dst: "192.168.1.42",
            payload: PacketBuilder.udp(srcPort: 53, dstPort: 54_000, payload: header)
        )
        let packet = decodeFrame(frame)
        let facts = try? #require(packet.dnsFacts)
        if let facts {
            #expect(facts.transactionID == 0x1234)
            #expect(facts.isResponse == true)
            #expect(facts.questionCount == 1)
        }
        // The malformed body aborts name parsing, so no answers are surfaced.
        #expect(packet.dnsAnswers.isEmpty)
    }

    @Test("A complete reassembled TCP DNS record forwards facts identical to the UDP decode")
    func reassembledForwardsIdenticalFacts() {
        let dns = PacketBuilder.dnsResponse(name: "example.com", answers: ["93.184.16.34"])
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let metadata = PacketDecoder.decodeReassembledTCPPayload(payload, sourcePort: 53, destinationPort: 52_000)

        let udpFrame = PacketBuilder.dnsResponseFrame(
            name: "example.com", answers: ["93.184.16.34"], src: "1.1.1.1", dst: "192.168.1.42"
        )
        #expect(metadata?.dnsFacts == decodeFrame(udpFrame).dnsFacts)
        #expect(metadata?.dnsFacts?.answerCount == 1)
    }

    @Test("An incomplete reassembled DNS record yields no metadata and therefore no facts")
    func reassembledIncompleteHasNoFacts() {
        // The 2-byte prefix declares 100 bytes; only a short remainder is present.
        let payload: [UInt8] = [0x00, 0x64] + Array(repeating: 0, count: 10)
        let metadata = PacketDecoder.decodeReassembledTCPPayload(payload, sourcePort: 53, destinationPort: 52_000)
        #expect(metadata == nil)
    }
}

// MARK: - TLSDecodeTests

@Suite("TLS decode")
struct TLSDecodeTests {
    @Test("TLS ClientHello exposes SNI, TCP transport, and a Client Hello child layer")
    func clientHello() {
        let frame = PacketBuilder.tlsClientHelloFrame(
            sni: "api.example.com",
            src: "192.168.1.42",
            dst: "93.184.16.34"
        )
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .tls)
        #expect(packet.transport == .tcp)
        #expect(packet.sni == "api.example.com")

        // Destination is the TLS server on 443.
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "93.184.16.34", port: 443))
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.168.1.42", port: 52_344))

        #expect(packet.protocolStack == [.ipv4, .tcp, .tls])

        // The TLS layer must carry a "Handshake: Client Hello" child whose field holds the SNI.
        let tlsLayer = try? #require(packet.layer(.tls))
        if let tlsLayer {
            let hello = try? #require(tlsLayer.children.first { $0.title == "Handshake: Client Hello" })
            if let hello {
                #expect(hello.fields.contains(DecodedField(name: "server_name", value: "api.example.com")))
            }
        }
    }
}

// MARK: - HTTPDecodeTests

@Suite("HTTP decode")
struct HTTPDecodeTests {
    @Test("HTTP request exposes the request line and Host header")
    func httpRequest() {
        let frame = PacketBuilder.httpRequestFrame(
            host: "example.com",
            path: "/index.html",
            src: "192.168.1.42",
            dst: "93.184.16.34"
        )
        let packet = decodeFrame(frame)

        #expect(packet.appProtocol == .http)
        #expect(packet.transport == .tcp)
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "93.184.16.34", port: 80))
        #expect(packet.protocolStack == [.ipv4, .tcp, .http])

        let httpLayer = try? #require(packet.layer(.http))
        if let httpLayer {
            #expect(httpLayer.fields.contains(DecodedField(name: "Host", value: "example.com")))
            #expect(httpLayer.fields.contains(DecodedField(name: "Request", value: "GET /index.html HTTP/1.1")))
            #expect(httpLayer.summary == "GET /index.html HTTP/1.1")
        }
    }
}

// MARK: - HeaderDecodeTests

@Suite("IPv4 / TCP / UDP header decode")
struct HeaderDecodeTests {
    @Test("TCP SYN frame decodes both endpoints and SYN flag")
    func tcpSyn() {
        let frame = PacketBuilder.tcpSynFrame(
            src: "10.1.2.3",
            dst: "203.0.113.7",
            srcPort: 49_152,
            dstPort: 8_443
        )
        let packet = decodeFrame(frame)

        #expect(packet.transport == .tcp)
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "10.1.2.3", port: 49_152))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "203.0.113.7", port: 8_443))

        // No application payload on a bare SYN.
        #expect(packet.appProtocol == nil)
        #expect(packet.protocolStack == [.ipv4, .tcp])

        let tcpLayer = try? #require(packet.layer(.tcp))
        if let tcpLayer {
            #expect(tcpLayer.fields.contains(DecodedField(name: "Source Port", value: "49152")))
            #expect(tcpLayer.fields.contains(DecodedField(name: "Destination Port", value: "8443")))
            #expect(tcpLayer.fields.contains(DecodedField(name: "Flags", value: "SYN")))
        }
    }

    @Test("IPv4 layer carries source, destination, and TCP protocol fields")
    func ipv4Fields() {
        let frame = PacketBuilder.tcpSynFrame(
            src: "172.16.0.99",
            dst: "192.0.2.200",
            srcPort: 1_234,
            dstPort: 4_321
        )
        let packet = decodeFrame(frame)
        let ipLayer = try? #require(packet.layer(.ipv4))
        if let ipLayer {
            #expect(ipLayer.fields.contains(DecodedField(name: "Source", value: "172.16.0.99")))
            #expect(ipLayer.fields.contains(DecodedField(name: "Destination", value: "192.0.2.200")))
            #expect(ipLayer.fields.contains(DecodedField(name: "Protocol", value: "TCP (6)")))
        }
    }

    @Test("UDP DNS frame decodes both ports through the UDP header")
    func udpPorts() {
        let frame = PacketBuilder.dnsQueryFrame(
            name: "host.test",
            src: "192.168.0.5",
            dst: "9.9.9.9",
            srcPort: 60_000
        )
        let packet = decodeFrame(frame)

        #expect(packet.transport == .udp)
        #expect(packet.sourceEndpoint == IPEndpoint(ip: "192.168.0.5", port: 60_000))
        #expect(packet.destinationEndpoint == IPEndpoint(ip: "9.9.9.9", port: 53))

        let udpLayer = try? #require(packet.layer(.udp))
        if let udpLayer {
            #expect(udpLayer.fields.contains(DecodedField(name: "Source Port", value: "60000")))
            #expect(udpLayer.fields.contains(DecodedField(name: "Destination Port", value: "53")))
        }
    }
}

// MARK: - TCPSegmentFactsTests

@Suite("TCP segment facts")
struct TCPSegmentFactsTests {
    // MARK: Internal

    @Test("A bare header-only segment still carries complete typed facts")
    func bareSegmentCarriesFacts() {
        let facts = try? #require(decodeFacts(flags: 0x10, sequence: 100)) // ACK, no payload
        if let facts {
            #expect(facts.sequenceNumber == 100)
            #expect(facts.acknowledgementNumber == 0)
            #expect(facts.flags == [.ack])
            #expect(facts.windowSize == 0xFFFF)
            #expect(facts.headerLength == 20)
            #expect(facts.payloadSequence == 100) // no SYN → unchanged
            #expect(facts.payloadLength == 0)
        }
    }

    @Test("SYN consumes exactly one sequence number for the payload sequence")
    func synAdjustsPayloadSequence() {
        let facts = try? #require(decodeFacts(flags: 0x02, sequence: 1_000)) // SYN, no payload
        if let facts {
            #expect(facts.flags == [.syn])
            #expect(facts.sequenceNumber == 1_000)
            #expect(facts.payloadSequence == 1_001)
            #expect(facts.payloadLength == 0)
        }
    }

    @Test("SYN+ACK carries both bits and the SYN-adjusted payload sequence")
    func synAckFacts() {
        let facts = try? #require(decodeFacts(flags: 0x12, sequence: 500))
        if let facts {
            #expect(facts.flags == [.syn, .ack])
            #expect(facts.flags.contains(.syn))
            #expect(facts.flags.contains(.ack))
            #expect(facts.payloadSequence == 501)
        }
    }

    @Test("A data ACK reports the captured payload length and unshifted sequence")
    func dataSegmentFacts() {
        let facts = try? #require(decodeFacts(flags: 0x10, payload: [1, 2, 3, 4], sequence: 200))
        if let facts {
            #expect(facts.flags == [.ack])
            #expect(facts.payloadSequence == 200) // no SYN
            #expect(facts.payloadLength == 4)
        }
    }

    @Test("FIN and RST bits are read from the typed flags")
    func finAndRstFacts() {
        #expect(decodeFacts(flags: 0x01)?.flags == [.fin])
        let rst = try? #require(decodeFacts(flags: 0x04))
        if let rst {
            #expect(rst.flags == [.rst])
            #expect(rst.flags.contains(.rst))
        }
    }

    @Test("The acknowledgement number is stored even without the ACK flag")
    func acknowledgementStoredWithoutAckFlag() {
        // A hand-built SYN (no ACK flag) whose acknowledgement field is non-zero.
        let segment: [UInt8] =
            [0x9C, 0x40, 0x01, 0xBB] + // srcPort 40000, dstPort 443
            [0x00, 0x00, 0x00, 0x64] + // seq 100
            [0x0A, 0x0B, 0x0C, 0x0D] + // ack — present with the ACK flag clear
            [0x50, 0x02] + // data offset 5 words, SYN only
            [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.1", dst: "203.0.113.7", payload: segment
        )
        let facts = PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(), originalLength: frame.count
        ).tcpFacts
        #expect(facts?.acknowledgementNumber == 0x0A0B0C0D)
        #expect(facts?.flags.contains(.ack) == false)
        #expect(facts?.payloadSequence == 101) // SYN still consumes one
    }

    // MARK: Private

    private func decodeFacts(flags: UInt8, payload: [UInt8] = [], sequence: UInt32 = 1) -> TCPSegmentFacts? {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.1", dst: "203.0.113.7",
            payload: PacketBuilder.tcp(
                srcPort: 40_000, dstPort: 443, flags: flags, payload: payload, sequence: sequence
            )
        )
        return PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000), originalLength: frame.count
        ).tcpFacts
    }
}

// MARK: - DNSAnswerRetentionTests

@Suite("DNS answer retention cap")
struct DNSAnswerRetentionTests {
    @Test("A response below the cap retains every answer and omits none")
    func belowCapRetainsAll() {
        let answers = (1 ... 10).map { "198.51.100.\($0)" }
        let frame = PacketBuilder.dnsResponseFrame(
            name: "few.example", answers: answers, src: "203.0.113.53", dst: "198.51.100.10"
        )
        let packet = decodeFrame(frame)
        #expect(packet.dnsAnswers == answers)
        #expect(packet.dnsAnswersOmittedCount == 0)
    }

    @Test("A response beyond the cap retains 64 answers and counts the remainder")
    func beyondCapRetains64AndCountsOmitted() {
        let answers = (1 ... 70).map { "198.51.100.\($0)" }
        let frame = PacketBuilder.dnsResponseFrame(
            name: "many.example", answers: answers, src: "203.0.113.53", dst: "198.51.100.10"
        )
        let packet = decodeFrame(frame)
        #expect(packet.dnsAnswers.count == 64)
        #expect(packet.dnsAnswers == Array(answers.prefix(64))) // first-seen order
        #expect(packet.dnsAnswersOmittedCount == 6)

        // The rendered "Answer N" display fields are capped identically.
        let answerFields = packet.layer(.dns)?.fields.filter { $0.name.hasPrefix("Answer ") } ?? []
        #expect(answerFields.count == 64)
    }

    @Test("Reassembled TCP DNS carries the same answer omission metadata")
    func reassembledTCPDNSCarriesOmissionCount() {
        let answers = (1 ... 70).map { "198.51.100.\($0)" }
        let dns = PacketBuilder.dnsResponse(name: "many-tcp.example", answers: answers)
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let metadata = PacketDecoder.decodeReassembledTCPPayload(
            payload, sourcePort: 53, destinationPort: 52_000
        )
        #expect(metadata?.dnsAnswers == Array(answers.prefix(64)))
        #expect(metadata?.dnsAnswersOmittedCount == 6)
    }
}

// MARK: - ApplicationMatcherPrecedenceTests

/// Guards the first-match-wins precedence and gates of the whole-frame TCP/UDP
/// application matcher chains: a passing higher-priority gate always wins, and a
/// selected candidate never falls through to a lower-priority one.
@Suite("Application matcher precedence and gates")
struct ApplicationMatcherPrecedenceTests {
    // MARK: Internal

    // MARK: TCP frame precedence

    @Test("A TLS record on TCP port 53 is classified as TLS, not DNS")
    func tlsOnPort53StaysTLS() {
        let frame = PacketBuilder.tlsRecordFrame(
            contentType: 23, body: [0x00], src: "192.168.1.5", dst: "1.1.1.1",
            srcPort: 50_000, dstPort: 53
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .tls)
    }

    @Test("An HTTP-looking payload on TCP port 53 selects DNS and never falls through to HTTP")
    func port53DoesNotFallThroughToHTTP() {
        let payload = Array("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "192.168.1.5", dst: "1.1.1.1",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 53, flags: 0x18, payload: payload)
        )
        let packet = decodeFrame(frame)
        // DNS is selected on the port gate before HTTP is ever considered; a DNS decode
        // failure on the HTTP bytes must not reclassify the frame as HTTP.
        #expect(packet.appProtocol != .http)
    }

    // MARK: UDP frame precedence / gates

    @Test("STUN on UDP port 443 stays STUN and is not treated as QUIC")
    func stunOnPort443StaysSTUN() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.168.1.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 443, payload: stunBinding())
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .stun)
    }

    @Test("QUIC content without a 443 endpoint stays UDP-only")
    func quicWithout443StaysUDP() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.168.1.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 60_000, payload: quicLongHeader())
        )
        let packet = decodeFrame(frame)
        #expect(packet.transport == .udp)
        #expect(packet.appProtocol == nil)
    }

    @Test("The same QUIC content on UDP port 443 is classified as QUIC")
    func quicOn443IsQUIC() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.168.1.5", dst: "203.0.113.9",
            payload: PacketBuilder.udp(srcPort: 50_000, dstPort: 443, payload: quicLongHeader())
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol == .quic)
    }

    @Test("Port 53 wins before the QUIC gate on a 443↔53 datagram")
    func port53WinsBeforeQUIC() {
        // src 443, dst 53: both the DNS port gate and the QUIC 443 gate would pass, but
        // DNS precedes QUIC, so QUIC must never be selected.
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "203.0.113.9", dst: "192.168.1.5",
            payload: PacketBuilder.udp(srcPort: 443, dstPort: 53, payload: quicLongHeader())
        )
        let packet = decodeFrame(frame)
        #expect(packet.appProtocol != .quic)
    }

    // MARK: Private

    // MARK: Fixtures

    /// A minimal 20-byte STUN Binding Request: type, zero length, magic cookie, txid.
    private func stunBinding() -> [UInt8] {
        var bytes: [UInt8] = [0x00, 0x01, 0x00, 0x00] // Binding Request, message length 0
        bytes += [0x21, 0x12, 0xA4, 0x42] // magic cookie
        bytes += Array(repeating: 0xAB, count: 12) // transaction id
        return bytes
    }

    /// A minimal clear-text QUIC v1 long header with zero-length connection IDs.
    private func quicLongHeader() -> [UInt8] {
        [0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]
    }
}

// MARK: - ReassembledApplicationTests

/// Confirms the reassembled TCP chain keeps its completion rules, DNS length-prefix
/// gate, and no-fall-through behavior after centralization.
@Suite("Reassembled TCP application classification")
struct ReassembledApplicationTests {
    @Test("A complete reassembled TLS ClientHello reports TLS, SNI, and completion")
    func reassembledTLSComplete() {
        let bytes = PacketBuilder.tlsClientHello(sni: "api.example.com")
        let result = PacketDecoder.decodeReassembledTCPPayload(bytes, sourcePort: 52_000, destinationPort: 443)
        #expect(result?.appProtocol == .tls)
        #expect(result?.sni == "api.example.com")
        #expect(result?.isComplete == true)
    }

    @Test("A truncated reassembled TLS record stays TLS and reports incomplete")
    func reassembledTLSFragment() {
        // Content type 23, declared body 100 bytes, only 10 captured → a fragment.
        let bytes: [UInt8] = [23, 0x03, 0x03, 0x00, 0x64] + Array(repeating: 0, count: 10)
        let result = PacketDecoder.decodeReassembledTCPPayload(bytes, sourcePort: 52_000, destinationPort: 443)
        #expect(result?.appProtocol == .tls)
        #expect(result?.isComplete == false)
    }

    @Test("A complete reassembled DNS response reports DNS and completion")
    func reassembledDNSComplete() {
        let dns = PacketBuilder.dnsResponse(name: "example.com", answers: ["93.184.16.34"])
        let payload = [UInt8(dns.count >> 8), UInt8(dns.count & 0xFF)] + dns
        let result = PacketDecoder.decodeReassembledTCPPayload(payload, sourcePort: 53, destinationPort: 52_000)
        #expect(result?.appProtocol == .dns)
        #expect(result?.dnsQuery == "example.com")
        #expect(result?.isComplete == true)
    }

    @Test("Reassembled DNS with no length prefix yet yields nil")
    func reassembledDNSMissingLengthPrefix() {
        let result = PacketDecoder.decodeReassembledTCPPayload([0x00], sourcePort: 53, destinationPort: 52_000)
        #expect(result == nil)
    }

    @Test("Reassembled DNS whose declared length has not fully arrived yields nil, not HTTP")
    func reassembledDNSIncompleteDoesNotFallThrough() {
        // The 2-byte prefix declares 100 bytes; only an HTTP-looking remainder is present.
        // The DNS gate is selected on the port, so the incomplete length must yield nil
        // rather than falling through to the HTTP candidate.
        let remainder = Array("GET / HTTP/1.1\r\n\r\n".utf8)
        let payload: [UInt8] = [0x00, 0x64] + remainder
        let result = PacketDecoder.decodeReassembledTCPPayload(payload, sourcePort: 53, destinationPort: 52_000)
        #expect(result == nil)
    }

    @Test("A complete reassembled HTTP request reports HTTP and completion")
    func reassembledHTTPComplete() {
        let bytes = Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        let result = PacketDecoder.decodeReassembledTCPPayload(bytes, sourcePort: 52_000, destinationPort: 80)
        #expect(result?.appProtocol == .http)
        #expect(result?.isComplete == true)
    }

    @Test("A reassembled HTTP request without a header terminator reports incomplete")
    func reassembledHTTPIncomplete() {
        let bytes = Array("GET / HTTP/1.1\r\nHost: example.com".utf8)
        let result = PacketDecoder.decodeReassembledTCPPayload(bytes, sourcePort: 52_000, destinationPort: 80)
        #expect(result?.appProtocol == .http)
        #expect(result?.isComplete == false)
    }
}
