import Foundation
import Testing
@testable import Tracexy

struct FrameExpressionTests {
    @Test("Capture-interface direction preserves unknown under negation and boolean composition")
    func captureDirectionPredicate() throws {
        let packet = DecodedPacket(timestamp: nil, originalLength: 60)
        let inbound = FrameFilterFacts(packet: packet, captureDirection: .inbound)
        let outbound = FrameFilterFacts(packet: packet, captureDirection: .outbound)
        let unknown = FrameFilterFacts(packet: packet, captureDirection: .unknown)
        var parser = FrameExpressionParser()
        let inboundExpression = try parser.parse("frame.capture_direction == inbound")
        let outboundExpression = try parser.parse("frame.capture_direction == outbound")

        #expect(inboundExpression.evaluate(inbound) == .yes)
        #expect(inboundExpression.evaluate(outbound) == .no)
        #expect(outboundExpression.evaluate(outbound) == .yes)
        #expect(outboundExpression.evaluate(inbound) == .no)
        #expect(inboundExpression.evaluate(unknown) == .unknown)
        #expect(try parser.parse("not frame.capture_direction == inbound").evaluate(unknown) == .unknown)
        #expect(try parser.parse("frame.len >= 0 or frame.capture_direction == inbound")
            .evaluate(unknown) == .yes)
        #expect(throws: FrameExpressionError.self) {
            _ = try parser.parse("frame.capture_direction == unknown")
        }
    }

    @Test
    func matchesOnlyTheObservedFrame() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.sourceEndpoint = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        packet.destinationEndpoint = IPEndpoint(ip: "198.51.100.7", port: 443)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 2, flags: [.rst, .ack], windowSize: 0,
            headerLength: 20, payloadSequence: 1, payloadLength: 0, options: TCPOptionFacts()
        )
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        let matching = try parser.parse("tcp.rst and tcp.port == 443 and ip.src == 192.0.2.10")
        let nonmatching = try parser.parse("tcp.syn or ip.dst == 203.0.113.1")
        #expect(matching.evaluate(facts) == .yes)
        #expect(nonmatching.evaluate(facts) == .no)
        #expect(try parser.parse("ip.addr == 198.51.100.7").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.addr == 192.0.2.10").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.addr == 203.0.113.1").evaluate(facts) == .no)
        #expect(try parser.parse("tcp.syn or tcp.rst and ip.src == 192.0.2.10").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.srcport == 50000").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.srcport == 443").evaluate(facts) == .no)
        #expect(try parser.parse("tcp.dstport == 443").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.dstport == 50000").evaluate(facts) == .no)
    }

    @Test
    func ipAddressTermsDoNotTreatARPEndpointsAsIPHeaders() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 42)
        packet.sourceEndpoint = IPEndpoint(ip: "192.0.2.10", port: 0)
        packet.destinationEndpoint = IPEndpoint(ip: "192.0.2.11", port: 0)
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.addr == 192.0.2.10").evaluate(facts) == .no)
    }

    @Test
    func filtersRawTCPSequenceAndAcknowledgementValues() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: .max, acknowledgementNumber: 0, flags: [], windowSize: 0,
            headerLength: 20, payloadSequence: 0, payloadLength: 0, options: TCPOptionFacts()
        )
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("tcp.seq_raw == 4294967295").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.ack_raw == 0").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.seq_raw == 0").evaluate(facts) == .no)
        #expect(try parser.parse("tcp.ack_raw == 1").evaluate(facts) == .no)
        #expect(try parser.parse("tcp.seq_raw == 4294967295 and tcp.ack_raw == 0").evaluate(facts) == .yes)

        var incomplete = DecodedPacket(timestamp: nil, originalLength: 54)
        incomplete.decodeStop = .cutShort
        let partial = FrameFilterFacts(packet: incomplete)
        #expect(try parser.parse("tcp.seq_raw == 1").evaluate(partial) == .unknown)
        #expect(try parser.parse("not tcp.ack_raw == 0").evaluate(partial) == .unknown)
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("tcp.seq_raw > 0") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("tcp.ack_raw == 4294967296") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("tcp.seq_raw == -1") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("tcp.ack_raw == 1 trailing") }
    }

    @Test
    func filtersIPv4TTLAndIPv6HopLimitAcrossTunnelLayers() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 90)
        packet.layers = [DecodedLayer(
            proto: .ipv4, title: "Outer IPv4", fields: [DecodedField(name: "TTL", value: "64")], children: [
                DecodedLayer(proto: .ipv6, title: "Inner IPv6", fields: [DecodedField(name: "Hop Limit", value: "32")]),
            ]
        )]
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.ttl == 64").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.ttl < 32").evaluate(facts) == .no)
        #expect(try parser.parse("ipv6.hlim <= 32").evaluate(facts) == .yes)
        #expect(try parser.parse("ipv6.hlim > 32").evaluate(facts) == .no)
        #expect(try parser.parse("not ip.ttl == 65").evaluate(facts) == .yes)
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("ip.ttl == 256") }

        var truncated = packet
        truncated.decodeStop = .cutShort
        let partial = FrameFilterFacts(packet: truncated)
        #expect(try parser.parse("ip.ttl == 63").evaluate(partial) == .unknown)
        // A decoded Hop Limit that matches makes its negation false even if
        // decoding later stops; the observed header is positive evidence.
        #expect(try parser.parse("not ipv6.hlim == 32").evaluate(partial) == .no)
    }

    @Test
    func filtersIPv4MoreFragmentsAndByteOffsetsWithoutLosingUnknown() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 120)
        packet.layers = [DecodedLayer(
            proto: .ipv4, title: "Outer IPv4", fields: [
                DecodedField(name: "Fragment Offset", value: "0"),
                DecodedField(name: "More Fragments", value: "Yes"),
            ], children: [DecodedLayer(
                proto: .ipv4, title: "Inner IPv4", fields: [
                    DecodedField(name: "Fragment Offset", value: "1480"),
                    DecodedField(name: "More Fragments", value: "No"),
                ]
            )]
        )]
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.flags.mf").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.frag_offset == 1480").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.frag_offset > 1000").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.frag_offset == 8").evaluate(facts) == .no)
        #expect(try parser.parse("not ip.flags.mf").evaluate(facts) == .no)
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("ip.frag_offset == 65536") }

        var incomplete = DecodedPacket(timestamp: nil, originalLength: 120)
        incomplete.decodeStop = .cutShort
        let partial = FrameFilterFacts(packet: incomplete)
        #expect(try parser.parse("ip.flags.mf").evaluate(partial) == .unknown)
        #expect(try parser.parse("not ip.flags.mf").evaluate(partial) == .unknown)
        #expect(try parser.parse("ip.frag_offset == 0").evaluate(partial) == .unknown)
    }

    @Test
    func decodedFrameFilterOffersDirectionalPortsAndParsesEachTerm() throws {
        let sourceTCP = DecodedFrameFilter.term(proto: .tcp, field: "Source Port", value: "50000")
        let destinationTCP = DecodedFrameFilter.term(proto: .tcp, field: "Destination Port", value: "443")
        let sequence = DecodedFrameFilter.term(proto: .tcp, field: "Seq", value: "4294967295")
        let acknowledgement = DecodedFrameFilter.term(proto: .tcp, field: "Ack", value: "0")
        let sourceUDP = DecodedFrameFilter.term(proto: .udp, field: "Source Port", value: "53")
        let destinationIP = DecodedFrameFilter.term(proto: .ipv6, field: "Destination", value: "2001:db8::1")
        let ttl = DecodedFrameFilter.term(proto: .ipv4, field: "TTL", value: "64")
        let hopLimit = DecodedFrameFilter.term(proto: .ipv6, field: "Hop Limit", value: "32")
        let fragmentOffset = DecodedFrameFilter.term(proto: .ipv4, field: "Fragment Offset", value: "1480")
        let moreFragments = DecodedFrameFilter.term(proto: .ipv4, field: "More Fragments", value: "Yes")
        let noMoreFragments = DecodedFrameFilter.term(proto: .ipv4, field: "More Fragments", value: "No")
        let tcpFlagTerms = [
            ("FIN", "tcp.flags.fin"), ("SYN", "tcp.flags.syn"), ("RST", "tcp.flags.reset"),
            ("PSH", "tcp.flags.push"), ("Acknowledgment (ACK)", "tcp.flags.ack"),
            ("URG", "tcp.flags.urg"), ("ECE", "tcp.flags.ece"), ("CWR", "tcp.flags.cwr"),
        ]
        let icmpType = DecodedFrameFilter.term(proto: .icmp, field: "Type", value: "Destination Unreachable (3)")
        let icmpCode = DecodedFrameFilter.term(proto: .icmp, field: "Code", value: "3")
        let icmpv6Type = DecodedFrameFilter.term(proto: .icmpv6, field: "Type", value: "Packet Too Big (2)")
        let icmpv6Code = DecodedFrameFilter.term(proto: .icmpv6, field: "Code", value: "0")
        #expect(sourceTCP == "tcp.srcport == 50000")
        #expect(destinationTCP == "tcp.dstport == 443")
        #expect(sequence == "tcp.seq_raw == 4294967295")
        #expect(acknowledgement == "tcp.ack_raw == 0")
        #expect(sourceUDP == "udp.srcport == 53")
        #expect(destinationIP == "ip.dst == 2001:db8::1")
        #expect(ttl == "ip.ttl == 64")
        #expect(hopLimit == "ipv6.hlim == 32")
        #expect(fragmentOffset == "ip.frag_offset == 1480")
        #expect(moreFragments == "ip.flags.mf")
        #expect(noMoreFragments == "not ip.flags.mf")
        for (field, term) in tcpFlagTerms {
            #expect(DecodedFrameFilter.term(proto: .tcp, field: field, value: "Yes") == term)
            #expect(DecodedFrameFilter.term(proto: .tcp, field: field, value: "No") == "not \(term)")
            #expect(DecodedFrameFilter.term(proto: .tcp, field: field, value: "maybe") == nil)
            #expect(DecodedFrameFilter.availability(in: [DecodedLayer(proto: .tcp, title: "TCP")])
                .supports(proto: .tcp, field: field))
        }
        #expect(icmpType == "icmp.type == 3")
        #expect(icmpCode == "icmp.code == 3")
        #expect(icmpv6Type == "icmpv6.type == 2")
        #expect(icmpv6Code == "icmpv6.code == 0")
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "TTL", value: "256") == nil)
        #expect(DecodedFrameFilter.term(proto: .ipv6, field: "Hop Limit", value: "-1") == nil)
        #expect(DecodedFrameFilter.term(proto: .icmp, field: "Type", value: "Destination Unreachable (256)") == nil)
        #expect(DecodedFrameFilter.term(proto: .icmpv6, field: "Type", value: "2 trailing") == nil)
        #expect(DecodedFrameFilter.term(proto: .tcp, field: "Source Port", value: "70000") == nil)
        #expect(DecodedFrameFilter.term(proto: .tcp, field: "Seq", value: "4294967296") == nil)
        #expect(DecodedFrameFilter.term(proto: .tcp, field: "Ack", value: "0") == "tcp.ack_raw == 0")
        #expect(DecodedFrameFilter.term(proto: .ethernet, field: "Source", value: "00:11:22:33:44:55") == nil)
        for expression in [
            sourceTCP,
            destinationTCP,
            sequence,
            acknowledgement,
            sourceUDP,
            destinationIP,
            ttl,
            hopLimit,
            fragmentOffset,
            moreFragments,
            noMoreFragments,
            icmpType,
            icmpCode,
            icmpv6Type,
            icmpv6Code
        ].compactMap({ $0 }) {
            var parser = FrameExpressionParser()
            _ = try parser.parse(expression)
        }
    }

    @Test
    func combiningFrameFilterGroupsAnExistingCaseInsensitiveExpression() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.sourceEndpoint = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        packet.destinationEndpoint = IPEndpoint(ip: "198.51.100.7", port: 443)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 2, flags: [.rst], windowSize: 0,
            headerLength: 20, payloadSequence: 1, payloadLength: 0, options: TCPOptionFacts()
        )
        let expressionText = DecodedFieldFilter.Combination.andSelected
            .combineFrame("tcp.rst OR\ttcp.syn", "tcp.dstport == 80")
        #expect(expressionText == "(tcp.rst OR\ttcp.syn) and tcp.dstport == 80")
        var parser = FrameExpressionParser()
        #expect(try parser.parse(expressionText).evaluate(FrameFilterFacts(packet: packet)) == .no)
    }

    @Test
    func tunnelLayerMultiplicitySuppressesAmbiguousFieldFilters() {
        let layers = [DecodedLayer(
            proto: .ipv4, title: "Outer IP", children: [
                DecodedLayer(proto: .udp, title: "Tunnel UDP", children: [
                    DecodedLayer(proto: .ipv6, title: "Inner IP", children: [
                        DecodedLayer(proto: .tcp, title: "Inner TCP"),
                        DecodedLayer(proto: .icmpv6, title: "Nested ICMPv6"),
                        DecodedLayer(proto: .icmp, title: "Nested ICMPv4"),
                    ]),
                    DecodedLayer(proto: .icmp, title: "Outer ICMP"),
                    DecodedLayer(proto: .icmpv6, title: "Outer ICMPv6"),
                ]),
            ]
        )]
        let availability = DecodedFrameFilter.availability(in: layers)
        #expect(!availability.supports(proto: .ipv4, field: "Source"))
        #expect(!availability.supports(proto: .ipv4, field: "TTL"))
        #expect(!availability.supports(proto: .ipv4, field: "Fragment Offset"))
        #expect(!availability.supports(proto: .ipv4, field: "Identification"))
        #expect(!availability.supports(proto: .ipv6, field: "Hop Limit"))
        #expect(!availability.supports(proto: .udp, field: "Destination Port"))
        #expect(!availability.supports(proto: .tcp, field: "Source Port"))
        #expect(!availability.supports(proto: .tcp, field: "Window"))
        #expect(!availability.supports(proto: .tcp, field: "Seq"))
        #expect(!availability.supports(proto: .tcp, field: "Ack"))
        #expect(!availability.supports(proto: .icmp, field: "Type"))
        #expect(!availability.supports(proto: .icmpv6, field: "Code"))
        #expect(!availability.supports(proto: .dns, field: "Transaction ID"))

        let ordinary = DecodedFrameFilter.availability(in: [
            DecodedLayer(proto: .ipv4, title: "IP"),
            DecodedLayer(proto: .tcp, title: "TCP"),
        ])
        #expect(ordinary.supports(proto: .ipv4, field: "Source"))
        #expect(ordinary.supports(proto: .ipv4, field: "TTL"))
        #expect(ordinary.supports(proto: .ipv4, field: "Identification"))
        #expect(ordinary.supports(proto: .ipv4, field: "Fragment Offset"))
        #expect(ordinary.supports(proto: .tcp, field: "Source Port"))
        #expect(ordinary.supports(proto: .tcp, field: "Window"))
        #expect(ordinary.supports(proto: .tcp, field: "Seq"))
        #expect(ordinary.supports(proto: .tcp, field: "Ack"))

        let icmpLayers = DecodedFrameFilter.availability(in: [
            DecodedLayer(proto: .icmp, title: "ICMP"),
            DecodedLayer(proto: .icmpv6, title: "ICMPv6"),
        ])
        #expect(icmpLayers.supports(proto: .icmp, field: "Type"))
        #expect(icmpLayers.supports(proto: .icmp, field: "Code"))
        #expect(icmpLayers.supports(proto: .icmpv6, field: "Type"))
        #expect(icmpLayers.supports(proto: .icmpv6, field: "Code"))

        let dnsLayers = DecodedFrameFilter.availability(in: [DecodedLayer(proto: .mdns, title: "mDNS")])
        #expect(dnsLayers.supports(proto: .mdns, field: "Transaction ID"))
        #expect(dnsLayers.supports(proto: .mdns, field: "Truncated (TC)"))
        let ambiguousDNS = DecodedFrameFilter.availability(in: [
            DecodedLayer(proto: .dns, title: "DNS"),
            DecodedLayer(proto: .mdns, title: "mDNS"),
        ])
        #expect(!ambiguousDNS.supports(proto: .dns, field: "Transaction ID"))
        #expect(!ambiguousDNS.supports(proto: .dns, field: "Truncated (TC)"))
    }

    @Test
    func frameLengthUsesOriginalLengthEvenWhenDecodeStops() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 128)
        packet.decodeStop = .cutShort
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("frame.len==128").evaluate(facts) == .yes)
        #expect(try parser.parse("frame.len > 127").evaluate(facts) == .yes)
        #expect(try parser.parse("frame.len >= 128").evaluate(facts) == .yes)
        #expect(try parser.parse("frame.len < 129").evaluate(facts) == .yes)
        #expect(try parser.parse("frame.len <= 128").evaluate(facts) == .yes)
        #expect(try parser.parse("frame.len > 128").evaluate(facts) == .no)
        #expect(try parser.parse("not frame.len < 128").evaluate(facts) == .yes)
    }

    @Test
    func captureLengthAndTruncationUseObservedCaptureMetadata() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 128)
        packet.decodeStop = .cutShort
        var parser = FrameExpressionParser()
        let truncated = FrameFilterFacts(packet: packet, capturedLength: 54)
        #expect(try parser.parse("frame.cap_len == 54").evaluate(truncated) == .yes)
        #expect(try parser.parse("frame.cap_len > 54").evaluate(truncated) == .no)
        #expect(try parser.parse("frame.cap_len <= 54").evaluate(truncated) == .yes)
        #expect(try parser.parse("frame.truncated").evaluate(truncated) == .yes)
        #expect(try parser.parse("not frame.truncated").evaluate(truncated) == .no)
        let complete = FrameFilterFacts(packet: packet, capturedLength: 128)
        #expect(try parser.parse("frame.truncated").evaluate(complete) == .no)
        #expect(try parser.parse("frame.cap_len >= 128").evaluate(complete) == .yes)
        let missing = FrameFilterFacts(packet: packet)
        #expect(try parser.parse("not frame.truncated").evaluate(missing) == .unknown)
        #expect(try parser.parse("frame.cap_len == 54").evaluate(missing) == .unknown)
        let normalized = FrameFilterFacts(packet: packet, capturedLength: 144, originalLength: 144)
        #expect(try parser.parse("frame.len == 144 and frame.cap_len == 144").evaluate(normalized) == .yes)
        #expect(try parser.parse("frame.truncated").evaluate(normalized) == .no)
    }

    @Test
    func tcpWindowValueUsesTheObservedRawHeaderField() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 2, flags: [.ack], windowSize: 0,
            headerLength: 20, payloadSequence: 1, payloadLength: 0, options: TCPOptionFacts()
        )
        var parser = FrameExpressionParser()
        let zero = FrameFilterFacts(packet: packet)
        #expect(try parser.parse("tcp.window_size_value == 0").evaluate(zero) == .yes)
        #expect(try parser.parse("tcp.window_size_value < 1").evaluate(zero) == .yes)
        #expect(try parser.parse("tcp.window_size_value > 0").evaluate(zero) == .no)
        #expect(try parser.parse("not tcp.window_size_value == 0").evaluate(zero) == .no)
        packet.tcpFacts = nil
        packet.decodeStop = .cutShort
        #expect(try parser.parse("not tcp.window_size_value == 0")
            .evaluate(FrameFilterFacts(packet: packet)) == .unknown)
        packet.decodeStop = nil
        #expect(try parser.parse("tcp.window_size_value == 0")
            .evaluate(FrameFilterFacts(packet: packet)) == .no)
    }

    @Test
    func tcpFlagPredicatesMatchObservedHeaderBitsAndPreserveUnknown() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 2, flags: [.fin, .syn, .rst, .psh, .ack, .urg, .ece, .cwr],
            windowSize: 1, headerLength: 20, payloadSequence: 1, payloadLength: 0, options: TCPOptionFacts()
        )
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        for field in [
            "tcp.flags.fin", "tcp.flags.syn", "tcp.flags.reset", "tcp.flags.push",
            "tcp.flags.ack", "tcp.flags.urg", "tcp.flags.ece", "tcp.flags.cwr",
        ] {
            #expect(try parser.parse(field).evaluate(facts) == .yes)
        }
        packet.tcpFacts = TCPSegmentFacts(
            sequenceNumber: 1, acknowledgementNumber: 2, flags: [.ack], windowSize: 1,
            headerLength: 20, payloadSequence: 1, payloadLength: 0, options: TCPOptionFacts()
        )
        #expect(try parser.parse("tcp.flags.ack").evaluate(FrameFilterFacts(packet: packet)) == .yes)
        #expect(try parser.parse("tcp.flags.fin").evaluate(FrameFilterFacts(packet: packet)) == .no)
        packet.tcpFacts = nil
        packet.decodeStop = .cutShort
        let truncated = FrameFilterFacts(packet: packet)
        #expect(try parser.parse("tcp.flags.ack").evaluate(truncated) == .unknown)
        #expect(try parser.parse("not tcp.flags.ack").evaluate(truncated) == .unknown)
    }

    @Test
    func truncationStaysUnknownUnderNegation() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.decodeStop = .cutShort
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("not tcp.rst").evaluate(facts) == .unknown)
        #expect(try parser.parse("tcp.rst or tcp.syn").evaluate(facts) == .unknown)
        #expect(try parser.parse("tcp.rst and ip.src == 192.0.2.1").evaluate(facts) == .unknown)
        #expect(try parser.parse("tcp.rst").evaluate(nil) == .unknown)
    }

    @Test
    func observedIPHeaderRemainsFilterableWhenTransportIsCutShort() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.layers = [DecodedLayer(
            proto: .ipv4, title: "IPv4", fields: [
                DecodedField(name: "Source", value: "192.0.2.9"),
                DecodedField(name: "Destination", value: "198.51.100.8"),
            ]
        )]
        packet.decodeStop = .cutShort
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.src == 192.0.2.9").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.addr == 198.51.100.8").evaluate(facts) == .yes)
        #expect(try parser.parse("not tcp.rst").evaluate(facts) == .unknown)
    }

    @Test
    func incompleteAddressPairDoesNotProveAnAddressAbsent() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.sourceEndpoint = IPEndpoint(ip: "192.0.2.9", port: 443)
        packet.decodeStop = .cutShort
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.addr == 192.0.2.9").evaluate(facts) == .yes)
        #expect(try parser.parse("ip.addr == 198.51.100.8").evaluate(facts) == .unknown)
        #expect(try parser.parse("not ip.addr == 198.51.100.8").evaluate(facts) == .unknown)
    }

    @Test
    func unfinishedFragmentCannotProveTransportFieldAbsent() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 54)
        packet.ipFragment = IPFragmentFacts(
            version: .v4, source: "192.0.2.9", destination: "198.51.100.8",
            identification: 7, protocolNumber: 6, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.src == 192.0.2.9").evaluate(facts) == .yes)
        #expect(try parser.parse("tcp.rst").evaluate(facts) == .unknown)
        #expect(try parser.parse("not tcp.rst").evaluate(facts) == .unknown)
    }

    @Test
    func udpDNSResponseCodeMatchesOnlyObservedHeader() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 70)
        packet.transport = .udp
        packet.sourceEndpoint = IPEndpoint(ip: "198.51.100.53", port: 53)
        packet.destinationEndpoint = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        packet.dnsFacts = try DNSMessageFacts(dnsHeader: PacketBuffer([
            0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0,
        ]))
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("udp.port == 53 and dns.response and dns.rcode == 3").evaluate(facts) == .yes)
        #expect(try parser.parse("dns.id == 4660").evaluate(facts) == .yes)
        #expect(try parser.parse("dns.id == 4661").evaluate(facts) == .no)
        #expect(try parser.parse("udp.port == 53 and dns.id == 4660").evaluate(facts) == .yes)
        #expect(try parser.parse("dns.rcode == 2").evaluate(facts) == .no)
        #expect(try parser.parse("tcp.port == 53").evaluate(facts) == .no)
    }

    @Test
    func dnsIdentifierUsesOnlyObservedFixedHeaderAndPreservesUnknown() throws {
        let maximumID = try DNSMessageFacts(dnsHeader: PacketBuffer([
            0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]))
        var packet = DecodedPacket(timestamp: nil, originalLength: 70)
        packet.dnsFacts = maximumID
        packet.decodeStop = .cutShort // A malformed variable body does not erase a decoded ID.
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("dns.id == 65535").evaluate(facts) == .yes)
        #expect(try parser.parse("dns.id == 0").evaluate(facts) == .no)

        var zeroIDPacket = DecodedPacket(timestamp: nil, originalLength: 70)
        zeroIDPacket.dnsFacts = try DNSMessageFacts(dnsHeader: PacketBuffer(Array(repeating: 0, count: 12)))
        #expect(try parser.parse("dns.id == 0").evaluate(FrameFilterFacts(packet: zeroIDPacket)) == .yes)

        var stopped = DecodedPacket(timestamp: nil, originalLength: 70)
        stopped.decodeStop = .cutShort
        let stoppedFacts = FrameFilterFacts(packet: stopped)
        #expect(try parser.parse("dns.id == 4660").evaluate(stoppedFacts) == .unknown)
        #expect(try parser.parse("not dns.id == 4660").evaluate(stoppedFacts) == .unknown)
        let completeNonDNS = FrameFilterFacts(packet: DecodedPacket(timestamp: nil, originalLength: 70))
        #expect(try parser.parse("dns.id == 0").evaluate(completeNonDNS) == .no)

        for protocolNumber in [UInt8(6), 17] {
            var fragment = DecodedPacket(timestamp: nil, originalLength: 70)
            fragment.ipFragment = IPFragmentFacts(
                version: .v4, source: "192.0.2.1", destination: "192.0.2.2",
                identification: 11, protocolNumber: protocolNumber, offset: 8, moreFragments: true,
                payloadRange: 0 ..< 0, isPayloadComplete: true
            )
            let fragmentFacts = FrameFilterFacts(packet: fragment)
            #expect(try parser.parse("dns.id == 4660").evaluate(fragmentFacts) == .unknown)
            #expect(try parser.parse("not dns.id == 4660").evaluate(fragmentFacts) == .unknown)
            #expect(try parser.parse("dns.flags.truncated").evaluate(fragmentFacts) == .unknown)
            #expect(try parser.parse("not dns.flags.truncated").evaluate(fragmentFacts) == .unknown)
        }

        var ipv6ExtensionFragment = DecodedPacket(timestamp: nil, originalLength: 70)
        ipv6ExtensionFragment.ipFragment = IPFragmentFacts(
            version: .v6, source: "2001:db8::1", destination: "2001:db8::2",
            identification: 12, protocolNumber: 60, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let ipv6Facts = FrameFilterFacts(packet: ipv6ExtensionFragment)
        #expect(try parser.parse("dns.id == 4660").evaluate(ipv6Facts) == .unknown)
        #expect(try parser.parse("not dns.id == 4660").evaluate(ipv6Facts) == .unknown)
        #expect(try parser.parse("dns.flags.truncated").evaluate(ipv6Facts) == .unknown)
        #expect(try parser.parse("not dns.flags.truncated").evaluate(ipv6Facts) == .unknown)

        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("dns.id == 65536") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("dns.id == -1") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("dns.id > 1") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("dns.id == 1 trailing") }
    }

    @Test
    func dnsTruncationBitIsDistinctFromCaptureTruncation() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 70)
        packet.dnsFacts = try DNSMessageFacts(dnsHeader: PacketBuffer([
            0x12, 0x34, 0x83, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ]))
        packet.decodeStop = .cutShort // The TC header bit survives a missing later body.
        let packetFacts = FrameFilterFacts(packet: packet, capturedLength: 70)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("dns.flags.truncated").evaluate(packetFacts) == .yes)
        #expect(try parser.parse("dns.response and dns.flags.truncated").evaluate(packetFacts) == .yes)
        #expect(try parser.parse("frame.truncated").evaluate(packetFacts) == .no)
        #expect(try parser.parse("not dns.flags.truncated").evaluate(packetFacts) == .no)

        var ordinaryHeader = DecodedPacket(timestamp: nil, originalLength: 70)
        ordinaryHeader.dnsFacts = try DNSMessageFacts(dnsHeader: PacketBuffer([
            0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
        ]))
        let capturedShort = FrameFilterFacts(packet: ordinaryHeader, capturedLength: 69)
        #expect(try parser.parse("dns.flags.truncated").evaluate(capturedShort) == .no)
        #expect(try parser.parse("frame.truncated").evaluate(capturedShort) == .yes)

        var missingHeader = DecodedPacket(timestamp: nil, originalLength: 70)
        missingHeader.decodeStop = .cutShort
        let unknown = FrameFilterFacts(packet: missingHeader)
        #expect(try parser.parse("dns.flags.truncated").evaluate(unknown) == .unknown)
        #expect(try parser.parse("not dns.flags.truncated").evaluate(unknown) == .unknown)
        #expect(DecodedFrameFilter.term(proto: .dns, field: "Truncated (TC)", value: "Yes") == "dns.flags.truncated")
        #expect(DecodedFrameFilter.term(proto: .llmnr, field: "Truncated (TC)", value: "No")
            == "not dns.flags.truncated")
        #expect(DecodedFrameFilter.term(proto: .mdns, field: "Truncated (TC)", value: "maybe") == nil)
    }

    @Test
    func ipv4IdentificationMatchesObservedHeadersAndPreservesUnknown() throws {
        var repeated = DecodedPacket(timestamp: nil, originalLength: 80)
        repeated.layers = [
            DecodedLayer(
                proto: .ipv4,
                title: "Outer IPv4",
                fields: [DecodedField(name: "Identification", value: "0x1234")]
            ),
            DecodedLayer(
                proto: .ipv4,
                title: "Inner IPv4",
                fields: [DecodedField(name: "Identification", value: "0xFFFF")]
            ),
            DecodedLayer(
                proto: .ipv4,
                title: "Zero-ID IPv4",
                fields: [DecodedField(name: "Identification", value: "0x0000")]
            ),
        ]
        let repeatedFacts = FrameFilterFacts(packet: repeated)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.id == 4660").evaluate(repeatedFacts) == .yes)
        #expect(try parser.parse("ip.id == 65535").evaluate(repeatedFacts) == .yes)
        #expect(try parser.parse("ip.id == 0").evaluate(repeatedFacts) == .yes)
        #expect(try parser.parse("ip.id == 42").evaluate(repeatedFacts) == .no)

        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Identification", value: "0x1234") == "ip.id == 4660")
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Identification", value: "1234") == nil)
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Identification", value: "0x10000") == nil)
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("ip.id == 65536") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("ip.id == -1") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("ip.id > 1") }

        var stopped = DecodedPacket(timestamp: nil, originalLength: 80)
        stopped.decodeStop = .cutShort
        let unknown = FrameFilterFacts(packet: stopped)
        #expect(try parser.parse("ip.id == 4660").evaluate(unknown) == .unknown)
        #expect(try parser.parse("not ip.id == 4660").evaluate(unknown) == .unknown)

        var ipv6Only = DecodedPacket(timestamp: nil, originalLength: 80)
        ipv6Only.layers = [DecodedLayer(proto: .ipv6, title: "IPv6")]
        #expect(try parser.parse("ip.id == 4660").evaluate(FrameFilterFacts(packet: ipv6Only)) == .no)

        var outerFragment = DecodedPacket(timestamp: nil, originalLength: 80)
        outerFragment.layers = [DecodedLayer(
            proto: .ipv4, title: "Outer IPv4", fields: [DecodedField(name: "Identification", value: "0x1234")]
        )]
        outerFragment.ipFragment = IPFragmentFacts(
            version: .v4, source: "192.0.2.1", destination: "192.0.2.2",
            identification: 0x1234, protocolNumber: 4, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let fragmentFacts = FrameFilterFacts(packet: outerFragment)
        #expect(try parser.parse("ip.id == 4660").evaluate(fragmentFacts) == .yes)
        #expect(try parser.parse("ip.id == 1").evaluate(fragmentFacts) == .unknown)
        #expect(try parser.parse("not ip.id == 1").evaluate(fragmentFacts) == .unknown)

        var udpTunnelFragment = DecodedPacket(timestamp: nil, originalLength: 80)
        udpTunnelFragment.layers = [DecodedLayer(
            proto: .ipv4, title: "Outer IPv4", fields: [DecodedField(name: "Identification", value: "0x1234")]
        )]
        udpTunnelFragment.ipFragment = IPFragmentFacts(
            version: .v4, source: "192.0.2.1", destination: "192.0.2.2",
            identification: 0x1234, protocolNumber: 17, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let udpTunnelFacts = FrameFilterFacts(packet: udpTunnelFragment)
        #expect(try parser.parse("ip.id == 4660").evaluate(udpTunnelFacts) == .yes)
        #expect(try parser.parse("ip.id == 1").evaluate(udpTunnelFacts) == .unknown)
        #expect(try parser.parse("not ip.id == 1").evaluate(udpTunnelFacts) == .unknown)

        var ipv6ExtensionFragment = DecodedPacket(timestamp: nil, originalLength: 80)
        ipv6ExtensionFragment.ipFragment = IPFragmentFacts(
            version: .v6, source: "2001:db8::1", destination: "2001:db8::2",
            identification: 0x1234, protocolNumber: 60, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let ipv6FragmentFacts = FrameFilterFacts(packet: ipv6ExtensionFragment)
        #expect(try parser.parse("ip.id == 1").evaluate(ipv6FragmentFacts) == .unknown)
        #expect(try parser.parse("not ip.id == 1").evaluate(ipv6FragmentFacts) == .unknown)
    }

    @Test
    func ipv4DontFragmentMatchesItsOwnBitAndPreservesUnknown() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 80)
        packet.layers = [
            DecodedLayer(
                proto: .ipv4, title: "Outer IPv4",
                fields: [DecodedField(name: "Don't Fragment", value: "No")]
            ),
            DecodedLayer(
                proto: .ipv4, title: "Inner IPv4",
                fields: [DecodedField(name: "Don't Fragment", value: "Yes")]
            ),
        ]
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("ip.flags.df").evaluate(facts) == .yes)
        #expect(try parser.parse("not ip.flags.df").evaluate(facts) == .no)
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Don't Fragment", value: "Yes") == "ip.flags.df")
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Don't Fragment", value: "No") == "not ip.flags.df")
        #expect(DecodedFrameFilter.term(proto: .ipv4, field: "Don't Fragment", value: "maybe") == nil)
        #expect(DecodedFrameFilter.availability(in: packet.layers).hasSingleIPLayer == false)

        var ipv6Only = DecodedPacket(timestamp: nil, originalLength: 80)
        ipv6Only.layers = [DecodedLayer(proto: .ipv6, title: "IPv6")]
        #expect(try parser.parse("ip.flags.df").evaluate(FrameFilterFacts(packet: ipv6Only)) == .no)

        var clear = DecodedPacket(timestamp: nil, originalLength: 80)
        clear.layers = [DecodedLayer(
            proto: .ipv4, title: "IPv4", fields: [DecodedField(name: "Don't Fragment", value: "No")]
        )]
        #expect(try parser.parse("ip.flags.df").evaluate(FrameFilterFacts(packet: clear)) == .no)
        #expect(try parser.parse("not ip.flags.df").evaluate(FrameFilterFacts(packet: clear)) == .yes)

        var stopped = DecodedPacket(timestamp: nil, originalLength: 80)
        stopped.decodeStop = .cutShort
        #expect(try parser.parse("ip.flags.df").evaluate(FrameFilterFacts(packet: stopped)) == .unknown)
        #expect(try parser.parse("not ip.flags.df").evaluate(FrameFilterFacts(packet: stopped)) == .unknown)

        var udpTunnelFragment = clear
        udpTunnelFragment.ipFragment = IPFragmentFacts(
            version: .v4, source: "192.0.2.1", destination: "192.0.2.2",
            identification: 1, protocolNumber: 17, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        #expect(try parser.parse("ip.flags.df").evaluate(FrameFilterFacts(packet: udpTunnelFragment)) == .unknown)
        #expect(try parser.parse("not ip.flags.df").evaluate(FrameFilterFacts(packet: udpTunnelFragment)) == .unknown)
        udpTunnelFragment.layers[0].fields = [DecodedField(name: "Don't Fragment", value: "Yes")]
        #expect(try parser.parse("ip.flags.df").evaluate(FrameFilterFacts(packet: udpTunnelFragment)) == .yes)
    }

    @Test
    func icmpTypeAndCodeMatchOnlyTheirObservedFamilyAndHeader() throws {
        var ipv4 = DecodedPacket(timestamp: nil, originalLength: 64)
        ipv4.icmpFacts = ICMPMessageFacts(family: .ipv4, type: 3, code: 3)
        let ipv4Facts = FrameFilterFacts(packet: ipv4)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("icmp.type == 3").evaluate(ipv4Facts) == .yes)
        #expect(try parser.parse("icmp.code == 3").evaluate(ipv4Facts) == .yes)
        #expect(try parser.parse("icmp.type == 11").evaluate(ipv4Facts) == .no)
        #expect(try parser.parse("icmpv6.type == 3").evaluate(ipv4Facts) == .no)
        #expect(try parser.parse("icmp.type == 3 and icmp.code == 3").evaluate(ipv4Facts) == .yes)

        var ipv6 = DecodedPacket(timestamp: nil, originalLength: 64)
        ipv6.icmpFacts = ICMPMessageFacts(family: .ipv6, type: 2, code: 0)
        let ipv6Facts = FrameFilterFacts(packet: ipv6)
        #expect(try parser.parse("icmpv6.type == 2").evaluate(ipv6Facts) == .yes)
        #expect(try parser.parse("icmpv6.code == 0").evaluate(ipv6Facts) == .yes)
        #expect(try parser.parse("icmp.type == 2").evaluate(ipv6Facts) == .no)
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("icmp.type == 256") }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("icmpv6.code > 0") }
    }

    @Test
    func incompleteICMPHeadersAndUnresolvedFragmentsRemainUnknownUnderNegation() throws {
        var ipv4Fragment = DecodedPacket(timestamp: nil, originalLength: 48)
        ipv4Fragment.ipFragment = IPFragmentFacts(
            version: .v4, source: "192.0.2.1", destination: "192.0.2.2",
            identification: 9, protocolNumber: 1, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        var ipv6Fragment = DecodedPacket(timestamp: nil, originalLength: 48)
        ipv6Fragment.ipFragment = IPFragmentFacts(
            version: .v6, source: "2001:db8::1", destination: "2001:db8::2",
            identification: 10, protocolNumber: 58, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        var truncated = DecodedPacket(timestamp: nil, originalLength: 48)
        truncated.decodeStop = .cutShort

        var parser = FrameExpressionParser()
        let cases: [(String, DecodedPacket)] = [
            ("icmp.type == 3", ipv4Fragment),
            ("not icmp.code == 3", ipv4Fragment),
            ("icmpv6.type == 2", ipv6Fragment),
            ("not icmpv6.code == 0", ipv6Fragment),
            ("icmp.type == 3", truncated),
            ("not icmpv6.type == 2", truncated),
        ]
        for (expression, packet) in cases {
            #expect(try parser.parse(expression).evaluate(FrameFilterFacts(packet: packet)) == .unknown)
        }

        let fragmentedFrame = PacketBuilder.ethernetIPv6(
            nextHeader: 44,
            src: [0xFE80],
            dst: [0xFE80, 0, 0, 0, 0, 0, 0, 1],
            payload: [60, 0, 0, 9, 0xAB, 0xCD, 0, 1]
                + [58, 0, 1, 4, 0, 0, 0, 0]
                + [2, 0, 0, 0, 0, 0, 0, 0]
        )
        let fragmentPacket = PacketDecoder.decode(
            PacketBuffer(fragmentedFrame), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: fragmentedFrame.count
        )
        #expect(fragmentPacket.ipFragment?.protocolNumber == 60)
        #expect(try parser.parse("icmpv6.type == 2").evaluate(FrameFilterFacts(packet: fragmentPacket)) == .unknown)
        #expect(try parser.parse("not icmpv6.type == 2").evaluate(FrameFilterFacts(packet: fragmentPacket)) == .unknown)
        #expect(try parser.parse("not (tcp.srcport == 50000 and tcp.seq_raw == 1000)")
            .evaluate(FrameFilterFacts(packet: fragmentPacket)) == .unknown)
        #expect(try parser.parse("not tcp.window_size_value == 0")
            .evaluate(FrameFilterFacts(packet: fragmentPacket)) == .unknown)

        let fullICMPv6Frame = PacketBuilder.ethernetIPv6(
            nextHeader: 58,
            src: [0xFE80],
            dst: [0xFE80, 0, 0, 0, 0, 0, 0, 1],
            payload: [2, 0, 0, 0, 0, 0, 0, 0]
        )
        let ipv6HeaderOnly = Array(fullICMPv6Frame.prefix(14 + 40))
        let headerOnlyPacket = PacketDecoder.decode(
            PacketBuffer(ipv6HeaderOnly), linkType: LinkType.ethernet,
            timestamp: nil, originalLength: fullICMPv6Frame.count
        )
        #expect(headerOnlyPacket.decodeStop == .cutShort)
        let headerOnlyFacts = FrameFilterFacts(packet: headerOnlyPacket)
        #expect(try parser.parse("icmpv6.type == 2").evaluate(headerOnlyFacts) == .unknown)
        #expect(try parser.parse("not icmpv6.type == 2").evaluate(headerOnlyFacts) == .unknown)
    }

    @Test
    func unfinishedUDPFragmentKeepsDNSAndPortUnknown() throws {
        var packet = DecodedPacket(timestamp: nil, originalLength: 70)
        packet.ipFragment = IPFragmentFacts(
            version: .v4, source: "198.51.100.53", destination: "192.0.2.10",
            identification: 8, protocolNumber: 17, offset: 8, moreFragments: true,
            payloadRange: 0 ..< 0, isPayloadComplete: true
        )
        let facts = FrameFilterFacts(packet: packet)
        var parser = FrameExpressionParser()
        #expect(try parser.parse("udp.port == 53").evaluate(facts) == .unknown)
        #expect(try parser.parse("not dns.rcode == 3").evaluate(facts) == .unknown)
    }

    @Test
    func rejectsUnsupportedAndMalformedInputAtItsPosition() {
        var parser = FrameExpressionParser()
        #expect(throws: FrameExpressionError(position: 1, reason: "Unsupported frame field: http.host")) {
            _ = try parser.parse("http.host == example.com")
        }
        #expect(throws: FrameExpressionError(position: 13, reason: "Expected a port from 0 to 65535")) {
            _ = try parser.parse("tcp.port == 70000")
        }
        #expect(throws: FrameExpressionError(position: 14, reason: "Expected a DNS response code from 0 to 15")) {
            _ = try parser.parse("dns.rcode == 16")
        }
        #expect(throws: FrameExpressionError(
            position: 14, reason: "Expected a frame length from 0 to 4294967295"
        )) { _ = try parser.parse("frame.len == 4294967296") }
        #expect(throws: FrameExpressionError(
            position: 18, reason: "Expected a frame length from 0 to 4294967295"
        )) { _ = try parser.parse("frame.cap_len == 4294967296") }
        #expect(throws: FrameExpressionError.self) {
            _ = try parser.parse("tcp.window_size_value == 65536")
        }
        #expect(throws: FrameExpressionError(
            position: 13, reason: "Expected a frame length from 0 to 4294967295"
        )) { _ = try parser.parse("frame.len > -1") }
        #expect(throws: FrameExpressionError(position: 11, reason: "Expected ==")) {
            _ = try parser.parse("frame.len = 54")
        }
        #expect(throws: FrameExpressionError.self) { _ = try parser.parse("not (tcp.rst") }
        #expect(throws: FrameExpressionError.self) {
            _ = try parser.parse(String(repeating: "not ", count: 20) + "tcp.rst")
        }
    }

    @Test @MainActor
    func invalidDraftKeepsTheAcceptedExpression() {
        let state = CaptureFrameListState()
        state.frameExpressionDraft = "tcp.rst"
        state.applyFrameExpression()
        #expect(state.acceptedFrameExpressionText == "tcp.rst")
        state.frameExpressionDraft = "http.host == example.com"
        state.applyFrameExpression()
        #expect(state.frameExpressionError?.position == 1)
        #expect(state.acceptedFrameExpressionText == "tcp.rst")
        state.clearFrameExpression()
        #expect(state.acceptedFrameExpression == nil)
    }

    @Test @MainActor
    func temporaryHighlightUsesDraftIndependentlyFromAppliedFilter() {
        let state = CaptureFrameListState()
        state.frameExpressionDraft = "tcp.rst"
        state.applyFrameExpression()
        state.frameExpressionDraft = "udp.port == 53"
        state.highlightFramesFromDraft()

        #expect(state.acceptedFrameExpressionText == "tcp.rst")
        #expect(state.highlightedFrameExpressionText == "udp.port == 53")
        #expect(state.highlightedFrameExpression != nil)

        state.frameExpressionDraft = "http.host == example.com"
        state.highlightFramesFromDraft()
        #expect(state.frameExpressionError != nil)
        #expect(state.highlightedFrameExpressionText == "udp.port == 53")
        #expect(state.acceptedFrameExpressionText == "tcp.rst")

        state.clearFrameHighlight()
        #expect(state.highlightedFrameExpression == nil)
        #expect(state.acceptedFrameExpressionText == "tcp.rst")
    }

    @Test @MainActor
    func decodedFieldHighlightPreservesAppliedFilterAndDraft() {
        let state = CaptureFrameListState()
        state.frameExpressionDraft = "tcp.rst"
        state.applyFrameExpression()
        state.frameExpressionDraft = "udp.port == 53"

        state.highlightFrames(with: "not tcp.flags.ack")

        #expect(state.acceptedFrameExpressionText == "tcp.rst")
        #expect(state.frameExpressionDraft == "udp.port == 53")
        #expect(state.highlightedFrameExpressionText == "not tcp.flags.ack")
        #expect(state.highlightedFrameExpression != nil)
    }
}
