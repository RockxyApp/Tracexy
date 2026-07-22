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
