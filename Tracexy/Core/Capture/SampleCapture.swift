import Foundation

nonisolated enum SampleCapture {
    static func frames(now: Date = Date()) -> [CapturedFrame] {
        var frames: [CapturedFrame] = []
        var clock = now.addingTimeInterval(-92)

        func push(_ bytes: [UInt8], gap: Double = 0.4) {
            frames.append(CapturedFrame(bytes: bytes, timestamp: clock, originalLength: bytes.count))
            clock = clock.addingTimeInterval(gap)
        }

        let client = "192.168.1.42"
        let resolver = "1.1.1.1"

        // api.example.com — DNS lookup, then TLS handshake to the resolved IP.
        push(PacketBuilder.dnsQueryFrame(name: "api.example.com", src: client, dst: resolver, srcPort: 54_001))
        push(
            PacketBuilder
                .dnsResponseFrame(
                    name: "api.example.com",
                    answers: ["93.184.16.34"],
                    src: resolver,
                    dst: client,
                    dstPort: 54_001
                ),
            gap: 0.018
        )
        push(PacketBuilder.tlsClientHelloFrame(
            sni: "api.example.com",
            src: client,
            dst: "93.184.16.34",
            srcPort: 52_344
        ))

        // cdn.fastly.net — DNS + TLS.
        push(PacketBuilder.dnsQueryFrame(name: "cdn.fastly.net", src: client, dst: resolver, srcPort: 54_002))
        push(
            PacketBuilder
                .dnsResponseFrame(
                    name: "cdn.fastly.net",
                    answers: ["151.101.1.10"],
                    src: resolver,
                    dst: client,
                    dstPort: 54_002
                ),
            gap: 0.024
        )
        push(PacketBuilder.tlsClientHelloFrame(
            sni: "cdn.fastly.net",
            src: client,
            dst: "151.101.1.10",
            srcPort: 52_345
        ))

        // registry.npmjs.org — plaintext HTTP request.
        push(PacketBuilder.httpRequestFrame(
            host: "registry.npmjs.org",
            path: "/tracexy/-/tracexy-1.0.0.tgz",
            src: client,
            dst: "104.16.20.35",
            srcPort: 52_400
        ))

        // auth.example.com — TLS, then the server resets the connection (error).
        push(PacketBuilder.tlsClientHelloFrame(sni: "auth.example.com", src: client, dst: "20.50.1.2", srcPort: 52_346))
        push(PacketBuilder.ethernetIPv4(
            proto: 6,
            src: "20.50.1.2",
            dst: client,
            payload: PacketBuilder.tcp(srcPort: 443, dstPort: 52_346, flags: 0x04, payload: [])
        ), gap: 0.42)

        // edge.quic.cloud — DNS + a QUIC long-header packet.
        push(PacketBuilder.dnsQueryFrame(name: "edge.quic.cloud", src: client, dst: resolver, srcPort: 54_003))
        push(
            PacketBuilder
                .dnsResponseFrame(
                    name: "edge.quic.cloud",
                    answers: ["172.64.1.1"],
                    src: resolver,
                    dst: client,
                    dstPort: 54_003
                ),
            gap: 0.02
        )
        push(PacketBuilder.ethernetIPv4(
            proto: 17,
            src: client,
            dst: "172.64.1.1",
            payload: PacketBuilder.udp(
                srcPort: 54_321,
                dstPort: 443,
                payload: [0xC3, 0x00, 0x00, 0x00, 0x01, 0x08]
            )
        ))

        // Incomplete handshake — SYN with no response (warning).
        push(PacketBuilder.tcpSynFrame(src: client, dst: "203.0.113.9", srcPort: 51_000, dstPort: 443))

        return frames
    }
}
