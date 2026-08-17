import Foundation

nonisolated enum PacketBuilder {
    // MARK: Internal

    // MARK: Composite frames (Ethernet II + IPv4 + transport + app)

    static func dnsQueryFrame(name: String, src: String, dst: String, srcPort: UInt16 = 54_000) -> [UInt8] {
        ethernetIPv4(
            proto: 17,
            src: src,
            dst: dst,
            payload: udp(srcPort: srcPort, dstPort: 53, payload: dnsQuery(name: name))
        )
    }

    static func dnsResponseFrame(
        name: String,
        answers: [String],
        src: String,
        dst: String,
        dstPort: UInt16 = 54_000
    )
        -> [UInt8]
    {
        ethernetIPv4(
            proto: 17,
            src: src,
            dst: dst,
            payload: udp(srcPort: 53, dstPort: dstPort, payload: dnsResponse(name: name, answers: answers))
        )
    }

    static func tlsClientHelloFrame(sni: String, src: String, dst: String, srcPort: UInt16 = 52_344) -> [UInt8] {
        ethernetIPv4(
            proto: 6,
            src: src,
            dst: dst,
            payload: tcp(srcPort: srcPort, dstPort: 443, flags: 0x18, payload: tlsClientHello(sni: sni))
        )
    }

    /// Ethernet+IPv4+TCP frame carrying a single raw TLS record. `declaredLength`
    /// overrides the record's length field (defaulting to the actual body length),
    /// so a test can model a fragment whose declared body exceeds the captured
    /// bytes — TCP reassembly does not exist, so records legitimately arrive split.
    static func tlsRecordFrame(
        contentType: UInt8,
        version: UInt16 = 0x0303,
        body: [UInt8],
        declaredLength: UInt16? = nil,
        src: String,
        dst: String,
        srcPort: UInt16 = 50_000,
        dstPort: UInt16 = 443
    )
        -> [UInt8]
    {
        let length = declaredLength ?? UInt16(body.count)
        let record = [contentType] + be16(version) + be16(length) + body
        return ethernetIPv4(
            proto: 6,
            src: src,
            dst: dst,
            payload: tcp(srcPort: srcPort, dstPort: dstPort, flags: 0x18, payload: record)
        )
    }

    static func httpRequestFrame(
        host: String,
        path: String,
        src: String,
        dst: String,
        srcPort: UInt16 = 52_100
    )
        -> [UInt8]
    {
        let request = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Tracexy\r\n\r\n"
        return ethernetIPv4(
            proto: 6,
            src: src,
            dst: dst,
            payload: tcp(srcPort: srcPort, dstPort: 80, flags: 0x18, payload: Array(request.utf8))
        )
    }

    static func tcpSynFrame(src: String, dst: String, srcPort: UInt16, dstPort: UInt16) -> [UInt8] {
        ethernetIPv4(
            proto: 6,
            src: src,
            dst: dst,
            payload: tcp(srcPort: srcPort, dstPort: dstPort, flags: 0x02, payload: [])
        )
    }

    // MARK: Layers

    static func ethernetIPv4(proto: UInt8, src: String, dst: String, payload: [UInt8]) -> [UInt8] {
        var frame = mac(6, 6, 6, 6, 6, 6) + mac(1, 2, 3, 4, 5, 6) + [0x08, 0x00]
        frame += ipv4Header(proto: proto, src: src, dst: dst, payloadCount: payload.count) + payload
        return frame
    }

    /// Ethernet + IPv4 frame carrying a Router Alert option (IHL = 6).
    static func ethernetIPv4RouterAlert(proto: UInt8, src: String, dst: String, payload: [UInt8]) -> [UInt8] {
        let options: [UInt8] = [0x94, 0x04, 0x00, 0x00] // Router Alert: type 148, length 4
        var header: [UInt8] = [0x46, 0x00] // version 4, IHL 6 (24-byte header)
        header += be16(UInt16(24 + payload.count)) // total length
        header += [0x00, 0x00, 0x40, 0x00] // id, flags/frag
        header += [64, proto] // TTL, protocol
        header += [0x00, 0x00] // checksum
        header += ipv4Bytes(src) + ipv4Bytes(dst)
        header += options
        var frame = mac(6, 6, 6, 6, 6, 6) + mac(1, 2, 3, 4, 5, 6) + [0x08, 0x00]
        frame += header + payload
        return frame
    }

    static func ipv4Header(proto: UInt8, src: String, dst: String, payloadCount: Int) -> [UInt8] {
        var header: [UInt8] = [0x45, 0x00] // version/IHL, DSCP
        header += be16(UInt16(20 + payloadCount)) // total length
        header += [0x00, 0x00, 0x40, 0x00] // id, flags/frag
        header += [64, proto] // TTL, protocol
        header += [0x00, 0x00] // checksum (0 = unchecked; decoder ignores)
        header += ipv4Bytes(src) + ipv4Bytes(dst)
        return header
    }

    static func udp(srcPort: UInt16, dstPort: UInt16, payload: [UInt8]) -> [UInt8] {
        be16(srcPort) + be16(dstPort) + be16(UInt16(8 + payload.count)) + [0x00, 0x00] + payload
    }

    // MARK: IPv6

    /// Ethernet II frame carrying an IPv6 packet (ethertype 0x86DD).
    static func ethernetIPv6(
        nextHeader: UInt8,
        src: [UInt16],
        dst: [UInt16],
        payload: [UInt8]
    )
        -> [UInt8]
    {
        var frame = mac(6, 6, 6, 6, 6, 6) + mac(1, 2, 3, 4, 5, 6) + [0x86, 0xDD]
        frame += ipv6Header(nextHeader: nextHeader, payloadCount: payload.count, src: src, dst: dst) + payload
        return frame
    }

    static func ipv6Header(nextHeader: UInt8, payloadCount: Int, src: [UInt16], dst: [UInt16]) -> [UInt8] {
        var header: [UInt8] = [0x60, 0x00, 0x00, 0x00] // version 6, traffic class 0, flow label 0
        header += be16(UInt16(payloadCount)) // payload length
        header += [nextHeader, 64] // next header, hop limit
        header += ipv6Bytes(src) + ipv6Bytes(dst)
        return header
    }

    /// An 8-byte Hop-by-Hop extension header with a PadN option.
    static func ipv6HopByHop(nextHeader: UInt8) -> [UInt8] {
        [nextHeader, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]
    }

    static func tcp(
        srcPort: UInt16,
        dstPort: UInt16,
        flags: UInt8,
        payload: [UInt8],
        sequence: UInt32 = 1
    )
        -> [UInt8]
    {
        var header = be16(srcPort) + be16(dstPort)
        header += be32(sequence) + be32(0) // seq, ack
        header += [0x50, flags] // data offset (5 words), flags
        header += [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00] // window, checksum, urgent
        return header + payload
    }

    /// A TCP SYN segment carrying a realistic option set (MSS, Window Scale,
    /// SACK Permitted, Timestamps) for exercising option parsing.
    static func tcpSynWithOptions(srcPort: UInt16, dstPort: UInt16) -> [UInt8] {
        var options: [UInt8] = []
        options += [2, 4] + be16(1_460) // MSS = 1460
        options += [1] // NOP
        options += [3, 3, 7] // Window Scale, shift 7
        options += [4, 2] // SACK Permitted
        options += [1, 1] // NOP, NOP
        options += [8, 10] + be32(123_456) + be32(0) // Timestamps
        while options.count % 4 != 0 {
            options.append(0) // pad to a 32-bit boundary
        }
        let dataOffsetWords = (20 + options.count) / 4
        var header = be16(srcPort) + be16(dstPort)
        header += be32(1) + be32(0)
        header += [UInt8(dataOffsetWords << 4), 0x02] // data offset, SYN flag
        header += [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]
        return header + options
    }

    // MARK: ARP / ICMP

    /// Ethernet frame carrying an ARP request (ethertype 0x0806).
    static func arpRequestFrame(senderIP: String, targetIP: String) -> [UInt8] {
        var arp = be16(1) + be16(0x0800) // hardware = Ethernet, protocol = IPv4
        arp += [6, 4] // hlen, plen
        arp += be16(1) // operation = request
        arp += mac(1, 2, 3, 4, 5, 6) + ipv4Bytes(senderIP)
        arp += mac(0, 0, 0, 0, 0, 0) + ipv4Bytes(targetIP)
        return mac(6, 6, 6, 6, 6, 6) + mac(1, 2, 3, 4, 5, 6) + [0x08, 0x06] + arp
    }

    /// Ethernet + IPv4 frame carrying an ICMP Echo Request (type 8).
    static func icmpEchoRequestFrame(src: String, dst: String) -> [UInt8] {
        let icmp: [UInt8] = [8, 0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01] // type, code, checksum, id, seq
        return ethernetIPv4(proto: 1, src: src, dst: dst, payload: icmp)
    }

    /// A DNS response carrying a single MX record, for RR-type parsing tests.
    static func dnsResponseMXFrame(name: String, src: String, dst: String) -> [UInt8] {
        ethernetIPv4(
            proto: 17, src: src, dst: dst,
            payload: udp(srcPort: 53, dstPort: 54_000, payload: dnsResponseMX(name: name))
        )
    }

    static func dnsResponseMX(name: String, preference: UInt16 = 10) -> [UInt8] {
        var dns: [UInt8] = be16(0x1234) + be16(0x8180) // id, flags (response, RD, RA)
        dns += be16(1) + be16(1) + be16(0) + be16(0) // qd=1, an=1
        dns += qname(name) + be16(15) + be16(1) // qtype MX, qclass IN
        dns += [0xC0, 0x0C] // name pointer → question qname
        dns += be16(15) + be16(1) // type MX, class IN
        dns += be32(300) // TTL
        let rdata = be16(preference) + qname("mail.\(name)")
        dns += be16(UInt16(rdata.count)) + rdata
        return dns
    }

    // MARK: Application payloads

    static func dnsQuery(name: String) -> [UInt8] {
        var dns: [UInt8] = be16(0x1234) + be16(0x0100) // id, flags (RD)
        dns += be16(1) + be16(0) + be16(0) + be16(0) // qd/an/ns/ar
        dns += qname(name) + be16(1) + be16(1) // qtype A, qclass IN
        return dns
    }

    static func dnsResponse(name: String, answers: [String]) -> [UInt8] {
        var dns: [UInt8] = be16(0x1234) + be16(0x8180) // id, flags (response, RD, RA)
        dns += be16(1) + be16(UInt16(answers.count)) + be16(0) + be16(0)
        dns += qname(name) + be16(1) + be16(1)
        for answer in answers {
            dns += [0xC0, 0x0C] // name pointer → question qname at offset 12
            dns += be16(1) + be16(1) // type A, class IN
            dns += be32(300) // TTL
            dns += be16(4) + ipv4Bytes(answer) // rdlength + IPv4
        }
        return dns
    }

    static func tlsClientHello(sni: String) -> [UInt8] {
        let server = Array(sni.utf8)
        // server_name extension: list(len) + nameType(0) + nameLen + name
        let serverNameList = be16(UInt16(3 + server.count)) + [0x00] + be16(UInt16(server.count)) + server
        let sniExtension = be16(0x0000) + be16(UInt16(serverNameList.count)) + serverNameList
        let extensions = sniExtension
        var handshakeBody: [UInt8] = be16(0x0303) // client version TLS 1.2
        handshakeBody += [UInt8](repeating: 0, count: 32) // random
        handshakeBody += [0x00] // session id length
        handshakeBody += be16(2) + be16(0x1301) // cipher suites (TLS_AES_128_GCM_SHA256)
        handshakeBody += [0x01, 0x00] // compression methods
        handshakeBody += be16(UInt16(extensions.count)) + extensions
        let handshake = [0x01] + be24(UInt32(handshakeBody.count)) + handshakeBody // ClientHello
        return [0x16, 0x03, 0x01] + be16(UInt16(handshake.count)) + handshake // TLS record (handshake)
    }

    // MARK: Private

    // MARK: Primitives

    private static func be16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    private static func be24(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ]
    }

    private static func be32(_ value: UInt32) -> [UInt8] {
        [UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
    }

    private static func mac(_ bytes: UInt8...) -> [UInt8] {
        bytes
    }

    private static func ipv4Bytes(_ address: String) -> [UInt8] {
        let parts = address.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : [0, 0, 0, 0]
    }

    /// Expands up to 8 leading hextets into a full 16-byte IPv6 address.
    private static func ipv6Bytes(_ hextets: [UInt16]) -> [UInt8] {
        let padded = (hextets + Array(repeating: UInt16(0), count: 8)).prefix(8)
        return padded.flatMap { be16($0) }
    }

    private static func qname(_ name: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in name.split(separator: ".") {
            let labelBytes = Array(label.utf8)
            bytes.append(UInt8(labelBytes.count))
            bytes += labelBytes
        }
        bytes.append(0)
        return bytes
    }
}
