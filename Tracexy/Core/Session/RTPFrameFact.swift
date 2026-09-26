import Foundation

// MARK: - RTPFrameFact

/// The RTP header of a UDP frame no other decoder claimed, for Statistics ▸ RTP
/// Streams. Read only when the payload has RTP's shape (version 2, not an RTCP
/// payload type, the CSRC list and padding inside the datagram); the frame and its
/// session keep their UDP labels, so a payload that merely looks like RTP never
/// changes what a session is called.
nonisolated struct RTPFrameFact: Hashable, Sendable {
    // MARK: Lifecycle

    init?(_ packet: DecodedPacket, bytes: [UInt8]) {
        guard packet.appProtocol == nil, packet.fiveTuple?.proto == .udp,
              let source = packet.sourceEndpoint, let destination = packet.destinationEndpoint,
              let range = packet.udpPayloadRange, range.upperBound <= bytes.count, range.count >= 12 else
        {
            return nil
        }
        let payload = bytes[range]
        let base = payload.startIndex
        let first = payload[base]
        let second = payload[base + 1]
        let payloadType = second & 0x7F
        let headerLength = 12 + 4 * Int(first & 0x0F)
        guard first >> 6 == 2, !(72 ... 76).contains(payloadType), headerLength <= payload.count else {
            return nil
        }
        if first & 0x20 != 0 {
            let padding = Int(payload[payload.index(before: payload.endIndex)])
            guard padding > 0, padding <= payload.count - headerLength else {
                return nil
            }
        }
        func be32(_ offset: Int) -> UInt32 {
            (0 ..< 4).reduce(0) { $0 << 8 | UInt32(payload[base + offset + $1]) }
        }
        self.payloadType = payloadType
        isMarker = second & 0x80 != 0
        sequence = UInt16(payload[base + 2]) << 8 | UInt16(payload[base + 3])
        timestamp = be32(4)
        ssrc = be32(8)
        length = range.count
        self.source = source
        self.destination = destination
    }

    // MARK: Internal

    let payloadType: UInt8
    let isMarker: Bool
    let sequence: UInt16
    let timestamp: UInt32
    let ssrc: UInt32
    /// The RTP packet's length (the UDP payload), for the analysis's bandwidth.
    let length: Int
    let source: IPEndpoint
    let destination: IPEndpoint
}

// MARK: - SIPFrameFact

/// A SIP message and the endpoints it went between, for Statistics ▸ SIP.
nonisolated struct SIPFrameFact: Hashable, Sendable {
    // MARK: Lifecycle

    init?(_ packet: DecodedPacket, bytes: [UInt8] = []) {
        guard let message = packet.sip, let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return nil
        }
        self.message = message
        self.source = source
        self.destination = destination
        let payload: [UInt8] = if let range = packet.udpPayloadRange, range.upperBound <= bytes.count {
            Array(bytes[range])
        } else {
            packet.tcpPayloadBytes
        }
        media = Self.sdpMedia(payload)
    }

    // MARK: Internal

    let message: SIPMessageFacts
    let source: IPEndpoint
    let destination: IPEndpoint
    /// Where the message's SDP body asks its media to be sent: the connection address
    /// (`c=`) and the first media line's port (`m=`), as Wireshark links RTP to a call.
    let media: IPEndpoint?

    // MARK: Private

    private static func sdpMedia(_ payload: [UInt8]) -> IPEndpoint? {
        guard let text = String(bytes: payload, encoding: .utf8), let split = text.range(of: "\r\n\r\n") else {
            return nil
        }
        var address: String?
        var port: UInt16?
        for line in text[split.upperBound...].split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ")
            if line.hasPrefix("c=IN IP"), fields.count >= 3, address == nil || port != nil {
                address = String(fields[2].split(separator: "/").first ?? fields[2])
            } else if line.hasPrefix("m="), port == nil, fields.count >= 2, let value = UInt16(fields[1]), value > 0 {
                port = value
            }
        }
        guard let address, let port, IPAddressValue(parsing: address) != nil else {
            return nil
        }
        return IPEndpoint(ip: address, port: port)
    }
}

// MARK: - MulticastFrameFact

/// A UDP datagram sent to an IPv4 224.0.0.0/4 or IPv6 ff00::/8 group, for
/// Statistics ▸ UDP Multicast Streams: its endpoints and the UDP length field.
nonisolated struct MulticastFrameFact: Hashable, Sendable {
    // MARK: Lifecycle

    init?(_ packet: DecodedPacket, bytes: [UInt8]) {
        guard packet.fiveTuple?.proto == .udp, let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint, let range = packet.udpPayloadRange,
              range.lowerBound >= 8, range.lowerBound <= bytes.count,
              let group = IPAddressValue(parsing: destination.ip), Self.isMulticast(group) else
        {
            return nil
        }
        let header = range.lowerBound - 8
        udpLength = UInt16(bytes[header + 4]) << 8 | UInt16(bytes[header + 5])
        self.source = source
        self.destination = destination
    }

    // MARK: Internal

    let source: IPEndpoint
    let destination: IPEndpoint
    let udpLength: UInt16

    static func isMulticast(_ address: IPAddressValue) -> Bool {
        switch address.family {
        case .v4: address.bytes[0] & 0xF0 == 0xE0
        case .v6: address.bytes[0] == 0xFF
        }
    }
}
