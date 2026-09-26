import Foundation

// MARK: - IPFrameFact

/// What Statistics ▸ IPv4 and IPv6 read from a frame, as Wireshark's IP stats taps
/// see it. Wireshark queues its IP tap once per IP header it dissects — each tunnel
/// level, though not the header an ICMP error quotes — and every one of those ticks
/// reads the frame's final addresses, port type and destination port, with that
/// header's own TTL or hop limit. So a GRE-tunnelled datagram counts twice under its
/// inner addresses.
nonisolated struct IPFrameFact: Hashable, Sendable {
    // MARK: Lifecycle

    init?(_ packet: DecodedPacket) {
        let layers = packet.layers.filter { $0.proto == .ipv4 || $0.proto == .ipv6 }
        guard let layer = layers.last else {
            return nil
        }
        func field(_ name: String) -> String? {
            layer.fields.first { $0.name == name }?.value
        }
        guard let source = field("Source"), let destination = field("Destination") else {
            return nil
        }
        headers = layers.map { layer in
            let isIPv6 = layer.proto == .ipv6
            let hop = layer.fields.first { $0.name == (isIPv6 ? "Hop Limit" : "TTL") }?.value
            return Header(isIPv6: isIPv6, hopLimit: hop.flatMap { UInt8($0) } ?? 0)
        }
        self.source = IPAddressValue(parsing: source)?.compressedText ?? source
        self.destination = IPAddressValue(parsing: destination)?.compressedText ?? destination
        switch packet.fiveTuple?.proto {
        case .tcp:
            portType = "TCP"
            destinationPort = packet.destinationEndpoint?.port ?? 0
        case .udp:
            portType = "UDP"
            destinationPort = packet.destinationEndpoint?.port ?? 0
        default:
            portType = "NONE"
            destinationPort = 0
        }
    }

    // MARK: Internal

    /// One IP header of the frame: which tree it ticks, and its TTL or hop limit.
    struct Header: Hashable, Sendable {
        let isIPv6: Bool
        let hopLimit: UInt8
    }

    /// Every IP header, outermost first.
    let headers: [Header]
    let source: String
    let destination: String
    /// Wireshark's `port_type_to_str`: TCP, UDP, or NONE for everything else.
    let portType: String
    let destinationPort: UInt16
}
