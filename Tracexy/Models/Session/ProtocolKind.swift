import Foundation

nonisolated enum ProtocolKind: String, CaseIterable, Identifiable, Hashable {
    case ethernet
    case ipv4
    case ipv6
    case arp
    case icmp
    case icmpv6
    case tcp
    case udp
    case dns
    case tls
    case http
    case http2
    case quic
    case websocket
    case stun
    case other

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    /// Short label shown in protocol-stack badges (e.g. "TLS", "HTTP/2").
    nonisolated var label: String {
        switch self {
        case .ethernet: "ETH"
        case .ipv4: "IPv4"
        case .ipv6: "IPv6"
        case .arp: "ARP"
        case .icmp: "ICMP"
        case .icmpv6: "ICMPv6"
        case .tcp: "TCP"
        case .udp: "UDP"
        case .dns: "DNS"
        case .tls: "TLS"
        case .http: "HTTP"
        case .http2: "HTTP/2"
        case .quic: "QUIC"
        case .websocket: "WS"
        case .stun: "STUN"
        case .other: "—"
        }
    }
}
