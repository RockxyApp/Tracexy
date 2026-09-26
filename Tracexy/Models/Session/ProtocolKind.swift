import Foundation

nonisolated enum ProtocolKind: String, CaseIterable, Identifiable, Hashable {
    case ethernet
    /// Linux cooked capture (SLL / SLL2) framing. Like Ethernet this is outer
    /// framing, not a session protocol.
    case linuxCooked
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
    /// Multicast DNS (Bonjour) on UDP 5353.
    case mdns
    case dhcp
    case ntp
    /// Trivial File Transfer Protocol on UDP 69.
    case tftp
    case ssh
    case ftp
    case smtp
    case pop3
    case imap
    /// Simple Service Discovery (UPnP) on UDP 1900.
    case ssdp
    /// Session Initiation Protocol (VoIP signalling) on UDP or TCP 5060.
    case sip
    /// SMB 1/2/3 file sharing on TCP 445 or 139.
    case smb
    /// Link-local Multicast Name Resolution on UDP 5355.
    case llmnr
    /// NetBIOS Name Service on UDP 137.
    case nbns
    /// Kerberos on UDP or TCP 88.
    case kerberos
    /// LDAP on TCP 389 (and the global catalog on 3268).
    case ldap
    /// Generic Routing Encapsulation (IP protocol 47).
    case gre
    /// Virtual eXtensible LAN (UDP 4789).
    case vxlan
    case other

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    /// Short label shown in protocol-stack badges (e.g. "TLS", "HTTP/2").
    nonisolated var label: String {
        switch self {
        case .ethernet: "ETH"
        case .linuxCooked: "SLL"
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
        case .mdns: "mDNS"
        case .dhcp: "DHCP"
        case .ntp: "NTP"
        case .tftp: "TFTP"
        case .ssh: "SSH"
        case .ftp: "FTP"
        case .smtp: "SMTP"
        case .pop3: "POP3"
        case .imap: "IMAP"
        case .ssdp: "SSDP"
        case .sip: "SIP"
        case .smb: "SMB"
        case .llmnr: "LLMNR"
        case .nbns: "NBNS"
        case .kerberos: "KRB5"
        case .ldap: "LDAP"
        case .gre: "GRE"
        case .vxlan: "VXLAN"
        case .other: "—"
        }
    }
}
