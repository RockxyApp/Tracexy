import Foundation

// MARK: - SupportedProtocolRow

/// One protocol Tracexy recognizes, for Help ▸ Supported Protocols (Wireshark's
/// View ▸ Internals ▸ Supported Protocols): its name, what is read from it, and the
/// Session Expression keywords that find its sessions.
nonisolated struct SupportedProtocolRow: Identifiable, Hashable, Sendable {
    let kind: ProtocolKind
    let name: String
    let reads: String
    let keywords: [String]

    var id: String {
        kind.rawValue
    }
}

// MARK: - SupportedProtocols

nonisolated enum SupportedProtocols {
    // MARK: Internal

    /// Every recognized protocol, outer framing first, in decode order.
    static var rows: [SupportedProtocolRow] {
        let keywords = Dictionary(grouping: SessionQueryParser.protocolKeywords.keys) {
            SessionQueryParser.protocolKeywords[$0]
        }
        return details.map { kind, name, reads in
            SupportedProtocolRow(
                kind: kind, name: name, reads: reads, keywords: (keywords[kind] ?? []).sorted()
            )
        }
    }

    // MARK: Private

    private static var details: [(ProtocolKind, String, String)] {
        [
            (.ethernet, "Ethernet II", String(localized: "Addresses, EtherType and VLAN tags")),
            (
                .linuxCooked,
                "Linux cooked capture (SLL, SLL2)",
                String(localized: "Packet type, hardware address and protocol")
            ),
            (
                .ipv4,
                "Internet Protocol version 4",
                String(
                    localized: "Header fields, fragments and options; checksum when validated; IP in IP and 6in4 unwrapped"
                )
            ),
            (
                .ipv6,
                "Internet Protocol version 6",
                String(localized: "Header, extension headers and fragments; IP in IPv6 unwrapped")
            ),
            (.arp, "Address Resolution Protocol", String(localized: "Operation and sender and target addresses")),
            (
                .icmp,
                "Internet Control Message Protocol",
                String(localized: "Type and code, echo, and errors with the packet they quote")
            ),
            (.icmpv6, "ICMP for IPv6", String(localized: "Type and code, neighbor discovery, and errors")),
            (
                .tcp,
                "Transmission Control Protocol",
                String(localized: "Flags, sequence, window and options; connection analysis")
            ),
            (.udp, "User Datagram Protocol", String(localized: "Ports, length and checksum")),
            (.gre, "Generic Routing Encapsulation", String(localized: "The tunnel and the packet inside it")),
            (.vxlan, "Virtual Extensible LAN", String(localized: "The network identifier and the frame inside it")),
            (.dns, "Domain Name System", String(localized: "Questions, answers and response codes")),
            (.mdns, "Multicast DNS (Bonjour)", String(localized: "Names devices announce and ask for")),
            (.llmnr, "Link-Local Multicast Name Resolution", String(localized: "Name queries and answers")),
            (.nbns, "NetBIOS Name Service", String(localized: "Name queries and answers")),
            (
                .dhcp,
                "Dynamic Host Configuration Protocol",
                String(localized: "Message type, offered address, lease, router and DNS")
            ),
            (.ntp, "Network Time Protocol", String(localized: "Mode, stratum and reference")),
            (
                .tftp,
                "Trivial File Transfer Protocol",
                String(localized: "Requests, blocks, errors and options on port 69; Export Objects rebuilds files")
            ),
            (
                .tls,
                "Transport Layer Security",
                String(localized: "Records, hellos, versions, ciphers, ALPN, certificates and alerts")
            ),
            (.quic, "QUIC", String(localized: "Long-header packet type, version and connection IDs")),
            (
                .http,
                "Hypertext Transfer Protocol",
                String(localized: "HTTP/1 request and status lines, key headers and bodies")
            ),
            (
                .http2,
                "HTTP/2",
                String(
                    localized: "Frames, streams and HPACK headers of a followed cleartext connection; the preface or ALPN h2 marks a session"
                )
            ),
            (
                .websocket,
                "WebSocket",
                String(
                    localized: "Messages and frames after the HTTP/1 Upgrade, unmasked and decompressed, in a followed stream"
                )
            ),
            (.stun, "Session Traversal Utilities for NAT", String(localized: "Message type and attributes")),
            (
                .sip,
                "Session Initiation Protocol",
                String(localized: "Requests, responses and call IDs; VoIP calls and statistics")
            ),
            (.ssh, "Secure Shell", String(localized: "The protocol banner")),
            (
                .ftp,
                "File Transfer Protocol",
                String(localized: "Commands and replies; user names and passwords are never shown")
            ),
            (
                .smtp,
                "Simple Mail Transfer Protocol",
                String(localized: "Commands and replies; credentials are never shown")
            ),
            (.pop3, "Post Office Protocol 3", String(localized: "Commands and replies; credentials are never shown")),
            (
                .imap,
                "Internet Message Access Protocol",
                String(localized: "Tagged commands and replies; credentials are never shown")
            ),
            (.ssdp, "Simple Service Discovery Protocol", String(localized: "Discovery method and search target")),
            (.smb, "Server Message Block 2 and 3", String(localized: "Command, status and IDs")),
            (
                .kerberos,
                "Kerberos",
                String(localized: "Message type, error code and realm; principal names are never read")
            ),
            (
                .ldap,
                "Lightweight Directory Access Protocol",
                String(localized: "Operation, message ID and result code")
            ),
        ]
    }
}
