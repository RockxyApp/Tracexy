import Foundation
import os

// MARK: - DecodeAsProtocol

/// What Decode As can make a port's payload decode as — the protocols Tracexy's
/// decoder reads. Content-detected protocols (TLS, HTTP, STUN) are recognized on any
/// port already; forcing them only matters when detection would not fire.
nonisolated enum DecodeAsProtocol: String, CaseIterable, Codable, Identifiable, Sendable {
    case dns
    case mdns
    case ntp
    case dhcp
    case tftp
    case quic
    case stun
    case tls
    case http
    case ssh
    case ftp
    case smtp
    case pop3
    case imap
    case ssdp
    case sip
    case smb
    case llmnr
    case nbns
    case kerberos
    case ldap

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .dns: "DNS"
        case .mdns: "mDNS"
        case .ntp: "NTP"
        case .dhcp: "DHCP"
        case .tftp: "TFTP"
        case .quic: "QUIC"
        case .stun: "STUN"
        case .tls: "TLS"
        case .http: "HTTP/1"
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
        case .kerberos: "Kerberos"
        case .ldap: "LDAP"
        }
    }

    /// The protocol the decoder labels this one's layers with.
    var kind: ProtocolKind {
        ProtocolKind(rawValue: rawValue) ?? .other
    }

    /// Which transports the protocol can ride on.
    var transports: [DecodeAsRule.Transport] {
        switch self {
        case .dns,
             .sip,
             .kerberos: [.udp, .tcp]
        case .mdns,
             .ntp,
             .dhcp,
             .tftp,
             .quic,
             .stun,
             .ssdp,
             .llmnr,
             .nbns: [.udp]
        case .tls,
             .http,
             .ssh,
             .ftp,
             .smtp,
             .pop3,
             .imap,
             .smb,
             .ldap: [.tcp]
        }
    }
}

// MARK: - DecodeAsRule

/// One Decode As row: frames to or from `port` on `transport` decode as `decode`.
nonisolated struct DecodeAsRule: Codable, Hashable, Identifiable, Sendable {
    enum Transport: String, Codable, CaseIterable, Sendable {
        case tcp
        case udp

        // MARK: Internal

        var title: String {
            rawValue.uppercased()
        }
    }

    var id = UUID()
    var transport: Transport
    var port: UInt16
    var decode: DecodeAsProtocol

    var isValid: Bool {
        port > 0 && decode.transports.contains(transport)
    }
}

// MARK: - DecodeAs

/// Wireshark's Analyze ▸ Decode As: the active Project's port → protocol rules, read by
/// the decoder at every frame. A process-wide table (behind a lock) because every
/// decode path — the fold, rescans, Follow, the command line — shares the decoder,
/// just as Wireshark's dissector tables are global. Changing it affects the next
/// decode; a capture already folded is re-read with Reload (Wireshark's Redissect).
nonisolated enum DecodeAs {
    // MARK: Internal

    /// Rules for one synchronous decode, ahead of the process-wide table — for tests,
    /// which run in parallel with coordinators that rebind the table.
    @TaskLocal static var scopedRules: [DecodeAsRule]?

    /// Protocols switched off for one synchronous decode, ahead of the process-wide
    /// set — for tests, as ``scopedRules``.
    @TaskLocal static var scopedDisabled: Set<ProtocolKind>?

    static var rules: [DecodeAsRule] {
        table.withLock { $0 }
    }

    /// Analyze ▸ Enabled Protocols: the protocols the decoder must not recognize.
    static var disabled: Set<ProtocolKind> {
        disabledTable.withLock { $0 }
    }

    static func setRules(_ rules: [DecodeAsRule]) {
        table.withLock { $0 = rules.filter(\.isValid) }
    }

    static func setDisabled(_ kinds: Set<ProtocolKind>) {
        disabledTable.withLock { $0 = kinds }
    }

    /// `candidates` with a switched-off protocol's decode undone: a candidate whose
    /// decode adds a disabled protocol's layer leaves the packet as it found it, so
    /// the payload stays undecoded data, as Wireshark leaves a disabled dissector's.
    static func enabled(_ candidates: [PacketDecoder.ApplicationCandidate]) -> [PacketDecoder.ApplicationCandidate] {
        let disabled = scopedDisabled ?? disabledTable.withLock { $0 }
        guard !disabled.isEmpty else {
            return candidates
        }
        return candidates.map { candidate in
            PacketDecoder.ApplicationCandidate(matches: candidate.matches) { context, packet in
                let before = packet
                let result = try candidate.decode(context, &packet)
                guard packet.layers.dropFirst(before.layers.count).contains(where: { disabled.contains($0.proto) }) else {
                    return result
                }
                packet = before
                return nil
            }
        }
    }

    /// The candidate chain for one frame: a forced candidate for a matching rule (first
    /// matching rule wins, destination port before source port), then the default chain.
    static func candidates(
        _ defaults: [PacketDecoder.ApplicationCandidate],
        transport: DecodeAsRule.Transport,
        ports: (source: UInt16, destination: UInt16)
    )
        -> [PacketDecoder.ApplicationCandidate]
    {
        let rules = scopedRules ?? table.withLock { $0 }
        let rule = rules.first { $0.transport == transport && $0.port == ports.destination }
            ?? rules.first { $0.transport == transport && $0.port == ports.source }
        guard let rule else {
            return enabled(defaults)
        }
        return enabled([forced(rule.decode, transport: transport)] + defaults)
    }

    // MARK: Private

    private static let table = OSAllocatedUnfairLock<[DecodeAsRule]>(initialState: [])
    private static let disabledTable = OSAllocatedUnfairLock<Set<ProtocolKind>>(initialState: [])

    private static func forced(
        _ proto: DecodeAsProtocol,
        transport: DecodeAsRule.Transport
    )
        -> PacketDecoder.ApplicationCandidate
    {
        PacketDecoder.ApplicationCandidate(
            matches: { _ in true },
            decode: { context, packet in
                switch proto {
                case .dns: try PacketDecoder.dns(context.payload, into: &packet, tcp: transport == .tcp)
                case .mdns: try PacketDecoder.dns(context.payload, into: &packet, tcp: false, kind: .mdns)
                case .ntp: try PacketDecoder.ntp(context.payload, into: &packet)
                case .dhcp: try PacketDecoder.dhcp(context.payload, into: &packet)
                case .tftp: try PacketDecoder.tftp(context.payload, into: &packet)
                case .quic: PacketDecoder.quic(context.payload, into: &packet)
                case .stun: try PacketDecoder.stun(context.payload, into: &packet)
                case .tls: try PacketDecoder.tlsRecords(context.payload, into: &packet)
                case .http: try PacketDecoder.http(context.payload, into: &packet)
                case .ssh: try PacketDecoder.ssh(context.payload, into: &packet)
                case .ftp: try PacketDecoder.textService(.ftp, context.payload, into: &packet)
                case .smtp: try PacketDecoder.textService(.smtp, context.payload, into: &packet)
                case .pop3: try PacketDecoder.textService(.pop3, context.payload, into: &packet)
                case .imap: try PacketDecoder.textService(.imap, context.payload, into: &packet)
                case .ssdp: try PacketDecoder.ssdp(context.payload, into: &packet)
                case .sip: try PacketDecoder.sip(context.payload, into: &packet)
                case .smb: try PacketDecoder.smb(context.payload, into: &packet)
                case .llmnr: try PacketDecoder.dns(context.payload, into: &packet, tcp: false, kind: .llmnr)
                case .nbns: try PacketDecoder.nbns(context.payload, into: &packet)
                case .kerberos: try PacketDecoder.kerberos(context.payload, into: &packet)
                case .ldap: try PacketDecoder.ldap(context.payload, into: &packet)
                }
                return nil
            }
        )
    }
}
