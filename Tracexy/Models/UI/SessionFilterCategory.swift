import Foundation

// MARK: - SessionFilterCategory

/// A category tab in the session filter bar:
/// protocol categories form one group (a session matches if it matches *any*
/// active protocol), and investigation categories (Security / Errors) form an
/// independent group.
enum SessionFilterCategory: String, CaseIterable, Identifiable, Hashable {
    case dns
    case tcp
    case udp
    case tls
    case http
    case http2
    case quic
    case websocket
    case stun
    case security
    case errors

    // MARK: Internal

    /// Protocol categories, in display order (the "All" tab clears these).
    static let protocolFilters: [SessionFilterCategory] = [
        .dns, .tcp, .udp, .tls, .http, .http2, .quic, .websocket, .stun,
    ]

    /// Investigation categories, applied independently of the protocol group.
    static let investigationFilters: [SessionFilterCategory] = [.security, .errors]

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .dns: "DNS"
        case .tcp: "TCP"
        case .udp: "UDP"
        case .tls: "TLS"
        case .http: "HTTP"
        case .http2: "HTTP/2"
        case .quic: "QUIC"
        case .websocket: "WebSocket"
        case .stun: "STUN"
        case .security: "Security"
        case .errors: "Errors"
        }
    }

    nonisolated var isInvestigationFilter: Bool {
        self == .security || self == .errors
    }

    /// The protocol this category filters to (nil for investigation categories).
    nonisolated var protocolKind: ProtocolKind? {
        switch self {
        case .dns: .dns
        case .tcp: .tcp
        case .udp: .udp
        case .tls: .tls
        case .http: .http
        case .http2: .http2
        case .quic: .quic
        case .websocket: .websocket
        case .stun: .stun
        case .security,
             .errors: nil
        }
    }
}
