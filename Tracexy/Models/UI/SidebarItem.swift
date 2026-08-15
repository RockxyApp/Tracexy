import Foundation

// MARK: - SidebarItem

enum SidebarItem: String, CaseIterable, Identifiable, Hashable {
    case overview
    case sessions
    case flow
    case dns
    case tcp
    case tls
    case http
    case quic
    case saved

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .overview: "Overview"
        case .sessions: "Sessions"
        case .flow: "Flow Map"
        case .dns: "DNS"
        case .tcp: "TCP"
        case .tls: "TLS"
        case .http: "HTTP"
        case .quic: "QUIC"
        case .saved: "Saved"
        }
    }

    /// Real SF Symbol (never a colored dot — see design system).
    nonisolated var systemImage: String {
        switch self {
        case .overview: "gauge.with.dots.needle.67percent"
        case .sessions: "rectangle.stack"
        case .flow: "globe.americas"
        case .dns: "text.magnifyingglass"
        case .tcp: "arrow.left.arrow.right"
        case .tls: "lock.shield"
        case .http: "globe"
        case .quic: "bolt.horizontal"
        case .saved: "folder"
        }
    }

    /// When this item is a single-protocol lens, the protocol it filters to.
    nonisolated var protocolFilter: ProtocolKind? {
        switch self {
        case .dns: .dns
        case .tcp: .tcp
        case .tls: .tls
        case .http: .http
        case .quic: .quic
        default: nil
        }
    }
}

// MARK: - SidebarSection

/// The leaf-nav sections (selectable rows). Favorites/Sources are rendered
/// separately because their rows are dynamic disclosure groups; Protocols is a
/// single collapsed-by-default disclosure group of protocol lenses.
enum SidebarSection: String, CaseIterable, Identifiable, Hashable {
    case monitor
    case protocols

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .monitor: "Monitor"
        case .protocols: "Protocols"
        }
    }

    /// Real SF Symbol (never a colored dot — see design system).
    nonisolated var systemImage: String {
        switch self {
        case .monitor: "gauge.with.dots.needle.67percent"
        case .protocols: "square.stack.3d.down.right"
        }
    }

    nonisolated var items: [SidebarItem] {
        switch self {
        case .monitor: [.overview, .sessions, .flow]
        case .protocols: [.dns, .tcp, .tls, .http, .quic]
        }
    }
}
