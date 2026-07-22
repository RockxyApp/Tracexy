import Foundation
import SystemConfiguration

// MARK: - InterfaceCategory

/// Groups interfaces the way macOS's own network UI does.
enum InterfaceCategory: String, CaseIterable, Identifiable {
    case wifi
    case ethernet
    case thunderbolt
    case tunnels
    case loopback
    case other

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .wifi: "Wi-Fi"
        case .ethernet: "Ethernet"
        case .thunderbolt: "Thunderbolt"
        case .tunnels: "Tunnels"
        case .loopback: "Loopback"
        case .other: "Other"
        }
    }
}

// MARK: - NetworkInterface

/// A real network interface discovered on this Mac (no mock data — see Risk R-7).
struct NetworkInterface: Identifiable, Hashable {
    let id: String
    let displayName: String
    let category: InterfaceCategory
    let ipv4: String?
    let isUp: Bool
    let isLoopback: Bool

    /// Label shown in the toolbar interface menu, e.g. "Wi-Fi (en0)".
    var menuLabel: String {
        "\(displayName) (\(id))"
    }

    /// Real SF Symbol best-effort matched to the interface family.
    var symbol: String {
        switch category {
        case .wifi: "wifi"
        case .ethernet: "cable.connector"
        case .thunderbolt: "bolt.horizontal"
        case .tunnels: "lock"
        case .loopback: "arrow.triangle.2.circlepath"
        case .other: "network"
        }
    }

    var detail: String {
        var parts: [String] = []
        if let ipv4 {
            parts.append(ipv4)
        }
        parts.append(isUp ? "active" : "not connected")
        return parts.joined(separator: " · ")
    }
}

// MARK: - InterfaceGroup

struct InterfaceGroup: Identifiable {
    let category: InterfaceCategory
    let interfaces: [NetworkInterface]

    var id: String {
        category.id
    }
}

// MARK: - NetworkInterfaces

/// Enumerates the host's interfaces via `getifaddrs`, enriched with the friendly
/// display names macOS uses (via SystemConfiguration), so the UI never shows
/// fabricated interface data.
enum NetworkInterfaces {
    // MARK: Internal

    static func available() -> [NetworkInterface] {
        let scNames = systemConfigurationNames()
        var byName: [String: (ipv4: String?, isUp: Bool, isLoopback: Bool)] = [:]
        var order: [String] = []

        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            return []
        }
        defer { freeifaddrs(head) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }

            let name = String(cString: entry.pointee.ifa_name)
            let flags = Int32(entry.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) == IFF_UP && (flags & IFF_RUNNING) == IFF_RUNNING
            let isLoopback = (flags & IFF_LOOPBACK) == IFF_LOOPBACK

            var ipv4: String?
            if let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(
                    addr, socklen_t(addr.pointee.sa_len),
                    &host, socklen_t(host.count),
                    nil, 0, NI_NUMERICHOST
                ) == 0 {
                    ipv4 = String(cString: host)
                }
            }

            if let existing = byName[name] {
                if existing.ipv4 == nil, ipv4 != nil {
                    byName[name] = (ipv4, existing.isUp || isUp, isLoopback)
                }
            } else {
                order.append(name)
                byName[name] = (ipv4, isUp, isLoopback)
            }
        }

        return order.compactMap { name in
            guard let info = byName[name] else {
                return nil
            }
            let scName = scNames[name]
            return NetworkInterface(
                id: name,
                displayName: scName ?? fallbackName(forBSD: name),
                category: category(forBSD: name, scName: scName),
                ipv4: info.ipv4,
                isUp: info.isUp,
                isLoopback: info.isLoopback
            )
        }
    }

    /// Interfaces grouped by category (Wi-Fi, Ethernet, …) in display order,
    /// matching macOS's own network menus.
    static func grouped() -> [InterfaceGroup] {
        let all = available()
        return InterfaceCategory.allCases.compactMap { category in
            let items = all.filter { $0.category == category }
            return items.isEmpty ? nil : InterfaceGroup(category: category, interfaces: items)
        }
    }

    /// The most likely primary IPv4 (first up, non-loopback interface with an address).
    static func primaryIPv4() -> String? {
        available().first { !$0.isLoopback && $0.isUp && $0.ipv4 != nil }?.ipv4
    }

    // MARK: Private

    /// BSD name → localized display name, as macOS resolves them ("Wi-Fi",
    /// "Thunderbolt 1", "Ethernet Adapter", …).
    private static func systemConfigurationNames() -> [String: String] {
        var map: [String: String] = [:]
        guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else {
            return map
        }
        for interface in interfaces {
            guard let bsd = SCNetworkInterfaceGetBSDName(interface) as String?,
                  let name = SCNetworkInterfaceGetLocalizedDisplayName(interface) as String? else
            {
                continue
            }
            map[bsd] = name
        }
        return map
    }

    private static func category(forBSD bsd: String, scName: String?) -> InterfaceCategory {
        if bsd.hasPrefix("lo") {
            return .loopback
        }
        if bsd.hasPrefix("awdl") || bsd.hasPrefix("llw") {
            return .wifi
        }
        if bsd.hasPrefix("utun") || bsd.hasPrefix("ipsec") || bsd.hasPrefix("ppp")
            || bsd.hasPrefix("gif") || bsd.hasPrefix("stf")
        {
            return .tunnels
        }
        if let scName, scName.hasPrefix("Thunderbolt") {
            return .thunderbolt
        }
        if let scName, scName.localizedCaseInsensitiveContains("Wi-Fi") {
            return .wifi
        }
        if bsd == "en0", scName == nil {
            return .wifi
        }
        if bsd.hasPrefix("bridge") {
            return .thunderbolt
        }
        if bsd.hasPrefix("en") || bsd.hasPrefix("anpi") || bsd.hasPrefix("ap") {
            return .ethernet
        }
        return .other
    }

    private static func fallbackName(forBSD bsd: String) -> String {
        if bsd.hasPrefix("lo") {
            return "Loopback"
        }
        if bsd.hasPrefix("awdl") {
            return "Apple Wireless Direct Link"
        }
        if bsd.hasPrefix("llw") {
            return "Low-Latency Wi-Fi"
        }
        if bsd.hasPrefix("utun") || bsd.hasPrefix("ipsec") || bsd.hasPrefix("ppp") {
            return "VPN Tunnel"
        }
        if bsd.hasPrefix("gif") {
            return "Generic Tunnel"
        }
        if bsd.hasPrefix("stf") {
            return "IPv6 Tunnel"
        }
        if bsd.hasPrefix("bridge") {
            return "Thunderbolt Bridge"
        }
        if bsd.hasPrefix("anpi") || bsd.hasPrefix("ap") || bsd.hasPrefix("en") {
            return "Ethernet"
        }
        return bsd.uppercased()
    }
}
