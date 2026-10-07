import Darwin
import Foundation

// MARK: - GeoIPAddressScope

/// Address ranges Tracexy never looks up: they name no place, and asking about
/// them would only describe the user's own network.
nonisolated enum GeoIPAddressScope: String, CaseIterable, Hashable, Sendable {
    /// RFC 1918.
    case privateNetwork
    /// fc00::/7, RFC 4193.
    case uniqueLocal
    /// 169.254.0.0/16 and fe80::/10.
    case linkLocal
    /// 127.0.0.0/8 and ::1.
    case loopback
    /// 100.64.0.0/10, RFC 6598 (carrier-grade NAT).
    case sharedAddressSpace
    /// 224.0.0.0/4 and ff00::/8.
    case multicast
    /// 0.0.0.0/8 and ::.
    case unspecified
    /// 255.255.255.255 and 240.0.0.0/4.
    case reserved

    // MARK: Internal

    /// The ranges of each scope, as (network bytes, prefix length).
    static let ranges: [(scope: GeoIPAddressScope, network: IPAddressValue, prefix: Int)] = {
        let table: [(GeoIPAddressScope, String, Int)] = [
            (.privateNetwork, "10.0.0.0", 8),
            (.privateNetwork, "172.16.0.0", 12),
            (.privateNetwork, "192.168.0.0", 16),
            (.loopback, "127.0.0.0", 8),
            (.linkLocal, "169.254.0.0", 16),
            (.sharedAddressSpace, "100.64.0.0", 10),
            (.multicast, "224.0.0.0", 4),
            (.unspecified, "0.0.0.0", 8),
            (.reserved, "240.0.0.0", 4),
            (.loopback, "::1", 128),
            (.unspecified, "::", 128),
            (.linkLocal, "fe80::", 10),
            (.uniqueLocal, "fc00::", 7),
            (.multicast, "ff00::", 8),
        ]
        return table.compactMap { entry in
            IPAddressValue(parsing: entry.1).map { (scope: entry.0, network: $0, prefix: entry.2) }
        }
    }()

    /// Short label for a table cell.
    var label: String {
        switch self {
        case .privateNetwork: String(localized: "Private")
        case .uniqueLocal: String(localized: "Unique local")
        case .linkLocal: String(localized: "Link-local")
        case .loopback: String(localized: "Loopback")
        case .sharedAddressSpace: String(localized: "Shared (CGNAT)")
        case .multicast: String(localized: "Multicast")
        case .unspecified: String(localized: "Unspecified")
        case .reserved: String(localized: "Reserved")
        }
    }

    /// One sentence saying why the address was not looked up.
    var explanation: String {
        switch self {
        case .privateNetwork:
            String(localized: "A private address (RFC 1918). Tracexy never looks these up.")
        case .uniqueLocal:
            String(localized: "A unique local IPv6 address. Tracexy never looks these up.")
        case .linkLocal:
            String(localized: "A link-local address. Tracexy never looks these up.")
        case .loopback:
            String(localized: "A loopback address. Tracexy never looks these up.")
        case .sharedAddressSpace:
            String(localized: "A carrier-grade NAT address (RFC 6598). Tracexy never looks these up.")
        case .multicast:
            String(
                localized: "A multicast address. It names a group, not a place, so it isn’t looked up."
            )
        case .unspecified:
            String(localized: "An unspecified address. It names no host, so it isn’t looked up.")
        case .reserved:
            String(localized: "A reserved or broadcast address. It names no host, so it isn’t looked up.")
        }
    }

    /// The scope `address` falls in, or `nil` for an address that may be looked up.
    static func classify(_ address: IPAddressValue) -> GeoIPAddressScope? {
        if let embedded = GeoIPNetwork.embeddedIPv4(address) {
            return classify(embedded)
        }
        return ranges.first { GeoIPNetwork.contains($0.network, prefix: $0.prefix, address) }?.scope
    }
}

// MARK: - GeoIPNetwork

/// CIDR arithmetic on ``IPAddressValue`` bytes.
nonisolated enum GeoIPNetwork {
    /// The IPv4 address inside an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
    static func embeddedIPv4(_ address: IPAddressValue) -> IPAddressValue? {
        guard address.family == .v6, address.bytes.prefix(10).allSatisfy({ $0 == 0 }),
              address.bytes[10] == 0xFF, address.bytes[11] == 0xFF else
        {
            return nil
        }
        let tail = address.bytes.suffix(4).map(String.init).joined(separator: ".")
        return IPAddressValue(parsing: tail)
    }

    static func contains(_ network: IPAddressValue, prefix: Int, _ address: IPAddressValue) -> Bool {
        guard network.family == address.family else {
            return false
        }
        var remaining = max(0, min(prefix, network.bytes.count * 8))
        var index = 0
        while remaining > 0 {
            let bits = min(8, remaining)
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
            if network.bytes[index] & mask != address.bytes[index] & mask {
                return false
            }
            remaining -= bits
            index += 1
        }
        return true
    }

    /// `address` with every bit after `prefix` cleared.
    static func masked(_ address: IPAddressValue, prefix: Int) -> [UInt8] {
        var bytes = address.bytes
        for bit in max(0, prefix) ..< bytes.count * 8 {
            bytes[bit / 8] &= ~UInt8(0x80 >> (bit % 8))
        }
        return bytes
    }

    /// Canonical text for `bytes` in `family`, through `inet_ntop`.
    static func text(_ bytes: [UInt8], family: IPAddressFamily) -> String? {
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes { raw in
            inet_ntop(family == .v4 ? AF_INET : AF_INET6, raw.baseAddress, &output, socklen_t(output.count))
        }
        guard result != nil else {
            return nil
        }
        return String(cString: output)
    }

    /// `network/prefix`, or `nil` when the network overlaps a range that is never
    /// looked up (so an expression built from it can't reach such an address).
    static func publicCIDR(_ address: IPAddressValue, prefix: Int) -> String? {
        let bits = address.bytes.count * 8
        guard prefix > 0, prefix <= bits else {
            return nil
        }
        let masked = masked(address, prefix: prefix)
        guard let text = text(masked, family: address.family),
              let network = IPAddressValue(parsing: text) else
        {
            return nil
        }
        for range in GeoIPAddressScope.ranges where range.network.family == network.family {
            // Two prefixes overlap when the shorter one contains the other's network.
            let shorter = min(prefix, range.prefix)
            if contains(range.network, prefix: shorter, network) {
                return nil
            }
        }
        if address.family == .v6 {
            // ::/80 holds the IPv4-mapped and IPv4-compatible forms.
            let mappedRange = IPAddressValue(parsing: "::")
            if let mappedRange, contains(mappedRange, prefix: min(prefix, 80), network) {
                return nil
            }
        }
        return prefix == bits ? text : "\(text)/\(prefix)"
    }
}

// MARK: - GeoIPLocation

/// Where the chosen databases place one public address. Each field comes from the
/// first database, in the Project's order, that has it.
nonisolated struct GeoIPLocation: Hashable, Sendable {
    // MARK: Internal

    var countryCode: String?
    var country: String?
    var city: String?
    var asNumber: UInt32?
    var asOrganization: String?
    /// The network all the databases give this answer for, as CIDR text, and its
    /// prefix length.
    var network: String?
    var networkPrefix: Int?

    var isEmpty: Bool {
        countryCode == nil && country == nil && city == nil && asNumber == nil && asOrganization == nil
    }

    /// Country name when known, else its code.
    var countryText: String? {
        country ?? countryCode
    }

    var asNumberText: String? {
        asNumber.map { "AS\($0)" }
    }

    /// Fill anything still missing from one database's record.
    mutating func merge(_ record: MaxMindValue, language: String) {
        let place = record["country"] ?? record["registered_country"]
        if countryCode == nil, let code = place?["iso_code"]?.stringValue {
            countryCode = Self.bounded(code)
        }
        if country == nil, let names = place?["names"] {
            country = Self.name(in: names, language: language)
        }
        if city == nil, let names = record.value(at: ["city", "names"]) {
            city = Self.name(in: names, language: language)
        }
        if asNumber == nil, let number = record["autonomous_system_number"]?.unsignedValue,
           number <= UInt64(UInt32.max)
        {
            asNumber = UInt32(number)
        }
        if asOrganization == nil, let organization = record["autonomous_system_organization"]?.stringValue {
            asOrganization = Self.bounded(organization)
        }
    }

    /// Record the network every database gives this address's answer for: the
    /// longest of their prefixes, which lies inside all of them.
    mutating func setNetwork(of address: IPAddressValue, prefix: Int) {
        let masked = GeoIPNetwork.masked(address, prefix: prefix)
        network = GeoIPNetwork.text(masked, family: address.family).map { "\($0)/\(prefix)" }
        networkPrefix = prefix
    }

    // MARK: Private

    private static let maximumCharacters = 120

    private static func bounded(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters))
        return trimmed.isEmpty ? nil : String(trimmed.prefix(maximumCharacters))
    }

    private static func name(in names: MaxMindValue, language: String) -> String? {
        let chosen = names[language]?.stringValue ?? names["en"]?.stringValue
            ?? names.mapValue?.min { $0.key < $1.key }?.value.stringValue
        return chosen.flatMap(bounded)
    }
}

// MARK: - GeoIPAnswer

/// What the chosen databases say about one address.
nonisolated enum GeoIPAnswer: Hashable, Sendable {
    case located(GeoIPLocation)
    /// No database has a record for it.
    case notFound
    /// Never looked up, and why.
    case notLookedUp(GeoIPAddressScope)
    /// A database entry for it couldn't be read.
    case unreadable
    /// Not an IP address (an Ethernet endpoint, for example).
    case notAnAddress
}

// MARK: - GeoIPDatabaseSet

/// The Project's loaded databases, in its order. Pure and `Sendable`, so lookups
/// can run anywhere.
nonisolated struct GeoIPDatabaseSet: Sendable {
    let databases: [MaxMindDatabase]

    /// The language used for place names: the user's first preferred language when
    /// the databases have it, else English.
    static func preferredLanguage(
        for databases: [MaxMindDatabase],
        preferred: [String] = Locale.preferredLanguages
    )
        -> String
    {
        let available = Set(databases.flatMap(\.metadata.languages))
        for identifier in preferred {
            if available.contains(identifier) {
                return identifier
            }
            let base = String(identifier.prefix { $0 != "-" })
            if available.contains(base) {
                return base
            }
        }
        return "en"
    }

    func answer(for text: String, language: String) -> GeoIPAnswer {
        guard let parsed = IPAddressValue(parsing: text) else {
            return .notAnAddress
        }
        if let scope = GeoIPAddressScope.classify(parsed) {
            return .notLookedUp(scope)
        }
        let address = GeoIPNetwork.embeddedIPv4(parsed) ?? parsed
        var location = GeoIPLocation()
        var failed = false
        var prefix = 0
        for database in databases {
            do {
                guard let found = try database.search(address) else {
                    continue
                }
                prefix = max(prefix, found.prefixLength)
                if let value = found.value {
                    location.merge(value, language: language)
                }
            } catch {
                failed = true
            }
        }
        if !location.isEmpty {
            // A database that failed gives no network; claim only the address.
            location.setNetwork(of: address, prefix: failed ? address.bytes.count * 8 : prefix)
            return .located(location)
        }
        return failed ? .unreadable : .notFound
    }
}
