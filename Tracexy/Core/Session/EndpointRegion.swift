import Foundation

// MARK: - EndpointRegion

/// Where an address is administered, resolved offline from IANA's allocation of
/// IPv4 space to the five Regional Internet Registries.
///
/// This is deliberately **regional, not geographic**. Tracexy ships no
/// geolocation database, and inventing city-level coordinates for an address we
/// have not located would be the same fabrication the rest of this codebase
/// refuses. What IANA's allocation genuinely tells us is which registry
/// administers a block, which is a real, checkable fact — coarse, but true.
///
/// A registry is not a location: an ARIN-allocated block can be announced from
/// anywhere. The UI must therefore label these as *registry regions* and never
/// as "where the server is".
enum EndpointRegion: String, CaseIterable, Identifiable, Hashable, Sendable {
    case northAmerica
    case europe
    case asiaPacific
    case latinAmerica
    case africa
    /// Private, loopback, link-local, multicast — traffic that never left, or
    /// never could leave, this network.
    case local
    /// Allocated to no registry we can resolve, or not IPv4.
    case unknown

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .northAmerica: "North America"
        case .europe: "Europe / Middle East"
        case .asiaPacific: "Asia-Pacific"
        case .latinAmerica: "Latin America"
        case .africa: "Africa"
        case .local: "Local network"
        case .unknown: "Unresolved"
        }
    }

    nonisolated var registry: String? {
        switch self {
        case .northAmerica: "ARIN"
        case .europe: "RIPE NCC"
        case .asiaPacific: "APNIC"
        case .latinAmerica: "LACNIC"
        case .africa: "AFRINIC"
        case .local,
             .unknown: nil
        }
    }

    /// Representative point for drawing, in degrees. The centre of the region a
    /// registry serves — not a claim about any individual address.
    nonisolated var coordinate: (latitude: Double, longitude: Double) {
        switch self {
        case .northAmerica: (40, -100)
        case .europe: (50, 15)
        case .asiaPacific: (20, 110)
        case .latinAmerica: (-15, -60)
        case .africa: (2, 20)
        case .local: (0, 0)
        case .unknown: (0, 0)
        }
    }
}

// MARK: - EndpointRegionResolver

/// Maps an IPv4 address to the registry that administers its block.
///
/// The table is the IANA IPv4 `/8` allocation list, which is stable and small
/// enough to hold in the binary. It is intentionally not exhaustive to the /8:
/// legacy and mixed blocks resolve to `.unknown` rather than being guessed at,
/// because a wrong region drawn confidently is worse than an honest gap.
enum EndpointRegionResolver {
    // MARK: Internal

    static func region(forEndpoint endpoint: String) -> EndpointRegion {
        guard let address = Self.address(from: endpoint) else {
            return .unknown
        }
        return region(forAddress: address)
    }

    static func region(forAddress address: String) -> EndpointRegion {
        let parts = address.split(separator: ".")
        guard parts.count == 4, let first = UInt8(parts[0]), let second = UInt8(parts[1]) else {
            // IPv6 and anything unparsable. We could map IPv6 too, but the /8
            // table does not apply, and half-answering would be worse.
            return .unknown
        }
        if isLocal(first: first, second: second) {
            return .local
        }
        return allocations[first] ?? .unknown
    }

    // MARK: Private

    /// IANA IPv4 `/8` allocations, keyed by first octet. Blocks that are legacy,
    /// shared, or split across registries are deliberately absent so they resolve
    /// to `.unknown`.
    private static let allocations: [UInt8: EndpointRegion] = {
        var table: [UInt8: EndpointRegion] = [:]
        func assign(_ octets: [UInt8], _ region: EndpointRegion) {
            for octet in octets {
                table[octet] = region
            }
        }
        assign(
            [
                3,
                4,
                6,
                7,
                8,
                9,
                11,
                12,
                13,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                26,
                28,
                29,
                30,
                32,
                33,
                34,
                35,
                38,
                40,
                44,
                45,
                47,
                48,
                50,
                52,
                54,
                55,
                56,
                63,
                64,
                65,
                66,
                67,
                68,
                69,
                70,
                71,
                72,
                73,
                74,
                75,
                76,
                96,
                97,
                98,
                99,
                104,
                107,
                108,
                128,
                129,
                130,
                131,
                132,
                134,
                135,
                136,
                137,
                138,
                139,
                140,
                142,
                143,
                144,
                146,
                147,
                148,
                149,
                152,
                155,
                156,
                157,
                158,
                159,
                160,
                161,
                162,
                164,
                165,
                166,
                167,
                168,
                169,
                170,
                172,
                173,
                174,
                184,
                192,
                198,
                199,
                204,
                205,
                206,
                207,
                208,
                209,
                214,
                215,
                216
            ],
            .northAmerica
        )
        assign(
            [
                2,
                5,
                25,
                31,
                37,
                46,
                51,
                53,
                57,
                62,
                77,
                78,
                79,
                80,
                81,
                82,
                83,
                84,
                85,
                86,
                87,
                88,
                89,
                90,
                91,
                92,
                93,
                94,
                95,
                109,
                141,
                145,
                151,
                176,
                178,
                185,
                188,
                193,
                194,
                195,
                212,
                213,
                217
            ],
            .europe
        )
        assign(
            [
                1,
                14,
                27,
                36,
                39,
                42,
                43,
                49,
                58,
                59,
                60,
                61,
                101,
                103,
                106,
                110,
                111,
                112,
                113,
                114,
                115,
                116,
                117,
                118,
                119,
                120,
                121,
                122,
                123,
                124,
                125,
                126,
                133,
                150,
                153,
                163,
                171,
                175,
                180,
                182,
                183,
                202,
                203,
                210,
                211,
                218,
                219,
                220,
                221,
                222,
                223
            ],
            .asiaPacific
        )
        assign([177, 179, 181, 186, 187, 189, 190, 191, 200, 201], .latinAmerica)
        assign([41, 102, 105, 154, 196, 197], .africa)
        return table
    }()

    /// Strips the port. IPv6 literals carry several colons, so split from the right.
    private static func address(from endpoint: String) -> String? {
        guard let separator = endpoint.lastIndex(of: ":") else {
            return endpoint.isEmpty ? nil : endpoint
        }
        let host = String(endpoint[endpoint.startIndex ..< separator])
        return host.isEmpty ? nil : host
    }

    private static func isLocal(first: UInt8, second: UInt8) -> Bool {
        switch first {
        case 0,
             10,
             127: true // this network, private, loopback
        case 100: (64 ... 127).contains(second) // carrier-grade NAT
        case 169: second == 254 // link-local
        case 172: (16 ... 31).contains(second) // private
        case 192: second == 168 // private
        case 224 ... 255: true // multicast and reserved
        default: false
        }
    }
}
