import Foundation
@testable import Tracexy

// MARK: - MMDBTestValue

/// A value to write into a test database, with its exact wire type.
indirect enum MMDBTestValue: Sendable {
    case string(String)
    case double(Double)
    case bytes([UInt8])
    case uint16(UInt16)
    case uint32(UInt32)
    case int32(Int32)
    case uint64(UInt64)
    case uint128(high: UInt64, low: UInt64)
    case map([(String, MMDBTestValue)])
    case array([MMDBTestValue])
    case boolean(Bool)
    case float(Float)
    /// A raw pointer to `offset` in the data section (for hostile files).
    case pointer(Int)
    /// Bytes written exactly as given (for hostile files).
    case raw([UInt8])

    // MARK: Internal

    /// What the reader should decode this to. Written as statements with explicit
    /// result types: the recursive `.map` case as a switch expression made the
    /// type checker report a circular reference in some compile batches.
    var decoded: MaxMindValue {
        switch self {
        case let .string(value):
            return MaxMindValue.string(value)
        case let .double(value):
            return MaxMindValue.double(value)
        case let .bytes(value):
            return MaxMindValue.bytes(value)
        case let .uint16(value):
            return MaxMindValue.unsigned(UInt64(value))
        case let .uint32(value):
            return MaxMindValue.unsigned(UInt64(value))
        case let .int32(value):
            return MaxMindValue.int32(value)
        case let .uint64(value):
            return MaxMindValue.unsigned(value)
        case let .uint128(high, low):
            return MaxMindValue.uint128(high: high, low: low)
        case let .map(entries):
            var dictionary: [String: MaxMindValue] = [:]
            for entry in entries {
                let value: MMDBTestValue = entry.1
                dictionary[entry.0] = value.decoded
            }
            return MaxMindValue.map(dictionary)
        case let .array(items):
            var values: [MaxMindValue] = []
            for item in items {
                values.append(item.decoded)
            }
            return MaxMindValue.array(values)
        case let .boolean(value):
            return MaxMindValue.boolean(value)
        case let .float(value):
            return MaxMindValue.float(value)
        case .pointer,
             .raw:
            return MaxMindValue.boolean(false)
        }
    }
}

// MARK: - MMDBTestWriter

/// Writes MaxMind DB files for tests, following the MaxMind DB File Format
/// Specification 2.0: a binary search tree, 16 zero bytes, the data section, the
/// metadata marker and the metadata map. Independent of the reader under test.
struct MMDBTestWriter {
    // MARK: Lifecycle

    init(ipVersion: Int = 6, recordSize: Int = 28, databaseType: String = "Tracexy-Test-City") {
        self.ipVersion = ipVersion
        self.recordSize = recordSize
        self.databaseType = databaseType
    }

    // MARK: Internal

    var ipVersion: Int
    var recordSize: Int
    var databaseType: String
    var buildEpoch: UInt64 = 1_788_000_000
    var languages = ["en", "de"]
    /// Write repeated map keys and strings once and point at them afterwards.
    var deduplicatesStrings = true
    /// Metadata entries replaced or added (for hostile files).
    var metadataOverrides: [(String, MMDBTestValue)] = []

    /// A GeoLite2-City-shaped record.
    static func city(code: String, country: String, city: String?, germanCountry: String? = nil) -> MMDBTestValue {
        var countryNames: [(String, MMDBTestValue)] = [("en", .string(country))]
        if let germanCountry {
            countryNames.append(("de", .string(germanCountry)))
        }
        var entries: [(String, MMDBTestValue)] = [
            ("continent", .map([("code", .string("EU"))])),
            ("country", .map([
                ("geoname_id", .uint32(2_921_044)),
                ("iso_code", .string(code)),
                ("names", .map(countryNames)),
            ])),
            ("location", .map([
                ("latitude", .double(52.52)),
                ("longitude", .double(13.40)),
                ("accuracy_radius", .uint16(20)),
            ])),
        ]
        if let city {
            entries.append(("city", .map([("names", .map([("en", .string(city))]))])))
        }
        return .map(entries)
    }

    /// A GeoLite2-ASN-shaped record.
    static func asn(_ number: UInt32, _ organization: String) -> MMDBTestValue {
        .map([
            ("autonomous_system_number", .uint32(number)),
            ("autonomous_system_organization", .string(organization)),
        ])
    }

    /// Insert `value` for `cidr`. IPv4 networks in an IPv6 tree go under ::/96, as
    /// MaxMind's writer puts them.
    mutating func insert(_ cidr: String, _ value: MMDBTestValue) {
        let parts = cidr.split(separator: "/")
        guard let address = IPAddressValue(parsing: String(parts[0])) else {
            preconditionFailure("bad test network \(cidr)")
        }
        var prefix = parts.count == 2 ? Int(parts[1]) ?? 0 : address.bytes.count * 8
        var bits = Self.bits(address.bytes)
        if address.family == .v4, ipVersion == 6 {
            bits = Array(repeating: 0, count: 96) + bits
            prefix += 96
        }
        networks.append((Array(bits.prefix(prefix)), value))
    }

    /// The file's bytes.
    func build() -> [UInt8] {
        var nodes: [[Record]] = [[.empty, .empty]]
        var data: [UInt8] = []
        var encoder = Encoder(deduplicates: deduplicatesStrings)
        for (path, value) in networks {
            let offset = encoder.encode(value, into: &data)
            var node = 0
            for (depth, bit) in path.enumerated() {
                if depth == path.count - 1 {
                    nodes[node][bit] = .data(offset)
                    break
                }
                if case let .node(next) = nodes[node][bit] {
                    node = next
                } else {
                    nodes.append([.empty, .empty])
                    nodes[node][bit] = .node(nodes.count - 1)
                    node = nodes.count - 1
                }
            }
        }
        let nodeCount = nodes.count
        var file: [UInt8] = []
        for node in nodes {
            let values = node.map { record -> Int in
                switch record {
                case .empty: nodeCount
                case let .node(index): index
                case let .data(offset): nodeCount + 16 + offset
                }
            }
            file += Self.encodeNode(left: values[0], right: values[1], recordSize: recordSize)
        }
        file += Array(repeating: 0, count: 16)
        file += data
        file += MaxMindDatabase.metadataMarker
        var metadataEntries: [(String, MMDBTestValue)] = [
            ("node_count", .uint32(UInt32(nodeCount))),
            ("record_size", .uint16(UInt16(recordSize))),
            ("ip_version", .uint16(UInt16(ipVersion))),
            ("database_type", .string(databaseType)),
            ("languages", .array(languages.map { .string($0) })),
            ("binary_format_major_version", .uint16(2)),
            ("binary_format_minor_version", .uint16(0)),
            ("build_epoch", .uint64(buildEpoch)),
            ("description", .map([("en", .string("Tracexy test database"))])),
        ]
        for (key, value) in metadataOverrides {
            metadataEntries.removeAll { $0.0 == key }
            metadataEntries.append((key, value))
        }
        var metadataEncoder = Encoder(deduplicates: false)
        var metadata: [UInt8] = []
        _ = metadataEncoder.encode(.map(metadataEntries), into: &metadata)
        return file + metadata
    }

    // MARK: Private

    private enum Record {
        case empty
        case node(Int)
        case data(Int)
    }

    /// Data section encoder.
    private struct Encoder {
        let deduplicates: Bool
        var written: [String: Int] = [:]

        static func control(type: Int, size: Int) -> [UInt8] {
            var bytes: [UInt8]
            let sizeBits: Int
            var extra: [UInt8] = []
            switch size {
            case ..<29:
                sizeBits = size
            case ..<285:
                sizeBits = 29
                extra = [UInt8(size - 29)]
            case ..<65_821:
                sizeBits = 30
                extra = bigEndian(UInt64(size - 285), count: 2)
            default:
                sizeBits = 31
                extra = bigEndian(UInt64(size - 65_821), count: 3)
            }
            if type <= 7 {
                bytes = [UInt8(type << 5 | sizeBits)]
            } else {
                bytes = [UInt8(sizeBits), UInt8(type - 7)]
            }
            return bytes + extra
        }

        static func pointer(_ target: Int) -> [UInt8] {
            switch target {
            case ..<2_048:
                return [UInt8(0x20 | (target >> 8) & 0x7), UInt8(target & 0xFF)]
            case ..<526_336:
                let value = target - 2_048
                return [UInt8(0x28 | (value >> 16) & 0x7)] + bigEndian(UInt64(value & 0xFFFF), count: 2)
            case ..<134_744_064:
                let value = target - 526_336
                return [UInt8(0x30 | (value >> 24) & 0x7)] + bigEndian(UInt64(value & 0xFFFFFF), count: 3)
            default:
                return [0x38] + bigEndian(UInt64(target), count: 4)
            }
        }

        static func unsigned(type: Int, _ value: UInt64) -> [UInt8] {
            var bytes = bigEndian(value, count: 8)
            while let first = bytes.first, first == 0 {
                bytes.removeFirst()
            }
            return control(type: type, size: bytes.count) + bytes
        }

        static func bigEndian(_ value: UInt64, count: Int) -> [UInt8] {
            (0 ..< count).map { UInt8(truncatingIfNeeded: value >> UInt64(8 * (count - 1 - $0))) }
        }

        mutating func encode(_ value: MMDBTestValue, into data: inout [UInt8]) -> Int {
            let offset = data.count
            switch value {
            case let .string(text):
                if deduplicates, let previous = written[text] {
                    data += Self.pointer(previous)
                } else {
                    let bytes = Array(text.utf8)
                    data += Self.control(type: 2, size: bytes.count) + bytes
                    if deduplicates {
                        written[text] = offset
                    }
                }
            case let .double(number):
                data += Self.control(type: 3, size: 8) + Self.bigEndian(number.bitPattern, count: 8)
            case let .bytes(bytes):
                data += Self.control(type: 4, size: bytes.count) + bytes
            case let .uint16(number):
                data += Self.unsigned(type: 5, UInt64(number))
            case let .uint32(number):
                data += Self.unsigned(type: 6, UInt64(number))
            case let .int32(number):
                let bytes = Self.bigEndian(UInt64(UInt32(bitPattern: number)), count: 4)
                data += Self.control(type: 8, size: 4) + bytes
            case let .uint64(number):
                data += Self.unsigned(type: 9, number)
            case let .uint128(high, low):
                data += Self.control(type: 10, size: 16) + Self.bigEndian(high, count: 8) + Self.bigEndian(
                    low,
                    count: 8
                )
            case let .map(entries):
                data += Self.control(type: 7, size: entries.count)
                for (key, entry) in entries {
                    _ = encode(.string(key), into: &data)
                    _ = encode(entry, into: &data)
                }
            case let .array(items):
                data += Self.control(type: 11, size: items.count)
                for item in items {
                    _ = encode(item, into: &data)
                }
            case let .boolean(flag):
                data += Self.control(type: 14, size: flag ? 1 : 0)
            case let .float(number):
                data += Self.control(type: 15, size: 4) + Self.bigEndian(UInt64(number.bitPattern), count: 4)
            case let .pointer(target):
                data += Self.pointer(target)
            case let .raw(bytes):
                data += bytes
            }
            return offset
        }
    }

    private var networks: [(bits: [Int], value: MMDBTestValue)] = []

    private static func bits(_ bytes: [UInt8]) -> [Int] {
        bytes.flatMap { byte in (0 ..< 8).map { Int(byte >> UInt8(7 - $0)) & 1 } }
    }

    private static func encodeNode(left: Int, right: Int, recordSize: Int) -> [UInt8] {
        switch recordSize {
        case 24:
            return Encoder.bigEndian(UInt64(left), count: 3) + Encoder.bigEndian(UInt64(right), count: 3)
        case 28:
            let middle = UInt8((left >> 24) & 0x0F) << 4 | UInt8((right >> 24) & 0x0F)
            return Encoder.bigEndian(UInt64(left & 0xFFFFFF), count: 3) + [middle]
                + Encoder.bigEndian(UInt64(right & 0xFFFFFF), count: 3)
        default:
            return Encoder.bigEndian(UInt64(left), count: 4) + Encoder.bigEndian(UInt64(right), count: 4)
        }
    }
}

// MARK: - GeoIPFixtures

/// The databases the GeoIP tests and native QA use. Documentation ranges
/// (RFC 5737, RFC 3849) stand in for public networks; no real database is used.
enum GeoIPFixtures {
    /// City: 203.0.113.0/24 Germany/Berlin, 198.51.100.0/24 Japan/Tokyo,
    /// 192.0.2.0/25 France (no city), 2001:db8::/32 Canada/Toronto, and a hostile
    /// record for 10.0.0.0/8 that must never be read.
    static func city(recordSize: Int = 28) -> [UInt8] {
        var writer = MMDBTestWriter(ipVersion: 6, recordSize: recordSize, databaseType: "Tracexy-Test-City")
        writer.insert("203.0.113.0/24", MMDBTestWriter.city(
            code: "DE", country: "Germany", city: "Berlin", germanCountry: "Deutschland"
        ))
        writer.insert("198.51.100.0/24", MMDBTestWriter.city(code: "JP", country: "Japan", city: "Tokyo"))
        writer.insert("192.0.2.0/25", MMDBTestWriter.city(code: "FR", country: "France", city: nil))
        writer.insert("2001:db8::/32", MMDBTestWriter.city(code: "CA", country: "Canada", city: "Toronto"))
        writer.insert("10.0.0.0/8", MMDBTestWriter.city(code: "XX", country: "Leaked", city: "Leaked"))
        return writer.build()
    }

    /// ASN: 203.0.113.0/25 AS64500, 203.0.113.128/25 AS64501, 198.51.100.0/24
    /// AS64502, 2001:db8::/32 AS64503 (private-use AS numbers, RFC 6996).
    static func asn(recordSize: Int = 24) -> [UInt8] {
        var writer = MMDBTestWriter(ipVersion: 6, recordSize: recordSize, databaseType: "Tracexy-Test-ASN")
        writer.insert("203.0.113.0/25", MMDBTestWriter.asn(64_500, "Example Transit GmbH"))
        writer.insert("203.0.113.128/25", MMDBTestWriter.asn(64_501, "Example Hosting AG"))
        writer.insert("198.51.100.0/24", MMDBTestWriter.asn(64_502, "Example Networks KK"))
        writer.insert("2001:db8::/32", MMDBTestWriter.asn(64_503, "Example Six Inc."))
        return writer.build()
    }
}

// MARK: - GeoIPFixtures + independent writer

extension GeoIPFixtures {
    /// Written by `mmdb_writer` 0.2.7 (Python, independent of ``MMDBTestWriter``):
    /// IPv6 tree, 24-bit records, IPv4 at ::/96; the same networks as ``city()``
    /// with `location` doubles and `geoname_id`. Python `maxminddb` 2.8.2 reads it as
    /// ``IndependentCityOracle`` says.
    static let independentCity = decode([
        "AAABAADCAAACAADCAAADAAClAAAEAADCAAAFAADCAAAGAADCAAAHAADCAAAIAADCAAAJAADCAAAKAADCAAALAADCAAAMAADCAAAN",
        "AADCAAAOAADCAAAPAADCAAAQAADCAAARAADCAAASAADCAAATAADCAAAUAADCAAAVAADCAAAWAADCAAAXAADCAAAYAADCAAAZAADC",
        "AAAaAADCAAAbAADCAAAcAADCAAAdAADCAAAeAADCAAAfAADCAAAgAADCAAAhAADCAAAiAADCAAAjAADCAAAkAADCAAAlAADCAAAm",
        "AADCAAAnAADCAAAoAADCAAApAADCAAAqAADCAAArAADCAAAsAADCAAAtAADCAAAuAADCAAAvAADCAAAwAADCAAAxAADCAAAyAADC",
        "AAAzAADCAAA0AADCAAA1AADCAAA2AADCAAA3AADCAAA4AADCAAA5AADCAAA6AADCAAA7AADCAAA8AADCAAA9AADCAAA+AADCAAA/",
        "AADCAABAAADCAABBAADCAABCAADCAABDAADCAABEAADCAABFAADCAABGAADCAABHAADCAABIAADCAABJAADCAABKAADCAABLAADC",
        "AABMAADCAABNAADCAABOAADCAABPAADCAABQAADCAABRAADCAABSAADCAABTAADCAABUAADCAABVAADCAABWAADCAABXAADCAABY",
        "AADCAABZAADCAABaAADCAABbAADCAABcAADCAABdAADCAABeAADCAABfAADCAABgAADCAABhAABoAABiAADCAABjAADCAABkAADC",
        "AADCAABlAABmAADCAADCAABnAAGQAADCAADCAABpAABqAADCAABrAADCAABsAACSAABtAACAAABuAADCAABvAADCAABwAADCAABx",
        "AADCAAByAADCAABzAADCAAB0AADCAAB1AADCAAB2AADCAAB3AADCAAB4AADCAAB5AADCAAB6AADCAAB7AADCAAB8AADCAAB9AADC",
        "AADCAAB+AAB/AADCAAHeAADCAADCAACBAACCAADCAACDAADCAACEAADCAADCAACFAADCAACGAACHAADCAACIAADCAADCAACJAADC",
        "AACKAACLAADCAADCAACMAADCAACNAACOAADCAACPAADCAADCAACQAACRAADCAAIsAADCAACTAADCAADCAACUAADCAACVAACWAADC",
        "AACXAADCAACYAADCAACZAADCAACaAADCAACbAADCAACcAADCAACdAADCAACeAADCAADCAACfAADCAACgAADCAAChAACiAADCAACj",
        "AADCAACkAADCAADCAAKNAACmAADCAACnAADCAACoAADCAACpAADCAACqAADCAACrAADCAACsAADCAACtAADCAACuAADCAACvAADC",
        "AACwAADCAACxAADCAADCAACyAACzAADCAAC0AADCAAC1AADCAAC2AADCAADCAAC3AADCAAC4AAC5AADCAADCAAC6AADCAAC7AAC8",
        "AADCAADCAAC9AADCAAC+AADCAAC/AADAAADCAADBAADCAALpAADCAAAAAAAAAAAAAAAAAAAAAEljb250aW5lbnREY29kZUJFVeEg",
        "CiAPR2NvdW50cnlIaXNvX2NvZGVCWFhFbmFtZXNCZW5GTGVha2VkQmRl4iAxIDQgOyA0Smdlb25hbWVfaWTCA+jjIB8gKCArID4g",
        "RyBSSGxvY2F0aW9uSGxhdGl0dWRlaD/4AAAAAAAASWxvbmdpdHVkZWjAAgAAAAAAAE9hY2N1cmFjeV9yYWRpdXOhMuMgayB0IH0g",
        "hyCQIKBEY2l0eeEgMSA04SArILTkIAAgEiAXIFUgYiCiIK8guUJGUkZGcmFuY2VKRnJhbmtyZWljaOIgMSDSIDsg2cID6OMgHyDP",
        "ICsg5CBHIO2hMuMgayB0IH0ghyCQIP3jIAAgEiAXIPAgYiD/QkpQRUphcGFu4iAxIRwgOyEcwgPo4yAfIRkgKyEiIEchK6Ey4yBr",
        "IHQgfSCHIJAhO0VUb2t5b+EgMSFK4SArIVDkIAAgEiAXIS4gYiE9IK8hVUJERUdHZXJtYW55S0RldXRzY2hsYW5k4iAxIW4gOyF2",
        "wgPo4yAfIWsgKyGCIEchi6Ey4yBrIHQgfSCHIJAhm0ZCZXJsaW7hIDEhquEgKyGx5CAAIBIgFyGOIGIhnSCvIbZCQ0FGQ2FuYWRh",
        "RkthbmFkYeIgMSHPIDsh1sID6OMgHyHMICsh3SBHIeahMuMgayB0IH0ghyCQIfZHVG9yb250b+EgMSIF4SArIg3kIAAgEiAXIekg",
        "YiH4IK8iEqvN701heE1pbmQuY29t6Upub2RlX2NvdW50wcJLcmVjb3JkX3NpemWhGEppcF92ZXJzaW9uoQZNZGF0YWJhc2VfdHlw",
        "ZUdRQS1DaXR5SWxhbmd1YWdlcwIEQmVuQmRlW2JpbmFyeV9mb3JtYXRfbWFqb3JfdmVyc2lvbqECW2JpbmFyeV9mb3JtYXRfbWlu",
        "b3JfdmVyc2lvbqBLZGVzY3JpcHRpb27iQmVuT1RyYWNleHkgUUEgY2l0eUJkZVBUcmFjZXh5IFFBIFN0YWR0S2J1aWxkX2Vwb2No",
        "BAJqtBha",
    ])

    /// Written by `mmdb_writer` 0.2.7: the same networks as ``asn()``.
    static let independentASN = decode([
        "AAABAACpAAACAACpAAADAACMAAAEAACpAAAFAACpAAAGAACpAAAHAACpAAAIAACpAAAJAACpAAAKAACpAAALAACpAAAMAACpAAAN",
        "AACpAAAOAACpAAAPAACpAAAQAACpAAARAACpAAASAACpAAATAACpAAAUAACpAAAVAACpAAAWAACpAAAXAACpAAAYAACpAAAZAACp",
        "AAAaAACpAAAbAACpAAAcAACpAAAdAACpAAAeAACpAAAfAACpAAAgAACpAAAhAACpAAAiAACpAAAjAACpAAAkAACpAAAlAACpAAAm",
        "AACpAAAnAACpAAAoAACpAAApAACpAAAqAACpAAArAACpAAAsAACpAAAtAACpAAAuAACpAAAvAACpAAAwAACpAAAxAACpAAAyAACp",
        "AAAzAACpAAA0AACpAAA1AACpAAA2AACpAAA3AACpAAA4AACpAAA5AACpAAA6AACpAAA7AACpAAA8AACpAAA9AACpAAA+AACpAAA/",
        "AACpAABAAACpAABBAACpAABCAACpAABDAACpAABEAACpAABFAACpAABGAACpAABHAACpAABIAACpAABJAACpAABKAACpAABLAACp",
        "AABMAACpAABNAACpAABOAACpAABPAACpAABQAACpAABRAACpAABSAACpAABTAACpAABUAACpAABVAACpAABWAACpAABXAACpAABY",
        "AACpAABZAACpAABaAACpAABbAACpAABcAACpAABdAACpAABeAACpAABfAACpAABgAACpAACpAABhAACpAABiAABjAACpAABkAACp",
        "AABlAAB4AACpAABmAACpAABnAABoAACpAABpAACpAABqAACpAACpAABrAACpAABsAABtAACpAABuAACpAACpAABvAACpAABwAABx",
        "AACpAACpAAByAACpAABzAAB0AACpAAB1AACpAACpAAB2AAB3AACpAAEJAACpAAB5AACpAACpAAB6AACpAAB7AAB8AACpAAB9AACp",
        "AAB+AACpAAB/AACpAACAAACpAACBAACpAACCAACpAACDAACpAACEAACpAACpAACFAACpAACGAACpAACHAACIAACpAACJAACpAACK",
        "AACpAACpAACLAAEqAAFJAACNAACpAACOAACpAACPAACpAACQAACpAACRAACpAACSAACpAACTAACpAACUAACpAACVAACpAACWAACp",
        "AACXAACpAACYAACpAACpAACZAACaAACpAACbAACpAACcAACpAACdAACpAACpAACeAACpAACfAACgAACpAACpAAChAACpAACiAACj",
        "AACpAACpAACkAACpAAClAACpAACmAACnAACpAACoAACpAAFmAACpAAAAAAAAAAAAAAAAAAAAAFhhdXRvbm9tb3VzX3N5c3RlbV9u",
        "dW1iZXLC+/ZdAWF1dG9ub21vdXNfc3lzdGVtX29yZ2FuaXphdGlvblNFeGFtcGxlIE5ldHdvcmtzIEtL4iAAIBkgHCA8wvv0VEV4",
        "YW1wbGUgVHJhbnNpdCBHbWJI4iAAIFkgHCBcwvv1UkV4YW1wbGUgSG9zdGluZyBBR+IgACB6IBwgfcL791BFeGFtcGxlIFNpeCBJ",
        "bmMu4iAAIJkgHCCcq83vTWF4TWluZC5jb23pSm5vZGVfY291bnTBqUtyZWNvcmRfc2l6ZaEYSmlwX3ZlcnNpb26hBk1kYXRhYmFz",
        "ZV90eXBlRlFBLUFTTklsYW5ndWFnZXMBBEJlbltiaW5hcnlfZm9ybWF0X21ham9yX3ZlcnNpb26hAltiaW5hcnlfZm9ybWF0X21p",
        "bm9yX3ZlcnNpb26gS2Rlc2NyaXB0aW9u4UJlbk5UcmFjZXh5IFFBIEFTTktidWlsZF9lcG9jaAQCarQYWg==",
    ])

    private static func decode(_ lines: [String]) -> [UInt8] {
        guard let data = Data(base64Encoded: lines.joined()) else {
            preconditionFailure("bad fixture")
        }
        return [UInt8](data)
    }
}
