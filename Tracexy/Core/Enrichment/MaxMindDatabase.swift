import Foundation

// MARK: - MaxMindValue

/// One decoded value from a MaxMind DB data section.
nonisolated enum MaxMindValue: Hashable, Sendable {
    case string(String)
    case double(Double)
    case bytes([UInt8])
    /// uint16, uint32 and uint64.
    case unsigned(UInt64)
    case uint128(high: UInt64, low: UInt64)
    case int32(Int32)
    case map([String: MaxMindValue])
    case array([MaxMindValue])
    case boolean(Bool)
    case float(Float)

    // MARK: Internal

    var stringValue: String? {
        if case let .string(value) = self {
            return value
        }
        return nil
    }

    /// An unsigned or non-negative signed integer.
    var unsignedValue: UInt64? {
        switch self {
        case let .unsigned(value): value
        case let .int32(value) where value >= 0: UInt64(value)
        case let .uint128(high, low) where high == 0: low
        default: nil
        }
    }

    var mapValue: [String: MaxMindValue]? {
        if case let .map(value) = self {
            return value
        }
        return nil
    }

    subscript(key: String) -> MaxMindValue? {
        mapValue?[key]
    }

    /// The value at `path` through nested maps.
    func value(at path: [String]) -> MaxMindValue? {
        var current: MaxMindValue? = self
        for key in path {
            current = current?[key]
        }
        return current
    }
}

// MARK: - MaxMindDatabaseError

/// Why a file is not a MaxMind DB Tracexy can read, or why a lookup failed.
nonisolated enum MaxMindDatabaseError: Error, Hashable, Sendable {
    case notARegularFile
    case tooLarge(limit: Int)
    case noMetadata
    case invalidMetadata(String)
    case unsupportedFormat(major: UInt64)
    /// The search tree points outside itself or the data section.
    case corruptSearchTree
    /// A data section value is malformed or points outside its section.
    case corruptData
    /// Maps or arrays are nested deeper than ``MaxMindDatabase/maximumDepth``.
    case tooDeep
    /// A value holds more than ``MaxMindDatabase/maximumValuesPerRecord`` values.
    case tooManyValues
}

// MARK: - MaxMindDatabase

/// A pure, bounded reader for the MaxMind DB format (version 2), as written by
/// MaxMind for GeoLite2/GeoIP2 and by DB-IP for its MMDB files.
///
/// The whole file is held in memory; nothing is written, fetched or cached. The
/// reader validates the metadata and the search tree's bounds when it is made, and
/// decodes records with a depth and value budget, so a hostile file can fail a
/// lookup but can't make one unbounded.
///
/// See the MaxMind DB File Format Specification, version 2.0.
nonisolated struct MaxMindDatabase: Sendable {
    // MARK: Lifecycle

    init(bytes: [UInt8]) throws {
        guard bytes.count <= Self.maximumFileBytes else {
            throw MaxMindDatabaseError.tooLarge(limit: Self.maximumFileBytes)
        }
        guard let markerStart = Self.metadataMarkerStart(in: bytes) else {
            throw MaxMindDatabaseError.noMetadata
        }
        let metadataStart = markerStart + Self.metadataMarker.count
        var budget = Self.maximumValuesPerRecord
        let decoded = try Self.decode(
            bytes,
            at: metadataStart,
            section: metadataStart ..< bytes.count,
            depth: 0,
            budget: &budget
        ).value
        let metadata = try Metadata(decoded)
        let nodeBytes = metadata.recordSize * 2 / 8
        let (treeBytes, overflow) = metadata.nodeCount.multipliedReportingOverflow(by: nodeBytes)
        guard !overflow, treeBytes + Self.dataSeparatorBytes <= markerStart else {
            throw MaxMindDatabaseError.invalidMetadata("node_count")
        }
        self.bytes = bytes
        self.metadata = metadata
        self.nodeBytes = nodeBytes
        dataSection = (treeBytes + Self.dataSeparatorBytes) ..< markerStart

        // IPv4 addresses live at ::/96 of an IPv6 tree: follow 96 zero bits once.
        var node = 0
        var depth = 0
        if metadata.ipVersion == 6 {
            while depth < 96, node < metadata.nodeCount {
                node = Self.record(bytes, node: node, bit: 0, recordSize: metadata.recordSize, nodeBytes: nodeBytes)
                depth += 1
            }
        }
        ipv4Start = (node: node, depth: depth)
    }

    // MARK: Internal

    /// One lookup's answer: the record, and the network it covers.
    nonisolated struct Lookup: Hashable, Sendable {
        let value: MaxMindValue
        /// Prefix length of the network in the address's own family.
        let prefixLength: Int
    }

    /// What the metadata section says about the database.
    nonisolated struct Metadata: Hashable, Sendable {
        // MARK: Lifecycle

        init(_ value: MaxMindValue) throws {
            guard case .map = value else {
                throw MaxMindDatabaseError.invalidMetadata("metadata")
            }
            guard let major = value["binary_format_major_version"]?.unsignedValue else {
                throw MaxMindDatabaseError.invalidMetadata("binary_format_major_version")
            }
            guard major == 2 else {
                throw MaxMindDatabaseError.unsupportedFormat(major: major)
            }
            guard let nodes = value["node_count"]?.unsignedValue, nodes > 0, nodes < UInt64(UInt32.max) else {
                throw MaxMindDatabaseError.invalidMetadata("node_count")
            }
            guard let size = value["record_size"]?.unsignedValue, [24, 28, 32].contains(size) else {
                throw MaxMindDatabaseError.invalidMetadata("record_size")
            }
            guard let version = value["ip_version"]?.unsignedValue, version == 4 || version == 6 else {
                throw MaxMindDatabaseError.invalidMetadata("ip_version")
            }
            guard let type = value["database_type"]?.stringValue, !type.isEmpty else {
                throw MaxMindDatabaseError.invalidMetadata("database_type")
            }
            nodeCount = Int(nodes)
            recordSize = Int(size)
            ipVersion = Int(version)
            databaseType = String(type.prefix(Self.maximumTextCharacters))
            buildEpoch = value["build_epoch"]?.unsignedValue
            if case let .array(items)? = value["languages"] {
                languages = items.prefix(Self.maximumLanguages).compactMap(\.stringValue)
            } else {
                languages = []
            }
            let english = value.value(at: ["description", "en"])?.stringValue
            descriptionText = english.map { String($0.prefix(Self.maximumTextCharacters)) }
        }

        // MARK: Internal

        static let maximumTextCharacters = 200
        static let maximumLanguages = 32

        let nodeCount: Int
        let recordSize: Int
        let ipVersion: Int
        let databaseType: String
        /// Seconds since 1970 when the database was built. Required by the format,
        /// but tolerated when missing.
        let buildEpoch: UInt64?
        let languages: [String]
        let descriptionText: String?

        var buildDate: Date? {
            buildEpoch.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        }
    }

    /// Larger files are refused before they are read.
    static let maximumFileBytes = 512 * 1_048_576
    /// Maps and arrays nested deeper than this are refused.
    static let maximumDepth = 32
    /// Values decoded for one record (or the metadata), counting every nested one.
    static let maximumValuesPerRecord = 20_000
    /// The metadata marker is searched for in this many trailing bytes.
    static let metadataSearchBytes = 128 * 1_024
    static let metadataMarker: [UInt8] = [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
    static let dataSeparatorBytes = 16

    let metadata: Metadata

    /// Read `url` into memory and validate it. Only regular files are read; the
    /// size is checked before reading.
    static func read(contentsOf url: URL) throws -> MaxMindDatabase {
        let resolved = url.resolvingSymlinksInPath()
        let values = try resolved.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else {
            throw MaxMindDatabaseError.notARegularFile
        }
        guard let size = values.fileSize, size <= maximumFileBytes else {
            throw MaxMindDatabaseError.tooLarge(limit: maximumFileBytes)
        }
        let handle = try FileHandle(forReadingFrom: resolved)
        defer {
            try? handle.close()
        }
        let data = try handle.read(upToCount: maximumFileBytes + 1) ?? Data()
        guard data.count <= maximumFileBytes else {
            throw MaxMindDatabaseError.tooLarge(limit: maximumFileBytes)
        }
        return try MaxMindDatabase(bytes: [UInt8](data))
    }

    /// The record for `address`, or `nil` when the database has none. An IPv6
    /// address can't be found in an IPv4 database.
    func lookup(_ address: IPAddressValue) throws -> Lookup? {
        guard let found = try search(address), let value = found.value else {
            return nil
        }
        return Lookup(value: value, prefixLength: found.prefixLength)
    }

    /// The record for `address`, or `nil` when there is none, with the prefix
    /// length of the network the search ended in: every address in that network
    /// gets the same answer, found or not. `nil` for an IPv6 address in an IPv4
    /// database.
    func search(_ address: IPAddressValue) throws -> (value: MaxMindValue?, prefixLength: Int)? {
        let addressBits = address.bytes.count * 8
        let isMapped = address.family == .v4 && metadata.ipVersion == 6
        if address.family == .v6, metadata.ipVersion == 4 {
            return nil
        }
        // Tree bits already walked before the address's own: 96 zero bits (or
        // fewer, where the tree ends early) for IPv4 in an IPv6 tree.
        var node = isMapped ? ipv4Start.node : 0
        let walkedBefore = isMapped ? ipv4Start.depth : 0
        var bitIndex = 0
        while node < metadata.nodeCount, bitIndex < addressBits {
            let byte = address.bytes[bitIndex / 8]
            let bit = Int((byte >> UInt8(7 - bitIndex % 8)) & 1)
            node = Self.record(bytes, node: node, bit: bit, recordSize: metadata.recordSize, nodeBytes: nodeBytes)
            bitIndex += 1
        }
        let walked = walkedBefore + bitIndex
        let prefixLength = min(isMapped ? max(0, walked - 96) : walked, addressBits)
        if node == metadata.nodeCount {
            return (nil, prefixLength)
        }
        guard node > metadata.nodeCount else {
            throw MaxMindDatabaseError.corruptSearchTree
        }
        let relative = node - metadata.nodeCount - Self.dataSeparatorBytes
        let position = dataSection.lowerBound + relative
        guard relative >= 0, dataSection.contains(position) else {
            throw MaxMindDatabaseError.corruptSearchTree
        }
        var budget = Self.maximumValuesPerRecord
        let value = try Self.decode(bytes, at: position, section: dataSection, depth: 0, budget: &budget).value
        return (value, prefixLength)
    }

    /// How many networks the database has a record for: every search-tree record
    /// that points into the data section. Stops early when `isCancelled` says so.
    func networkCount(isCancelled: () -> Bool = { false }) -> Int? {
        var count = 0
        for node in 0 ..< metadata.nodeCount {
            if node & 0xFFFF == 0, isCancelled() {
                return nil
            }
            for bit in 0 ... 1 {
                let value = Self.record(
                    bytes, node: node, bit: bit, recordSize: metadata.recordSize, nodeBytes: nodeBytes
                )
                if value > metadata.nodeCount {
                    count += 1
                }
            }
        }
        return count
    }

    // MARK: Private

    private let bytes: [UInt8]
    private let nodeBytes: Int
    private let dataSection: Range<Int>
    private let ipv4Start: (node: Int, depth: Int)

    /// The start of the last metadata marker in the file's trailing bytes.
    private static func metadataMarkerStart(in bytes: [UInt8]) -> Int? {
        let marker = metadataMarker
        guard bytes.count >= marker.count else {
            return nil
        }
        let lowest = max(0, bytes.count - metadataSearchBytes)
        var start = bytes.count - marker.count
        while start >= lowest {
            if bytes[start] == marker[0] {
                var matched = true
                for index in 1 ..< marker.count where bytes[start + index] != marker[index] {
                    matched = false
                    break
                }
                if matched {
                    return start
                }
            }
            start -= 1
        }
        return nil
    }

    /// The left (`bit == 0`) or right record of `node`. The caller keeps `node`
    /// below the node count, and the tree's size was checked against the file.
    private static func record(_ bytes: [UInt8], node: Int, bit: Int, recordSize: Int, nodeBytes: Int) -> Int {
        let base = node * nodeBytes
        switch recordSize {
        case 24:
            let start = base + bit * 3
            return Int(bytes[start]) << 16 | Int(bytes[start + 1]) << 8 | Int(bytes[start + 2])
        case 28:
            if bit == 0 {
                return (Int(bytes[base + 3]) & 0xF0) << 20
                    | Int(bytes[base]) << 16 | Int(bytes[base + 1]) << 8 | Int(bytes[base + 2])
            }
            return (Int(bytes[base + 3]) & 0x0F) << 24
                | Int(bytes[base + 4]) << 16 | Int(bytes[base + 5]) << 8 | Int(bytes[base + 6])
        default:
            let start = base + bit * 4
            return Int(bytes[start]) << 24 | Int(bytes[start + 1]) << 16
                | Int(bytes[start + 2]) << 8 | Int(bytes[start + 3])
        }
    }

    private static func readUnsigned(
        _ bytes: [UInt8],
        at start: Int,
        count: Int,
        section: Range<Int>
    )
        throws -> UInt64
    {
        guard count <= 8, start >= section.lowerBound, start + count <= section.upperBound else {
            throw MaxMindDatabaseError.corruptData
        }
        var value: UInt64 = 0
        for index in start ..< start + count {
            value = value << 8 | UInt64(bytes[index])
        }
        return value
    }

    /// Decode the value at `position`. Pointers are relative to `section`'s start
    /// and must land inside it; a pointer to a pointer is refused.
    private static func decode(
        _ bytes: [UInt8],
        at position: Int,
        section: Range<Int>,
        depth: Int,
        budget: inout Int,
        followsPointers: Bool = true
    )
        throws -> (value: MaxMindValue, next: Int)
    {
        guard depth <= maximumDepth else {
            throw MaxMindDatabaseError.tooDeep
        }
        budget -= 1
        guard budget >= 0 else {
            throw MaxMindDatabaseError.tooManyValues
        }
        guard section.contains(position) else {
            throw MaxMindDatabaseError.corruptData
        }
        let control = bytes[position]
        var cursor = position + 1
        var type = Int(control >> 5)

        if type == 1 {
            guard followsPointers else {
                throw MaxMindDatabaseError.corruptData
            }
            let sizeBits = Int(control >> 3) & 0x3
            let high = UInt64(control & 0x7)
            let pointer: UInt64 = switch sizeBits {
            case 0:
                try high << 8 | readUnsigned(bytes, at: cursor, count: 1, section: section)
            case 1:
                try (high << 16 | readUnsigned(bytes, at: cursor, count: 2, section: section)) + 2_048
            case 2:
                try (high << 24 | readUnsigned(bytes, at: cursor, count: 3, section: section)) + 526_336
            default:
                try readUnsigned(bytes, at: cursor, count: 4, section: section)
            }
            cursor += sizeBits + 1
            let target = section.lowerBound + Int(pointer)
            guard pointer < UInt64(section.count) else {
                throw MaxMindDatabaseError.corruptData
            }
            budget += 1 // the pointer itself is not a value
            let resolved = try decode(
                bytes, at: target, section: section, depth: depth, budget: &budget, followsPointers: false
            )
            return (resolved.value, cursor)
        }

        if type == 0 {
            let extended = try readUnsigned(bytes, at: cursor, count: 1, section: section)
            cursor += 1
            type = 7 + Int(extended)
            guard type >= 8, type <= 15 else {
                throw MaxMindDatabaseError.corruptData
            }
        }

        var size = Int(control & 0x1F)
        switch size {
        case 29:
            size = try 29 + Int(readUnsigned(bytes, at: cursor, count: 1, section: section))
            cursor += 1
        case 30:
            size = try 285 + Int(readUnsigned(bytes, at: cursor, count: 2, section: section))
            cursor += 2
        case 31:
            size = try 65_821 + Int(readUnsigned(bytes, at: cursor, count: 3, section: section))
            cursor += 3
        default:
            break
        }

        switch type {
        case 2,
             4:
            guard size <= section.upperBound - cursor else {
                throw MaxMindDatabaseError.corruptData
            }
            let slice = bytes[cursor ..< cursor + size]
            if type == 4 {
                return (.bytes(Array(slice)), cursor + size)
            }
            guard let text = String(bytes: slice, encoding: .utf8) else {
                throw MaxMindDatabaseError.corruptData
            }
            return (.string(text), cursor + size)
        case 3:
            guard size == 8 else {
                throw MaxMindDatabaseError.corruptData
            }
            let raw = try readUnsigned(bytes, at: cursor, count: 8, section: section)
            return (.double(Double(bitPattern: raw)), cursor + 8)
        case 15:
            guard size == 4 else {
                throw MaxMindDatabaseError.corruptData
            }
            let raw = try readUnsigned(bytes, at: cursor, count: 4, section: section)
            return (.float(Float(bitPattern: UInt32(raw))), cursor + 4)
        case 5,
             6,
             9:
            let limit = type == 5 ? 2 : (type == 6 ? 4 : 8)
            guard size <= limit else {
                throw MaxMindDatabaseError.corruptData
            }
            return try (.unsigned(readUnsigned(bytes, at: cursor, count: size, section: section)), cursor + size)
        case 8:
            guard size <= 4 else {
                throw MaxMindDatabaseError.corruptData
            }
            let raw = try readUnsigned(bytes, at: cursor, count: size, section: section)
            return (.int32(Int32(bitPattern: UInt32(truncatingIfNeeded: raw))), cursor + size)
        case 10:
            guard size <= 16 else {
                throw MaxMindDatabaseError.corruptData
            }
            let highCount = max(0, size - 8)
            let high = try readUnsigned(bytes, at: cursor, count: highCount, section: section)
            let low = try readUnsigned(bytes, at: cursor + highCount, count: size - highCount, section: section)
            return (.uint128(high: high, low: low), cursor + size)
        case 14:
            guard size <= 1 else {
                throw MaxMindDatabaseError.corruptData
            }
            return (.boolean(size == 1), cursor)
        case 7:
            // Every entry takes at least two bytes, so a count the section can't
            // hold is refused before anything is reserved.
            guard size <= (section.upperBound - cursor) / 2 else {
                throw MaxMindDatabaseError.corruptData
            }
            var map: [String: MaxMindValue] = [:]
            for _ in 0 ..< size {
                let key = try decode(bytes, at: cursor, section: section, depth: depth + 1, budget: &budget)
                guard case let .string(name) = key.value else {
                    throw MaxMindDatabaseError.corruptData
                }
                let entry = try decode(bytes, at: key.next, section: section, depth: depth + 1, budget: &budget)
                map[name] = entry.value
                cursor = entry.next
            }
            return (.map(map), cursor)
        case 11:
            guard size <= section.upperBound - cursor else {
                throw MaxMindDatabaseError.corruptData
            }
            var items: [MaxMindValue] = []
            for _ in 0 ..< size {
                let item = try decode(bytes, at: cursor, section: section, depth: depth + 1, budget: &budget)
                items.append(item.value)
                cursor = item.next
            }
            return (.array(items), cursor)
        default:
            // 12 (data cache container) and 13 (end marker) never appear in data.
            throw MaxMindDatabaseError.corruptData
        }
    }
}
