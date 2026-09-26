import Foundation
import Observation
import Testing
@testable import Tracexy

private func address(_ text: String) throws -> IPAddressValue {
    try #require(IPAddressValue(parsing: text))
}

// MARK: - MaxMindDatabaseTests

/// The MMDB reader against databases written by ``MMDBTestWriter`` (the MaxMind DB
/// File Format Specification 2.0), cross-checked with the `maxminddb` Python
/// reader and `mmdb_writer` during development.
@Suite("MaxMind DB reader")
struct MaxMindDatabaseTests {
    // MARK: Internal

    @Test("Every record size finds IPv4 and IPv6 networks with their prefix lengths", arguments: [24, 28, 32])
    func lookupsAtEveryRecordSize(recordSize: Int) throws {
        let database = try MaxMindDatabase(bytes: GeoIPFixtures.city(recordSize: recordSize))
        #expect(database.metadata.recordSize == recordSize)

        let berlin = try #require(try database.lookup(address("203.0.113.77")))
        #expect(berlin.prefixLength == 24)
        #expect(berlin.value.value(at: ["country", "iso_code"]) == .string("DE"))
        #expect(berlin.value.value(at: ["city", "names", "en"]) == .string("Berlin"))
        #expect(berlin.value.value(at: ["country", "names", "de"]) == .string("Deutschland"))

        let france = try #require(try database.lookup(address("192.0.2.1")))
        #expect(france.prefixLength == 25)
        #expect(france.value.value(at: ["city"]) == nil)
        #expect(try database.lookup(address("192.0.2.200")) == nil)

        let toronto = try #require(try database.lookup(address("2001:db8:1234::1")))
        #expect(toronto.prefixLength == 32)
        #expect(toronto.value.value(at: ["country", "iso_code"]) == .string("CA"))
        #expect(try database.lookup(address("2001:db9::1")) == nil)
        #expect(try database.lookup(address("8.8.8.8")) == nil)
    }

    @Test("Metadata: type, build date, languages, networks")
    func metadata() throws {
        let database = try MaxMindDatabase(bytes: GeoIPFixtures.city())
        #expect(database.metadata.databaseType == "Tracexy-Test-City")
        #expect(database.metadata.ipVersion == 6)
        #expect(database.metadata.languages == ["en", "de"])
        #expect(database.metadata.buildDate == Date(timeIntervalSince1970: 1_788_000_000))
        #expect(database.metadata.descriptionText == "Tracexy test database")
        #expect(database.networkCount() == 5)
        #expect(try MaxMindDatabase(bytes: GeoIPFixtures.asn()).networkCount() == 4)
    }

    @Test("An IPv4-only database answers IPv4 and never IPv6")
    func ipv4Tree() throws {
        var writer = MMDBTestWriter(ipVersion: 4, recordSize: 24)
        writer.insert("198.51.100.0/23", MMDBTestWriter.asn(64_502, "Example Networks KK"))
        let database = try MaxMindDatabase(bytes: writer.build())
        let found = try #require(try database.lookup(address("198.51.101.9")))
        #expect(found.prefixLength == 23)
        #expect(found.value["autonomous_system_number"] == .unsigned(64_502))
        #expect(try database.lookup(address("2001:db8::1")) == nil)
    }

    @Test("Every data type decodes, with and without pointers", arguments: [true, false])
    func everyType(deduplicates: Bool) throws {
        let record: MMDBTestValue = .map([
            ("utf8_string", .string("Zürich, 東京")),
            ("empty", .string("")),
            ("double", .double(-1.5)),
            ("float", .float(2.25)),
            ("bytes", .bytes([0, 1, 2, 0xFF])),
            ("uint16", .uint16(65_535)),
            ("uint32", .uint32(4_294_967_295)),
            ("int32", .int32(-268_435_456)),
            ("uint64", .uint64(1 << 60)),
            ("uint128", .uint128(high: 1, low: 2)),
            ("array", .array([.uint32(1), .string("Zürich, 東京"), .boolean(true)])),
            ("true", .boolean(true)),
            ("false", .boolean(false)),
            ("long", .string(String(repeating: "x", count: 70_000))),
            ("map", .map([("nested", .map([("deeper", .string("utf8_string"))]))])),
        ])
        var writer = MMDBTestWriter(ipVersion: 6, recordSize: 32)
        writer.deduplicatesStrings = deduplicates
        writer.insert("2001:db8::/48", record)
        let database = try MaxMindDatabase(bytes: writer.build())
        let found = try #require(try database.lookup(address("2001:db8::5")))
        #expect(found.value == record.decoded)
    }

    @Test("Hostile files are refused or fail a lookup, never crash or run unbounded")
    func hostileFiles() throws {
        let valid = GeoIPFixtures.city()
        #expect(throws: MaxMindDatabaseError.noMetadata) { try MaxMindDatabase(bytes: []) }
        let noise = [UInt8](repeating: 0xAB, count: 4_096)
        #expect(throws: MaxMindDatabaseError.noMetadata) { try MaxMindDatabase(bytes: noise) }
        // Cut before the metadata marker ends.
        #expect(throws: (any Error).self) { try MaxMindDatabase(bytes: Array(valid.prefix(valid.count - 60))) }

        for (key, value) in [
            ("record_size", MMDBTestValue.uint16(20)),
            ("ip_version", .uint16(5)),
            ("node_count", .uint32(10_000_000)),
            ("node_count", .string("12")),
            ("database_type", .uint16(1)),
        ] {
            var writer = MMDBTestWriter()
            writer.insert("203.0.113.0/24", .string("x"))
            writer.metadataOverrides = [(key, value)]
            #expect(throws: (any Error).self, "\(key)") { try MaxMindDatabase(bytes: writer.build()) }
        }
        var future = MMDBTestWriter()
        future.insert("203.0.113.0/24", .string("x"))
        future.metadataOverrides = [("binary_format_major_version", .uint16(3))]
        #expect(throws: MaxMindDatabaseError.unsupportedFormat(major: 3)) { try MaxMindDatabase(bytes: future.build()) }

        try expectLookupFailure(.raw([0x5F, 0xFF, 0xFF, 0xFF, 0x7F]), MaxMindDatabaseError.corruptData) // huge string
        try expectLookupFailure(.raw([0x42, 0xC3, 0x28]), MaxMindDatabaseError.corruptData) // invalid UTF-8
        try expectLookupFailure(.raw([0x00, 0x09]), MaxMindDatabaseError.corruptData) // extended type 16
        try expectLookupFailure(.raw([0x00, 0x05]), MaxMindDatabaseError.corruptData) // data cache container
        try expectLookupFailure(.raw([0x02, 0x07]), MaxMindDatabaseError.corruptData) // boolean of size 2
        try expectLookupFailure(.raw([0x61, 0x00, 0x00]), MaxMindDatabaseError.corruptData) // double of size 1
        try expectLookupFailure(.raw([0xFF, 0xFF, 0xFF, 0xFF]), MaxMindDatabaseError.corruptData) // map of 65k+ entries
        try expectLookupFailure(.pointer(1_000_000), MaxMindDatabaseError.corruptData) // outside the section
        try expectLookupFailure(.raw([0x20, 0x00]), MaxMindDatabaseError.corruptData) // pointer to itself
        let deep = (0 ..< 40).reduce(MMDBTestValue.boolean(true)) { inner, _ in .array([inner]) }
        try expectLookupFailure(deep, MaxMindDatabaseError.tooDeep)
        let wide = MMDBTestValue.array(Array(repeating: .boolean(true), count: 25_000))
        try expectLookupFailure(wide, MaxMindDatabaseError.tooManyValues)
    }

    @Test("A pointer bomb spends the value budget instead of memory")
    func pointerBomb() throws {
        // A 200-entry map, then a map whose 200 values all point at it: 40,000 values.
        let inner = MMDBTestValue.map((0 ..< 200).map { ("k\($0)", .boolean(true)) })
        let bomb = MMDBTestValue.map((0 ..< 200).map { ("v\($0)", .pointer(0)) })
        var writer = MMDBTestWriter()
        writer.deduplicatesStrings = false
        writer.insert("198.51.100.0/24", inner) // data offset 0
        writer.insert("203.0.113.0/24", bomb)
        let database = try MaxMindDatabase(bytes: writer.build())
        #expect(throws: MaxMindDatabaseError.tooManyValues) { try database.lookup(address("203.0.113.1")) }
        #expect(try database.lookup(address("198.51.100.1")) != nil)
    }

    @Test("Random damage to a valid file never crashes the reader")
    func fuzz() throws {
        let valid = GeoIPFixtures.city()
        var generator = SplitMix(seed: 0x7E01B)
        let probes = try ["203.0.113.5", "198.51.100.9", "192.0.2.3", "2001:db8::1", "8.8.8.8"].map(address)
        for _ in 0 ..< 400 {
            var damaged = valid
            for _ in 0 ... Int(generator.next() % 8) {
                let index = Int(generator.next() % UInt64(damaged.count))
                damaged[index] = UInt8(truncatingIfNeeded: generator.next())
            }
            if generator.next() % 5 == 0 {
                damaged = Array(damaged.prefix(Int(generator.next() % UInt64(damaged.count))))
            }
            guard let database = try? MaxMindDatabase(bytes: damaged) else {
                continue
            }
            _ = database.networkCount()
            for probe in probes {
                _ = try? database.lookup(probe)
            }
        }
    }

    @Test("Files from an independent writer read exactly as Python's maxminddb reads them")
    func independentWriterOracle() throws {
        let city = try MaxMindDatabase(bytes: GeoIPFixtures.independentCity)
        let asn = try MaxMindDatabase(bytes: GeoIPFixtures.independentASN)
        #expect(city.metadata.databaseType == "QA-City")
        #expect(city.metadata.nodeCount == 194)
        #expect(city.metadata.recordSize == 24)
        #expect(city.metadata.buildEpoch == 1_790_187_610)
        #expect(city.metadata.languages == ["en", "de"])
        #expect(asn.metadata.nodeCount == 169)
        #expect(city.networkCount() == 5)
        #expect(asn.networkCount() == 4)

        // (address, prefix length, country code or AS number) from maxminddb 2.8.2's
        // get_with_prefix_len on the same bytes; nil where it finds no record.
        let cityOracle: [(String, Int, String?)] = [
            ("203.0.113.5", 24, "DE"), ("203.0.113.200", 24, "DE"), ("198.51.100.10", 24, "JP"),
            ("192.0.2.1", 25, "FR"), ("192.0.2.200", 25, nil), ("2001:db8::53", 32, "CA"),
            ("8.8.8.8", 7, nil), ("10.1.2.3", 8, "XX"),
        ]
        for (text, prefix, code) in cityOracle {
            let found = try #require(try city.search(address(text)), "\(text)")
            #expect(found.prefixLength == prefix, "\(text)")
            #expect(found.value?.value(at: ["country", "iso_code"])?.stringValue == code, "\(text)")
        }
        let asnOracle: [(String, Int, UInt64?)] = [
            ("203.0.113.5", 25, 64_500), ("203.0.113.200", 25, 64_501), ("198.51.100.10", 24, 64_502),
            ("192.0.2.1", 6, nil), ("2001:db8::53", 32, 64_503), ("8.8.8.8", 1, nil),
        ]
        for (text, prefix, number) in asnOracle {
            let found = try #require(try asn.search(address(text)), "\(text)")
            #expect(found.prefixLength == prefix, "\(text)")
            #expect(found.value?["autonomous_system_number"]?.unsignedValue == number, "\(text)")
        }

        let berlin = try #require(try city.lookup(address("203.0.113.5")))
        #expect(berlin.value == .map([
            "continent": .map(["code": .string("EU")]),
            "country": .map([
                "iso_code": .string("DE"),
                "names": .map(["en": .string("Germany"), "de": .string("Deutschland")]),
                "geoname_id": .unsigned(1_000),
            ]),
            "location": .map([
                "latitude": .double(1.5),
                "longitude": .double(-2.25),
                "accuracy_radius": .unsigned(50),
            ]),
            "city": .map(["names": .map(["en": .string("Berlin")])]),
        ]))
    }

    @Test("Only regular files are read")
    func regularFilesOnly() throws {
        #expect(throws: MaxMindDatabaseError.notARegularFile) {
            try MaxMindDatabase.read(contentsOf: URL(fileURLWithPath: "/dev/zero"))
        }
        #expect(throws: MaxMindDatabaseError.notARegularFile) {
            try MaxMindDatabase.read(contentsOf: FileManager.default.temporaryDirectory)
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("geoip-\(UUID().uuidString).mmdb")
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(GeoIPFixtures.asn()).write(to: url)
        let database = try MaxMindDatabase.read(contentsOf: url)
        #expect(database.metadata.databaseType == "Tracexy-Test-ASN")
    }

    // MARK: Private

    /// Deterministic generator for the damage test.
    private struct SplitMix {
        // MARK: Lifecycle

        init(seed: UInt64) {
            state = seed
        }

        // MARK: Internal

        var state: UInt64

        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var value = state
            value = (value ^ (value >> 30)) &* 0xBF58476D1CE4E5B9
            value = (value ^ (value >> 27)) &* 0x94D049BB133111EB
            return value ^ (value >> 31)
        }
    }

    /// A database whose only record is `value` fails its lookup with `error`.
    private func expectLookupFailure(_ value: MMDBTestValue, _ error: MaxMindDatabaseError) throws {
        var writer = MMDBTestWriter()
        writer.deduplicatesStrings = false
        writer.insert("203.0.113.0/24", value)
        let database = try MaxMindDatabase(bytes: writer.build())
        #expect(throws: error) { try database.lookup(address("203.0.113.9")) }
    }
}

// MARK: - GeoIPLookupTests

@Suite("GeoIP lookups")
struct GeoIPLookupTests {
    @Test("Private and special addresses are never looked up, whatever the database holds")
    func neverLooksUpPrivateAddresses() throws {
        let cases: [(String, GeoIPAddressScope)] = [
            ("10.1.2.3", .privateNetwork),
            ("172.16.0.1", .privateNetwork),
            ("172.31.255.255", .privateNetwork),
            ("192.168.1.1", .privateNetwork),
            ("127.0.0.1", .loopback),
            ("::1", .loopback),
            ("169.254.10.1", .linkLocal),
            ("fe80::1", .linkLocal),
            ("fd12:3456::1", .uniqueLocal),
            ("fc00::1", .uniqueLocal),
            ("100.64.0.1", .sharedAddressSpace),
            ("224.0.0.251", .multicast),
            ("ff02::fb", .multicast),
            ("0.0.0.0", .unspecified),
            ("::", .unspecified),
            ("255.255.255.255", .reserved),
            ("::ffff:10.0.0.1", .privateNetwork),
        ]
        for (text, scope) in cases {
            #expect(try GeoIPAddressScope.classify(address(text)) == scope, "\(text)")
        }
        for text in ["172.32.0.1", "8.8.8.8", "203.0.113.5", "2001:db8::1", "100.128.0.1", "::ffff:203.0.113.5"] {
            #expect(try GeoIPAddressScope.classify(address(text)) == nil, "\(text)")
        }

        let set = try GeoIPDatabaseSet(databases: [MaxMindDatabase(bytes: GeoIPFixtures.city())])
        // The city fixture holds a record for 10.0.0.0/8; it must never be read.
        #expect(set.answer(for: "10.9.8.7", language: "en") == .notLookedUp(.privateNetwork))
        #expect(set.answer(for: "::ffff:10.0.0.1", language: "en") == .notLookedUp(.privateNetwork))
        #expect(set.answer(for: "aa:bb:cc:dd:ee:ff", language: "en") == .notAnAddress)
        #expect(!GeoIPAddressScope.privateNetwork.explanation.contains("·"))
    }

    @Test("Several databases combine: city from one, AS from another, in the Project's order")
    func combinesDatabases() throws {
        let set = try GeoIPDatabaseSet(databases: [
            MaxMindDatabase(bytes: GeoIPFixtures.city()),
            MaxMindDatabase(bytes: GeoIPFixtures.asn()),
        ])
        guard case let .located(berlin) = set.answer(for: "203.0.113.200", language: "en") else {
            Issue.record("203.0.113.200 should be located")
            return
        }
        #expect(berlin.countryCode == "DE")
        #expect(berlin.country == "Germany")
        #expect(berlin.city == "Berlin")
        #expect(berlin.asNumber == 64_501)
        #expect(berlin.asNumberText == "AS64501")
        #expect(berlin.asOrganization == "Example Hosting AG")
        // The City network is /24, the ASN network /25: the answer holds for the /25.
        #expect(berlin.network == "203.0.113.128/25")

        guard case let .located(mapped) = set.answer(for: "::ffff:198.51.100.4", language: "en") else {
            Issue.record("An IPv4-mapped address is looked up as IPv4")
            return
        }
        #expect(mapped.city == "Tokyo")
        #expect(mapped.asNumber == 64_502)

        guard case let .located(german) = set.answer(for: "203.0.113.1", language: "de") else {
            Issue.record("203.0.113.1 should be located")
            return
        }
        #expect(german.country == "Deutschland")
        #expect(set.answer(for: "8.8.8.8", language: "en") == .notFound)

        #expect(GeoIPDatabaseSet.preferredLanguage(for: set.databases, preferred: ["de-DE", "en"]) == "de")
        #expect(GeoIPDatabaseSet.preferredLanguage(for: set.databases, preferred: ["vi-VN"]) == "en")
    }

    @Test("A network that overlaps a private range is written as the address itself")
    func publicNetworks() throws {
        #expect(try GeoIPNetwork.publicCIDR(address("203.0.113.77"), prefix: 24) == "203.0.113.0/24")
        #expect(try GeoIPNetwork.publicCIDR(address("203.0.113.77"), prefix: 32) == "203.0.113.77")
        #expect(try GeoIPNetwork.publicCIDR(address("9.1.2.3"), prefix: 4) == nil) // 0/4 holds 0/8 and 10/8
        #expect(try GeoIPNetwork.publicCIDR(address("2001:db8::5"), prefix: 32) == "2001:db8::/32")
        #expect(try GeoIPNetwork.publicCIDR(address("2001:db8::5"), prefix: 0) == nil)
        #expect(try GeoIPNetwork.publicCIDR(address("2001:db8::5"), prefix: 2) == nil) // ::/2 holds ::ffff:0:0/96
    }
}

// MARK: - GeoIPExpressionTests

@Suite("GeoIP Session Expression macros")
struct GeoIPExpressionTests {
    // MARK: Internal

    @Test("Each macro expands to the matching addresses and the result parses")
    func expansions() throws {
        let builtIns = try Self.builtIns()
        let parser = SessionQueryParser()
        let cases: [(String, [String], String)] = [
            ("geoip_country", ["DE"], "ip in {203.0.113.0/25}"),
            ("geoip_country", ["germany"], "ip in {203.0.113.0/25}"),
            ("geoip_country", ["\"Japan\""], "ip in {198.51.100.0/24}"),
            ("geoip_city", ["tokyo"], "ip in {198.51.100.0/24}"),
            ("geoip_asn", ["AS64503"], "ip in {2001:db8::/32}"),
            ("geoip_asn", ["64502"], "ip in {198.51.100.0/24}"),
            ("geoip_org", ["example"], "ip in {198.51.100.0/24, 2001:db8::/32, 203.0.113.0/25}"),
            ("geoip_country", ["XX"], GeoIPExpressionBuiltIns.matchesNothing),
            ("geoip_asn", ["not-a-number"], GeoIPExpressionBuiltIns.matchesNothing),
        ]
        for (name, values, expected) in cases {
            #expect(builtIns.expansion(of: name, values: values) == .text(expected), "\(name)(\(values))")
            if case let .text(text)? = builtIns.expansion(of: name, values: values) {
                #expect((try? parser.parse(text)) != nil, "\(text)")
            }
        }
        #expect(builtIns.expansion(of: "geoip_country", values: []) == .wrongValueCount(expected: 1))
        #expect(builtIns.expansion(of: "geoip_country", values: ["DE", "FR"]) == .wrongValueCount(expected: 1))
        #expect(builtIns.expansion(of: "web", values: []) == nil)
    }

    @Test("Many addresses are split into sets the parser accepts")
    func largeSets() throws {
        var entries: [GeoIPExpressionBuiltIns.Entry] = []
        for index in 1 ... 70 {
            var location = GeoIPLocation()
            location.countryCode = "DE"
            try entries.append(.init(address: address("203.0.113.\(index)"), location: location))
        }
        let text = GeoIPExpressionBuiltIns.expression(for: entries)
        #expect(text.components(separatedBy: "ip in {").count - 1 == 3)
        #expect((try? SessionQueryParser().parse(text)) != nil)
    }

    @Test("Macros expand in the Session Expression path; a user macro of the same name wins")
    func preprocessing() throws {
        let builtIns = try Self.builtIns()
        let result = ExpressionLibraryPreprocessing.preprocess(
            "$geoip_country(DE) and tcp", macros: [], builtIns: builtIns
        )
        #expect(result == .success("(ip in {203.0.113.0/25}) and tcp"))
        let quoted = ExpressionLibraryPreprocessing.preprocess(
            "${geoip_org:\"Example Networks, KK\"}", macros: [], builtIns: builtIns
        )
        #expect(quoted == .success(GeoIPExpressionBuiltIns.matchesNothing.wrapped))

        let own = ExpressionLibraryPreprocessing.preprocess(
            "$geoip_country", macros: [ExpressionMacro(name: "geoip_country", text: "udp")], builtIns: builtIns
        )
        #expect(own == .success("(udp)"))

        guard case let .failure(error) = ExpressionLibraryPreprocessing.preprocess(
            "tcp and $geoip_country(DE)", macros: [], builtIns: nil
        ), case let .expression(parse) = error.reason else {
            Issue.record("Without databases the macro is unknown")
            return
        }
        #expect(parse.reason == .unknownName("$geoip_country"))
        #expect(parse.position == 9)
    }

    @Test("Menu uses quote values that aren't plain")
    func menuUses() {
        #expect(GeoIPExpressionBuiltIns.use(.country, value: "DE") == "$geoip_country(DE)")
        #expect(GeoIPExpressionBuiltIns.use(.organization, value: "A, \"B\"") == "$geoip_org(\"A, \\\"B\\\"\")")
    }

    // MARK: Private

    private static func builtIns() throws -> GeoIPExpressionBuiltIns {
        let set = try GeoIPDatabaseSet(databases: [
            MaxMindDatabase(bytes: GeoIPFixtures.city()),
            MaxMindDatabase(bytes: GeoIPFixtures.asn()),
        ])
        let addresses = ["203.0.113.5", "203.0.113.6", "198.51.100.10", "2001:db8::53", "10.0.0.5", "8.8.8.8"]
        let entries = try addresses.compactMap { text -> GeoIPExpressionBuiltIns.Entry? in
            guard case let .located(location) = set.answer(for: text, language: "en") else {
                return nil
            }
            return try .init(address: address(text), location: location)
        }
        return GeoIPExpressionBuiltIns(entries: entries)
    }
}

private extension String {
    var wrapped: String {
        "(\(self))"
    }
}

// MARK: - GeoIPControllerTests

/// The controller over a real workspace: the Project's databases, the Endpoints and
/// Session Inspector seams, and `$geoip_…` through the public Session Expression
/// path.
@MainActor
@Suite("GeoIP controller", .serialized)
struct GeoIPControllerTests {
    // MARK: Internal

    @Test("The default policy adds one database; databases a Project already refers to beyond it are still read")
    func databaseLimitGovernsGrowthOnly() async throws {
        let isolation = ProjectIsolationEnvironment(name: "geoip-limit")
        defer { isolation.tearDown() }
        let coordinator = try await Self.openCapture(isolation, policy: DefaultAppPolicy())
        let files = try Self.writeDatabases(in: isolation)
        let (controller, _) = Self.controller(coordinator: coordinator, files: files)
        #expect(controller.databaseLimit == 1)

        controller.addDatabases()
        await Self.waitForDatabases(controller)
        #expect(controller.entries.count == 1)
        #expect(controller.addNotice != nil)
        #expect(!controller.canAddDatabases)

        // Two databases already stored are both read.
        let bookmarks = try files.map { try $0.bookmarkData() }
        coordinator.activeProjectDefaults.set(bookmarks, forKey: GeoIPController.bookmarksKey)
        controller.reloadAll()
        await Self.waitForDatabases(controller)
        #expect(controller.entries.count == 2)
        #expect(controller.isLocating)
        #expect(!controller.canAddDatabases)

        coordinator.applyPolicy(GeoTestPolicy())
        #expect(controller.databaseLimit == 4)
        #expect(controller.canAddDatabases)
    }

    @Test("A surface that asked before the locator was installed hears about it")
    func installationIsObserved() {
        let previous = AddressLocators.installed
        defer { AddressLocators.installed = previous }
        AddressLocators.installed = nil
        let controller = GeoIPController()
        var told = false
        withObservationTracking {
            _ = AddressLocators.installed
        } onChange: {
            told = true
        }
        AddressLocators.installed = controller
        #expect(told)
        #expect(AddressLocators.installed === controller)

        // Installing the same locator again is not a change.
        told = false
        withObservationTracking {
            _ = AddressLocators.installed
        } onChange: {
            told = true
        }
        AddressLocators.installed = controller
        #expect(!told)
    }

    @Test("The Project's databases locate addresses, fill the seams and filter sessions")
    func locatesAndFilters() async throws {
        let isolation = ProjectIsolationEnvironment(name: "geoip-locate")
        defer { isolation.tearDown() }
        let coordinator = try await Self.openCapture(isolation)
        let files = try Self.writeDatabases(in: isolation)
        let (controller, library) = Self.controller(coordinator: coordinator, files: files)
        #expect(!controller.isLocating)

        controller.addDatabases()
        await Self.waitForDatabases(controller)
        #expect(controller.entries.count == 2)
        let infos = controller.entries.compactMap { entry -> GeoIPDatabaseInfo? in
            if case let .ready(info) = entry.status {
                return info
            }
            return nil
        }
        #expect(infos.map(\.databaseType) == ["Tracexy-Test-City", "Tracexy-Test-ASN"])
        #expect(infos.map(\.networkCount) == [5, 4])
        #expect(infos.first?.buildDate == Date(timeIntervalSince1970: 1_788_000_000))
        #expect(controller.isLocating)
        #expect((coordinator.activeProjectDefaults.array(forKey: GeoIPController.bookmarksKey) as? [Data])?.count == 2)

        // Adding the same files again changes nothing and says so.
        controller.addDatabases()
        #expect(controller.entries.count == 2)
        #expect(controller.addNotice != nil)

        guard case let .located(berlin) = controller.answer(for: "203.0.113.5") else {
            Issue.record("203.0.113.5 should be located")
            return
        }
        #expect(berlin.city == "Berlin")
        #expect(berlin.asNumber == 64_500)
        #expect(controller.answer(for: "10.0.0.5") == .notLookedUp(.privateNetwork))
        #expect(controller.matches("203.0.113.5", filter: "berl"))
        #expect(controller.matches("203.0.113.5", filter: "AS64500"))
        #expect(!controller.matches("10.0.0.5", filter: "Private"))
        #expect(controller.columnTitle(.asOrganization) == "AS Organization")
        #expect(controller.menuItems(for: "203.0.113.5") == [
            AddressLocationMenuItem(title: "Show Sessions in Germany", expression: "$geoip_country(DE)"),
            AddressLocationMenuItem(title: "Show Sessions in AS64500", expression: "$geoip_asn(64500)"),
        ])

        // The Session Inspector's GeoIP layer.
        let session = try #require(coordinator.sessions.first { $0.destinationEndpointValue?.ip == "203.0.113.5" })
        let layer = try #require(controller.inspectorLayers(for: session).first)
        #expect(layer.title == "GeoIP")
        #expect(layer.children.map(\.title) == ["Source GeoIP", "Destination GeoIP"])
        #expect(layer.children.map(\.summary) == ["10.0.0.5", "203.0.113.5"])
        #expect(layer.children[0].fields.map(\.name) == ["Private"])
        #expect(layer.children[1].fields.map(\.value) == [
            "Germany (DE)", "Berlin", "AS64500", "Example Transit GmbH", "203.0.113.0/25",
        ])
        #expect(controller.inspectorLayers(for: session).first?.id == layer.id)
        for text in layer.children.flatMap(\.fields).map(\.value) {
            #expect(!text.contains("·"))
        }

        // $geoip_… through the Session Expression path.
        let workspace = coordinator.activeWorkspace
        coordinator.applySessionExpression("$geoip_country(DE)")
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.investigationQueryError == nil)
        #expect(workspace.acceptedInvestigationDraft?.expression == "$geoip_country(DE)")
        let german = Set(coordinator.sessions.filter {
            [$0.sourceEndpointValue?.ip, $0.destinationEndpointValue?.ip].contains("203.0.113.5")
        }.map(\.id))
        #expect(!german.isEmpty)
        #expect(workspace.investigationMatchedSessionIDs == german)

        coordinator.applySessionExpression("$geoip_asn(64502) or $geoip_country(XX)")
        await coordinator.waitForInvestigationQuery(in: workspace)
        let japanese = Set(coordinator.sessions.filter {
            [$0.sourceEndpointValue?.ip, $0.destinationEndpointValue?.ip].contains("198.51.100.10")
        }.map(\.id))
        #expect(!japanese.isEmpty)
        #expect(workspace.investigationMatchedSessionIDs == japanese)

        // Private addresses never match, even through a macro that names them.
        coordinator.applySessionExpression("$geoip_country(XX)")
        await coordinator.waitForInvestigationQuery(in: workspace)
        #expect(workspace.investigationQueryError == nil)
        #expect(workspace.investigationMatchedSessionIDs.isEmpty)

        // Removing the City database keeps the ASN answers only.
        let city = try #require(controller.entries.first?.id)
        controller.removeDatabase(city)
        #expect(controller.entries.count == 1)
        #expect((coordinator.activeProjectDefaults.array(forKey: GeoIPController.bookmarksKey) as? [Data])?.count == 1)
        guard case let .located(asnOnly) = controller.answer(for: "203.0.113.5") else {
            Issue.record("The ASN database still locates 203.0.113.5")
            return
        }
        #expect(asnOnly.country == nil)
        #expect(asnOnly.asNumber == 64_500)
        _ = library
    }

    @Test("Databases belong to the Project they were added in")
    func projectIsolation() async throws {
        let isolation = ProjectIsolationEnvironment(name: "geoip-projects")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator(policy: GeoTestPolicy())
        await coordinator.hydrateProjectsOnLaunch()
        let files = try Self.writeDatabases(in: isolation)
        let (controller, _) = Self.controller(coordinator: coordinator, files: files)
        let first = coordinator.projectStore.activeProjectID
        controller.addDatabases()
        await Self.waitForDatabases(controller)
        #expect(controller.isLocating)

        _ = coordinator.createProject(named: "Second")
        #expect(await coordinator.waitForProjectTransition())
        controller.syncProject()
        #expect(controller.entries.isEmpty)
        #expect(!controller.isLocating)
        #expect(controller.answer(for: "203.0.113.5") == .notFound)

        #expect(coordinator.switchToProject(id: first))
        #expect(await coordinator.waitForProjectTransition())
        controller.syncProject()
        await Self.waitForDatabases(controller)
        #expect(controller.entries.count == 2)
        #expect(controller.isLocating)
    }

    @Test("A file that isn't a database is listed with a plain reason")
    func unreadableFile() async throws {
        let isolation = ProjectIsolationEnvironment(name: "geoip-unreadable")
        defer { isolation.tearDown() }
        let coordinator = isolation.makeCoordinator(policy: GeoTestPolicy())
        await coordinator.hydrateProjectsOnLaunch()
        let url = isolation.root.appendingPathComponent("notes.mmdb")
        try Data("not a database".utf8).write(to: url)
        let (controller, _) = Self.controller(coordinator: coordinator, files: [url])
        controller.addDatabases()
        await Self.waitForDatabases(controller)
        #expect(controller.entries.map(\.status) == [.unavailable("This isn’t a MaxMind database (.mmdb) file.")])
        #expect(!controller.isLocating)
    }

    // MARK: Private

    private static func controller(
        coordinator: MainContentCoordinator,
        files: [URL]
    )
        -> (GeoIPController, ExpressionLibraryController)
    {
        let controller = GeoIPController(
            environment: [GeoIPController.qaDatabasesEnvironmentKey: files.map(\.path).joined(separator: ":")]
        )
        controller.attach(coordinator, applicationDefaults: .standard)
        // The workspace's own library: the macros need only GeoIP.
        let library = coordinator.filterLibrary
        library.attach(to: coordinator)
        library.builtInSource = controller
        return (controller, library)
    }

    private static func writeDatabases(in isolation: ProjectIsolationEnvironment) throws -> [URL] {
        let city = isolation.root.appendingPathComponent("Test-City.mmdb")
        let asn = isolation.root.appendingPathComponent("Test-ASN.mmdb")
        try Data(GeoIPFixtures.city()).write(to: city)
        try Data(GeoIPFixtures.asn()).write(to: asn)
        return [city, asn]
    }

    private static func waitForDatabases(_ controller: GeoIPController) async {
        for _ in 0 ..< 1_000 where controller.entries.contains(where: { $0.status == .reading }) {
            try? await Task.sleep(for: .milliseconds(5))
        }
    }

    /// A capture with private, located and unknown addresses.
    private static func openCapture(
        _ isolation: ProjectIsolationEnvironment,
        policy: (any AppPolicy)? = nil
    )
        async throws -> MainContentCoordinator
    {
        let coordinator = isolation.makeCoordinator(policy: policy ?? GeoTestPolicy())
        await coordinator.hydrateProjectsOnLaunch()
        let directory = isolation.root.appendingPathComponent("Fixtures", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("geoip.pcap")
        let start = Date(timeIntervalSince1970: 1_790_000_000)
        let frames = [
            PacketBuilder.tcpSynFrame(src: "10.0.0.5", dst: "203.0.113.5", srcPort: 50_000, dstPort: 443),
            PacketBuilder.tcpSynFrame(src: "10.0.0.5", dst: "198.51.100.10", srcPort: 50_001, dstPort: 80),
            PacketBuilder.tcpSynFrame(src: "192.168.1.2", dst: "192.168.1.3", srcPort: 50_002, dstPort: 22),
            PacketBuilder.dnsQueryFrame(name: "example.test", src: "10.0.0.5", dst: "8.8.8.8", srcPort: 50_003),
        ].enumerated().map { index, bytes in
            CapturedFrame(bytes: bytes, timestamp: start.addingTimeInterval(Double(index)), originalLength: bytes.count)
        }
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames, to: url)
        let size = try #require(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize)
        coordinator.openSavedCapture(SavedCapture(url: url, name: "geoip", date: Date(), byteCount: size))
        await coordinator.waitForSavedCaptureOpen()
        return coordinator
    }
}

// MARK: - GeoTestPolicy

/// Room for the two test databases.
private struct GeoTestPolicy: AppPolicy {
    var maxGeoIPDatabases = 4
}
