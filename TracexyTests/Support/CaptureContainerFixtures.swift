import Foundation
@testable import Tracexy

// MARK: - CaptureContainerFixtures

/// Block-level pcapng builders for container-metadata tests: section/interface
/// options, statistics, name-resolution, decryption-secrets, custom and unknown
/// blocks, and packet comments. Extends ``PcapngFixture`` without changing its
/// existing signatures. Every builder is deterministic; nothing here reads a
/// committed capture file.
enum CaptureContainerFixtures {
    struct SectionOptions {
        var hardware: String?
        var operatingSystem: String?
        var application: String?
        var comments: [String] = []
        /// Raw extra option bytes appended verbatim (already framed).
        var rawOptions: [UInt8] = []
    }

    struct InterfaceOptions {
        var name: String?
        var description: String?
        var filter: (kind: UInt8, text: String)?
        var operatingSystem: String?
        var hardware: String?
        var tsresol: UInt8?
        var tsoffset: Int64?
        var fcsLength: UInt8?
        var speed: UInt64?
        var comments: [String] = []
        var rawOptions: [UInt8] = []
    }

    struct StatisticsOptions {
        var startTicks: UInt64?
        var endTicks: UInt64?
        var received: UInt64?
        var dropped: UInt64?
        var filterAccepted: UInt64?
        var osDropped: UInt64?
        var delivered: UInt64?
    }

    static func sectionHeader(little: Bool, options: SectionOptions) -> [UInt8] {
        var body = PcapngFixture.u32(0x1A2B3C4D, little)
        body += PcapngFixture.u16(1, little)
        body += PcapngFixture.u16(0, little)
        body += PcapngFixture.u64(.max, little)
        var opts: [UInt8] = []
        for comment in options.comments {
            opts += stringOption(code: 1, comment, little)
        }
        if let value = options.hardware {
            opts += stringOption(code: 2, value, little)
        }
        if let value = options.operatingSystem {
            opts += stringOption(code: 3, value, little)
        }
        if let value = options.application {
            opts += stringOption(code: 4, value, little)
        }
        opts += options.rawOptions
        if !opts.isEmpty {
            opts += PcapngFixture.option(code: 0, value: [], little: little)
        }
        return PcapngFixture.block(type: 0x0A0D0D0A, little: little, body: body + opts)
    }

    static func interfaceDescription(
        little: Bool,
        linkType: UInt16 = 1,
        snapLength: UInt32 = 262_144,
        options: InterfaceOptions
    )
        -> [UInt8]
    {
        var body = PcapngFixture.u16(linkType, little)
        body += PcapngFixture.u16(0, little)
        body += PcapngFixture.u32(snapLength, little)
        var opts: [UInt8] = []
        for comment in options.comments {
            opts += stringOption(code: 1, comment, little)
        }
        if let value = options.name {
            opts += stringOption(code: 2, value, little)
        }
        if let value = options.description {
            opts += stringOption(code: 3, value, little)
        }
        if let value = options.speed {
            opts += PcapngFixture.option(code: 8, value: PcapngFixture.u64(value, little), little: little)
        }
        if let value = options.tsresol {
            opts += PcapngFixture.option(code: 9, value: [value], little: little)
        }
        if let filter = options.filter {
            opts += PcapngFixture.option(code: 11, value: [filter.kind] + Array(filter.text.utf8), little: little)
        }
        if let value = options.operatingSystem {
            opts += stringOption(code: 12, value, little)
        }
        if let value = options.fcsLength {
            opts += PcapngFixture.option(code: 13, value: [value], little: little)
        }
        if let value = options.tsoffset {
            opts += PcapngFixture.option(
                code: 14, value: PcapngFixture.u64(UInt64(bitPattern: value), little), little: little
            )
        }
        if let value = options.hardware {
            opts += stringOption(code: 15, value, little)
        }
        opts += options.rawOptions
        if !opts.isEmpty {
            opts += PcapngFixture.option(code: 0, value: [], little: little)
        }
        return PcapngFixture.block(type: 0x00000001, little: little, body: body + opts)
    }

    static func interfaceStatistics(
        little: Bool,
        interfaceID: UInt32,
        ticks: UInt64 = 0,
        options: StatisticsOptions
    )
        -> [UInt8]
    {
        var body = PcapngFixture.u32(interfaceID, little)
        body += PcapngFixture.u32(UInt32(ticks >> 32), little)
        body += PcapngFixture.u32(UInt32(ticks & 0xFFFFFFFF), little)
        var opts: [UInt8] = []
        func counter(_ code: UInt16, _ value: UInt64?) {
            if let value {
                opts += PcapngFixture.option(code: code, value: PcapngFixture.u64(value, little), little: little)
            }
        }
        counter(2, options.startTicks)
        counter(3, options.endTicks)
        counter(4, options.received)
        counter(5, options.dropped)
        counter(6, options.filterAccepted)
        counter(7, options.osDropped)
        counter(8, options.delivered)
        if !opts.isEmpty {
            opts += PcapngFixture.option(code: 0, value: [], little: little)
        }
        return PcapngFixture.block(type: 0x00000005, little: little, body: body + opts)
    }

    /// A Name Resolution Block with one IPv4 record and an end record.
    static func nameResolution(
        little: Bool,
        address: [UInt8] = [10, 0, 0, 1],
        name: String = "host.example"
    )
        -> [UInt8]
    {
        var body: [UInt8] = []
        body += PcapngFixture.u16(1, little) // nrb_record_ipv4
        let value = address + Array(name.utf8) + [0]
        body += PcapngFixture.u16(UInt16(value.count), little)
        body += value
        while body.count % 4 != 0 {
            body.append(0)
        }
        body += PcapngFixture.u16(0, little) // nrb_record_end
        body += PcapngFixture.u16(0, little)
        return PcapngFixture.block(type: 0x00000004, little: little, body: body)
    }

    static func decryptionSecrets(little: Bool, secretsType: UInt32, secrets: [UInt8]) -> [UInt8] {
        var body = PcapngFixture.u32(secretsType, little)
        body += PcapngFixture.u32(UInt32(secrets.count), little)
        body += secrets
        return PcapngFixture.block(type: 0x0000000A, little: little, body: body)
    }

    static func customBlock(little: Bool, copyable: Bool = true, payload: [UInt8] = [1, 2, 3, 4]) -> [UInt8] {
        let body = PcapngFixture.u32(0x00000001, little) + payload
        return PcapngFixture.block(type: copyable ? 0x00000BAD : 0x40000BAD, little: little, body: body)
    }

    static func unknownBlock(little: Bool, type: UInt32, payload: [UInt8] = [0, 0, 0, 0]) -> [UInt8] {
        PcapngFixture.block(type: type, little: little, body: payload)
    }

    static func enhancedPacket(
        little: Bool,
        interfaceID: UInt32 = 0,
        ticks: UInt64,
        captured: [UInt8],
        comments: [String]
    )
        -> [UInt8]
    {
        var opts: [UInt8] = []
        for comment in comments {
            opts += stringOption(code: 1, comment, little)
        }
        if !opts.isEmpty {
            opts += PcapngFixture.option(code: 0, value: [], little: little)
        }
        return PcapngFixture.enhancedPacket(
            little: little, interfaceID: interfaceID, ticks: ticks, captured: captured, trailingOptions: opts
        )
    }

    static func stringOption(code: UInt16, _ text: String, _ little: Bool) -> [UInt8] {
        PcapngFixture.option(code: code, value: Array(text.utf8), little: little)
    }

    /// A raw string option built from bytes (for invalid UTF-8 and over-cap cases).
    static func bytesOption(code: UInt16, _ bytes: [UInt8], _ little: Bool) -> [UInt8] {
        PcapngFixture.option(code: code, value: bytes, little: little)
    }

    /// The reference showcase used by the properties, oracle and export suites:
    /// two interfaces (Ethernet en0 with a filter, Raw IPv4 tunnel), section
    /// hardware/OS/application and a comment, the replay conversation on interface
    /// 0 with a comment on frame 2, one raw IPv4 frame on interface 1, statistics
    /// for both interfaces, a name-resolution block, a TLS key-log secrets block,
    /// a custom block, and one unknown block.
    static func showcasePcapng(little: Bool = true) -> [UInt8] {
        var file = sectionHeader(little: little, options: SectionOptions(
            hardware: "Mac16,10",
            operatingSystem: "macOS 26.5",
            application: "Tracexy fixture builder",
            comments: ["Section comment one"]
        ))
        file += interfaceDescription(little: little, linkType: UInt16(LinkType.ethernet), options: InterfaceOptions(
            name: "en0",
            description: "Wi-Fi",
            filter: (kind: 0, text: "tcp or udp"),
            operatingSystem: "macOS",
            tsresol: 6,
            comments: ["Interface comment"]
        ))
        file += interfaceDescription(little: little, linkType: UInt16(LinkType.raw), options: InterfaceOptions(
            name: "utun4",
            tsresol: 9
        ))
        var ordinal = 0
        for frame in ReplayCorpus.conversation() {
            ordinal += 1
            file += enhancedPacket(
                little: little,
                interfaceID: 0,
                ticks: ReplayCorpus.microTicks(frame),
                captured: frame.bytes,
                comments: ordinal == 2 ? ["Frame two comment"] : []
            )
        }
        for frame in ReplayCorpus.rawIPv4ConversationFrames().prefix(1) {
            file += PcapngFixture.enhancedPacket(
                little: little,
                interfaceID: 1,
                ticks: ReplayCorpus.microTicks(frame) * 1_000,
                captured: frame.bytes
            )
        }
        file += interfaceStatistics(little: little, interfaceID: 0, options: StatisticsOptions(
            startTicks: 1_700_000_000_000_000,
            endTicks: 1_700_000_100_000_000,
            received: 1_234,
            dropped: 5
        ))
        file += interfaceStatistics(little: little, interfaceID: 1, options: StatisticsOptions(received: 1, dropped: 0))
        file += nameResolution(little: little)
        file += decryptionSecrets(little: little, secretsType: 0x544C4B4C, secrets: Array("CLIENT_RANDOM 00 11\n".utf8))
        file += customBlock(little: little)
        file += unknownBlock(little: little, type: 0x000000F0)
        return file
    }
}

// MARK: - WiresharkOracle

/// Runs Wireshark's command-line tools when an installation is present, so
/// container facts can be checked against an independent implementation. Tests
/// that depend on it skip cleanly on machines without Wireshark; they never fail
/// for its absence.
enum WiresharkOracle {
    // MARK: Internal

    struct CapinfosReport {
        let fields: [String: String]

        subscript(_ key: String) -> String? {
            fields[key]
        }

        func int(_ key: String) -> Int? {
            fields[key].flatMap { Int($0.replacingOccurrences(of: " ", with: "").filter(\.isNumber)) }
        }
    }

    enum OracleError: Error {
        case unavailable
        case failed(status: Int32, output: String)
    }

    static var capinfosURL: URL? {
        let candidates = [
            "/Applications/Wireshark.app/Contents/MacOS/capinfos",
            "/opt/homebrew/bin/capinfos",
            "/usr/local/bin/capinfos",
        ]
        return candidates.map { URL(fileURLWithPath: $0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    static var tsharkURL: URL? {
        guard let capinfos = capinfosURL else {
            return nil
        }
        let tshark = capinfos.deletingLastPathComponent().appendingPathComponent("tshark")
        return FileManager.default.isExecutableFile(atPath: tshark.path) ? tshark : nil
    }

    static var isAvailable: Bool {
        capinfosURL != nil
    }

    /// `capinfos -A -m -T`-style machine output is awkward to parse; the default
    /// long form is stable "Key: value" lines, which is what this reads.
    static func capinfos(_ file: URL, extraArguments: [String] = []) throws -> CapinfosReport {
        guard let tool = capinfosURL else {
            throw OracleError.unavailable
        }
        let output = try run(tool, arguments: ["-A"] + extraArguments + [file.path])
        var fields: [String: String] = [:]
        var interfaceIndex = -1
        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("Interface #"), trimmed.hasSuffix("info:") {
                interfaceIndex += 1
                continue
            }
            // Interface detail lines are indented "Key = value"; top-level lines
            // are "Key: value".
            if interfaceIndex >= 0, line.hasPrefix(" "), let equals = trimmed.range(of: " = ") {
                let key = "if\(interfaceIndex)." + trimmed[..<equals.lowerBound].trimmingCharacters(in: .whitespaces)
                fields[key] = trimmed[equals.upperBound...].trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = trimmed.firstIndex(of: ":") else {
                continue
            }
            let key = trimmed[..<colon].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if fields[key] == nil {
                fields[key] = value
            }
        }
        return CapinfosReport(fields: fields)
    }

    static func tsharkFields(_ file: URL, fields: [String], filter: String? = nil) throws -> [[String]] {
        guard let tool = tsharkURL else {
            throw OracleError.unavailable
        }
        var arguments = ["-r", file.path, "-T", "fields", "-E", "separator=\t"]
        for field in fields {
            arguments += ["-e", field]
        }
        if let filter {
            arguments += ["-Y", filter]
        }
        let output = try run(tool, arguments: arguments)
        return output.split(separator: "\n", omittingEmptySubsequences: true).map { line in
            line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        }
    }

    // MARK: Private

    private static func run(_ tool: URL, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = tool
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(bytes: data, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw OracleError.failed(status: process.terminationStatus, output: output)
        }
        return output
    }
}
