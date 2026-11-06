import Darwin
import Foundation

// MARK: - HexDumpCaptureParser

/// A bounded hex dump parser. This is the byte-to-frame core of Import Hex Dump;
/// file selection and Project publication are separate. Offset mode selects an
/// explicit radix and starts each packet at zero. No-offset mode makes one frame
/// from byte rows. The exact 16-byte hex/ASCII layout produced by
/// `PacketBytesFormat` is accepted in offset mode, but its ASCII column must
/// match the bytes so it cannot hide omitted data.
nonisolated enum HexDumpCaptureParser {
    // MARK: Internal

    enum ParseError: LocalizedError, Equatable {
        case inputTooLarge
        case lineTooLong(line: Int)
        case invalidLine(line: Int)
        case offsetMismatch(line: Int, expected: Int, actual: Int)
        case frameTooLarge(line: Int)
        case noFrames
        case unsupportedLinkType
        case sourceNotRegular
        case sourceChanged
        case invalidTimestamp(line: Int)
        case missingTimestamp(line: Int)
        case duplicateTimestamp(line: Int)
        case timestampWithoutPacket(line: Int)
        case directionRequiresTimestamp
        case invalidRegex
        case regexDataGroupRequired
        case invalidRegexData(line: Int)
        case regexTimeLimit(line: Int)
        case invalidRegexSequenceNumber(line: Int)
        case invalidSyntheticIP(packet: Int)
        case invalidSyntheticUDPOptions
        case invalidSyntheticUDP(packet: Int)
        case invalidSyntheticTCPOptions
        case invalidSyntheticTCP(packet: Int)
        case invalidSyntheticSCTPOptions
        case invalidSyntheticSCTP(packet: Int)

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case .inputTooLarge: "The hex dump exceeds the 32 MiB input limit."
            case let .lineTooLong(line): "Line \(line) exceeds the 64 KiB limit."
            case let .invalidLine(line): "Line \(line) is not complete hex bytes in the selected offset format."
            case let .offsetMismatch(line, expected, actual):
                "Line \(line) starts at offset \(actual), but the next byte must be at \(expected)."
            case let .frameTooLarge(line): "The packet at line \(line) exceeds the 1 MiB frame limit."
            case .noFrames: "The text contains no complete packet bytes."
            case .unsupportedLinkType: "Choose a supported capture link type before importing the hex dump."
            case .sourceNotRegular: "Choose a regular text file containing a hex dump."
            case .sourceChanged: "The hex dump changed while it was being read. Import it again when it is complete."
            case let .invalidTimestamp(line): "Line \(line) is not a UTC ISO 8601 timestamp."
            case let .missingTimestamp(line): "The packet at line \(line) needs a preceding UTC timestamp."
            case let .duplicateTimestamp(line): "Line \(line) adds a second timestamp before any packet bytes."
            case let .timestampWithoutPacket(line): "Line \(line) has a timestamp without packet bytes."
            case .directionRequiresTimestamp: "Direction markers require real UTC timestamps; an untimed packet cannot store direction in a pcapng Simple Packet Block."
            case .invalidRegex: "Enter a valid regular expression of at most 512 characters; one-line mode requires ^ and $."
            case .regexDataGroupRequired: "The regular expression needs a named data group: (?<data>...)."
            case let .invalidRegexData(line): "Line \(line) contains incomplete or invalid packet data for the selected regex encoding."
            case let .regexTimeLimit(line): "The regular expression took too long near line \(line). Choose a simpler pattern."
            case let .invalidRegexSequenceNumber(line): "Line \(line) needs a positive decimal packet ID and a real UTC timestamp."
            case let .invalidSyntheticIP(packet): "Packet \(packet) is not one complete IPv4 or IPv6 packet for a synthetic Ethernet header."
            case .invalidSyntheticUDPOptions: "Choose valid source and destination IP addresses and UDP ports for the selected synthetic packet format."
            case let .invalidSyntheticUDP(packet): "Packet \(packet) could not be represented with the selected synthetic UDP headers."
            case .invalidSyntheticTCPOptions: "Choose valid source and destination IP addresses and TCP ports for the selected synthetic packet format."
            case let .invalidSyntheticTCP(packet): "Packet \(packet) could not be represented with the selected synthetic TCP headers."
            case .invalidSyntheticSCTPOptions: "Choose valid SCTP endpoints, ports, and chunk or DATA settings."
            case let .invalidSyntheticSCTP(packet): "Packet \(packet) is not complete SCTP chunks for the selected synthetic headers."
            }
        }
    }

    enum TimestampMode: Equatable, Sendable {
        case untimed
        case iso8601UTC
    }

    enum OffsetRadix: Int, Equatable, Sendable {
        case none = 0
        case hexadecimal = 16
        case decimal = 10
        case octal = 8
    }

    enum ByteGroupMode: Equatable, Sendable {
        case singleBytes
        case networkOrder
        case littleEndian
    }

    enum RegexDataEncoding: Int, Equatable, Sendable {
        case hexadecimal
        case octal
        case binary
        case base64
    }

    enum RegexPacketMode: Int, Equatable, Sendable {
        case onePerLine
        case acrossFile
    }

    static let maxInputBytes = 32 * 1_024 * 1_024
    static let maxLineBytes = 64 * 1_024
    static let maxFrameBytes = 1 * 1_024 * 1_024
    static let maxTotalFrameBytes = 16 * 1_024 * 1_024
    static let maxFrames = 100_000
    static let maxRegexMatchSeconds = 0.5
    static let maxRegexImportSeconds = 30.0

    /// Reads at most the input cap plus one byte through one descriptor. The
    /// descriptor identity is checked before and after parsing, so a changing
    /// source cannot be published from a partial or mixed snapshot.
    static func parse(
        contentsOf source: URL,
        linkType: UInt32,
        timestampMode: TimestampMode = .untimed,
        offsetRadix: OffsetRadix = .hexadecimal,
        byteGroupMode: ByteGroupMode = .singleBytes,
        directionIndicators: Bool = false,
        regexPattern: String? = nil,
        regexDataEncoding: RegexDataEncoding = .hexadecimal,
        regexPacketMode: RegexPacketMode = .onePerLine,
        syntheticEthernetForIP: Bool = false,
        syntheticUDP: SyntheticUDPPacketBuilder.Options? = nil,
        syntheticTCP: SyntheticTCPPacketBuilder.Options? = nil,
        syntheticSCTP: SyntheticSCTPPacketBuilder.Options? = nil
    )
        throws -> [CapturedFrame]
    {
        // A FIFO or device must not block before the regular-file check.
        let descriptor = source.path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC) }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(handle.fileDescriptor, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else
        {
            throw ParseError.sourceNotRegular
        }
        let flags = fcntl(descriptor, F_GETFL)
        if flags >= 0 {
            _ = fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK)
        }
        let identity = PcapFileIdentity.snapshot(of: handle)
        guard identity.size <= UInt64(maxInputBytes) else {
            throw ParseError.inputTooLarge
        }
        var input = Data()
        while input.count <= maxInputBytes {
            try Task.checkCancellation()
            guard let chunk = try handle.read(upToCount: min(65_536, maxInputBytes + 1 - input.count)),
                  !chunk.isEmpty else
            {
                break
            }
            input.append(chunk)
        }
        guard input.count <= maxInputBytes else {
            throw ParseError.inputTooLarge
        }
        guard PcapFileIdentity.snapshot(of: handle).matches(identity) else {
            throw ParseError.sourceChanged
        }
        let frames = try parse(
            input, linkType: linkType, timestampMode: timestampMode,
            offsetRadix: offsetRadix, byteGroupMode: byteGroupMode,
            directionIndicators: directionIndicators, regexPattern: regexPattern,
            regexDataEncoding: regexDataEncoding, regexPacketMode: regexPacketMode,
            syntheticEthernetForIP: syntheticEthernetForIP, syntheticUDP: syntheticUDP,
            syntheticTCP: syntheticTCP, syntheticSCTP: syntheticSCTP
        )
        guard PcapFileIdentity.snapshot(of: handle).matches(identity) else {
            throw ParseError.sourceChanged
        }
        var pathInfo = stat()
        guard source.path.withCString({ stat($0, &pathInfo) }) == 0,
              pathInfo.st_dev == info.st_dev,
              pathInfo.st_ino == info.st_ino,
              pathInfo.st_size == info.st_size,
              pathInfo.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              pathInfo.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec,
              pathInfo.st_ctimespec.tv_sec == info.st_ctimespec.tv_sec,
              pathInfo.st_ctimespec.tv_nsec == info.st_ctimespec.tv_nsec else
        {
            throw ParseError.sourceChanged
        }
        return frames
    }

    // Offset-mode parsing retains its packet-boundary state in one local scope.
    // swiftlint:disable:next function_body_length
    static func parse(
        _ input: Data,
        linkType: UInt32,
        timestampMode: TimestampMode = .untimed,
        offsetRadix: OffsetRadix = .hexadecimal,
        byteGroupMode: ByteGroupMode = .singleBytes,
        directionIndicators: Bool = false,
        regexPattern: String? = nil,
        regexDataEncoding: RegexDataEncoding = .hexadecimal,
        regexPacketMode: RegexPacketMode = .onePerLine,
        syntheticEthernetForIP: Bool = false,
        syntheticUDP: SyntheticUDPPacketBuilder.Options? = nil,
        syntheticTCP: SyntheticTCPPacketBuilder.Options? = nil,
        syntheticSCTP: SyntheticSCTPPacketBuilder.Options? = nil,
        isCancelled: () -> Bool = { Task.isCancelled },
        uptime: () -> Double = { ProcessInfo.processInfo.systemUptime }
    )
        throws -> [CapturedFrame]
    {
        if let regexPattern {
            let frames = try parseRegularText(
                input,
                linkType,
                regexPattern,
                regexDataEncoding,
                regexPacketMode,
                isCancelled,
                uptime
            )
            return try applySyntheticHeaders(
                frames, linkType: linkType, ethernetForIP: syntheticEthernetForIP,
                udp: syntheticUDP, tcp: syntheticTCP, sctp: syntheticSCTP
            )
        }
        try validateOptions(input, linkType, timestampMode, directionIndicators)

        var frames: [CapturedFrame] = []
        var current: [UInt8] = []
        var currentTimestamp: Date?
        var currentDirection: CaptureDirection = .unknown
        var pendingTimestamp: Date?
        var pendingDirection: CaptureDirection = .unknown
        var totalBytes = 0
        var start = input.startIndex
        var lineNumber = 0

        func finishCurrent() throws {
            guard !current.isEmpty else {
                return
            }
            guard frames.count < maxFrames else {
                throw ParseError.inputTooLarge
            }
            frames.append(CapturedFrame(
                bytes: current, timestamp: currentTimestamp, originalLength: current.count, linkType: linkType,
                direction: currentDirection
            ))
            current = []
            currentTimestamp = nil
            currentDirection = .unknown
        }

        func consume(_ line: Data.SubSequence) throws {
            let bytes = Array(line.last == 13 ? line.dropLast() : line)
            guard bytes.count <= maxLineBytes else {
                throw ParseError.lineTooLong(line: lineNumber)
            }
            guard let first = bytes.firstIndex(where: { $0 != 32 && $0 != 9 }) else {
                return
            }
            if bytes[first] == 35 {
                return
            } // A comment line.
            if timestampMode == .iso8601UTC,
               let (timestamp, markerDirection) = try Self.timestampPreamble(
                   bytes, first: first, directionIndicators: directionIndicators, line: lineNumber
               )
            {
                if offsetRadix == .none {
                    guard current.isEmpty else {
                        throw ParseError.invalidTimestamp(line: lineNumber)
                    }
                    guard pendingTimestamp == nil else {
                        throw ParseError.duplicateTimestamp(line: lineNumber)
                    }
                    pendingTimestamp = timestamp
                    pendingDirection = markerDirection
                    return
                }
                if current.isEmpty, pendingTimestamp != nil {
                    throw ParseError.duplicateTimestamp(line: lineNumber)
                }
                try finishCurrent()
                pendingTimestamp = timestamp
                pendingDirection = markerDirection
                return
            }
            if offsetRadix == .none {
                if current.isEmpty, timestampMode == .iso8601UTC {
                    guard let timestamp = pendingTimestamp else {
                        throw ParseError.missingTimestamp(line: lineNumber)
                    }
                    currentTimestamp = timestamp
                    currentDirection = pendingDirection
                    pendingTimestamp = nil
                    pendingDirection = .unknown
                }
                let appended = try Self.decodeHexTokens(
                    Array(bytes[first...]), line: lineNumber, byteGroupMode: byteGroupMode
                )
                current.append(contentsOf: appended)
                guard current.count <= maxFrameBytes else {
                    throw ParseError.frameTooLarge(line: lineNumber)
                }
                guard appended.count <= maxTotalFrameBytes,
                      totalBytes <= maxTotalFrameBytes - appended.count else
                {
                    throw ParseError.inputTooLarge
                }
                totalBytes += appended.count
                return
            }
            var index = first
            while index < bytes.count, bytes[index] != 32, bytes[index] != 9 {
                index += 1
            }
            let token = Array(bytes[first ..< index])
            let digits = token.last == 58 ? token.dropLast() : token[...]
            guard (3 ... 8).contains(digits.count),
                  let offset = Int(String(bytes: digits, encoding: .ascii) ?? "", radix: offsetRadix.rawValue) else
            {
                throw ParseError.invalidLine(line: lineNumber)
            }
            while index < bytes.count, bytes[index] == 32 || bytes[index] == 9 {
                index += 1
            }
            if offset == 0 {
                try finishCurrent()
                if timestampMode == .iso8601UTC {
                    guard let timestamp = pendingTimestamp else {
                        throw ParseError.missingTimestamp(line: lineNumber)
                    }
                    currentTimestamp = timestamp
                    currentDirection = pendingDirection
                    pendingTimestamp = nil
                    pendingDirection = .unknown
                }
            } else if current.isEmpty || offset != current.count {
                throw ParseError.offsetMismatch(line: lineNumber, expected: current.count, actual: offset)
            }
            // A trailing offset-only line is a conventional end marker.
            if index == bytes.count {
                guard offset > 0 else {
                    throw ParseError.invalidLine(line: lineNumber)
                }
                return
            }
            let appended = try decodeColumns(
                Array(bytes[index...]), line: lineNumber, byteGroupMode: byteGroupMode
            )
            current.append(contentsOf: appended)
            guard current.count <= maxFrameBytes else {
                throw ParseError.frameTooLarge(line: lineNumber)
            }
            guard appended.count <= maxTotalFrameBytes,
                  totalBytes <= maxTotalFrameBytes - appended.count else
            {
                throw ParseError.inputTooLarge
            }
            totalBytes += appended.count
        }

        for index in input.indices where input[index] == 10 {
            if isCancelled() {
                throw CancellationError()
            }
            lineNumber += 1
            try consume(input[start ..< index])
            start = input.index(after: index)
        }
        if start < input.endIndex {
            if isCancelled() {
                throw CancellationError()
            }
            lineNumber += 1
            try consume(input[start ..< input.endIndex])
        }
        try finishCurrent()
        if timestampMode == .iso8601UTC, pendingTimestamp != nil {
            throw ParseError.timestampWithoutPacket(line: lineNumber)
        }
        guard !frames.isEmpty else {
            throw ParseError.noFrames
        }
        return try applySyntheticHeaders(
            frames, linkType: linkType, ethernetForIP: syntheticEthernetForIP,
            udp: syntheticUDP, tcp: syntheticTCP, sctp: syntheticSCTP
        )
    }

    // MARK: Private

    private static func applySyntheticHeaders(
        _ frames: [CapturedFrame], linkType: UInt32, ethernetForIP: Bool,
        udp: SyntheticUDPPacketBuilder.Options?, tcp: SyntheticTCPPacketBuilder.Options?,
        sctp: SyntheticSCTPPacketBuilder.Options?
    )
        throws -> [CapturedFrame]
    {
        let selectedModes = (ethernetForIP ? 1 : 0) + (udp == nil ? 0 : 1)
            + (tcp == nil ? 0 : 1) + (sctp == nil ? 0 : 1)
        guard selectedModes <= 1 else {
            throw ParseError.invalidSyntheticTCPOptions
        }
        if let udp {
            return try SyntheticUDPPacketBuilder.wrap(
                frames, options: udp, linkType: linkType,
                maxFrameBytes: maxFrameBytes, maxTotalFrameBytes: maxTotalFrameBytes
            )
        }
        if let tcp {
            return try SyntheticTCPPacketBuilder.wrap(
                frames, options: tcp, linkType: linkType,
                maxFrameBytes: maxFrameBytes, maxTotalFrameBytes: maxTotalFrameBytes
            )
        }
        if let sctp {
            return try SyntheticSCTPPacketBuilder.wrap(
                frames, options: sctp, linkType: linkType,
                maxFrameBytes: maxFrameBytes, maxTotalFrameBytes: maxTotalFrameBytes
            )
        }
        return try addSyntheticEthernetIfRequested(frames, enabled: ethernetForIP, linkType: linkType)
    }

    private static func addSyntheticEthernetIfRequested(
        _ frames: [CapturedFrame], enabled: Bool, linkType: UInt32
    )
        throws -> [CapturedFrame]
    {
        guard enabled else {
            return frames
        }
        guard linkType == LinkType.ethernet else {
            throw ParseError.unsupportedLinkType
        }
        var totalBytes = 0
        return try frames.enumerated().map { index, frame in
            let bytes = frame.bytes
            let etherType: UInt16
            if bytes.count >= 20, bytes[0] >> 4 == 4 {
                let headerLength = Int(bytes[0] & 0x0F) * 4
                let packetLength = Int(bytes[2]) << 8 | Int(bytes[3])
                guard headerLength >= 20, headerLength <= bytes.count,
                      packetLength == bytes.count else
                {
                    throw ParseError.invalidSyntheticIP(packet: index + 1)
                }
                etherType = 0x0800
            } else if bytes.count >= 40, bytes[0] >> 4 == 6 {
                let payloadLength = Int(bytes[4]) << 8 | Int(bytes[5])
                guard payloadLength == bytes.count - 40 else {
                    throw ParseError.invalidSyntheticIP(packet: index + 1)
                }
                etherType = 0x86DD
            } else {
                throw ParseError.invalidSyntheticIP(packet: index + 1)
            }
            guard bytes.count <= maxFrameBytes - 14,
                  totalBytes <= maxTotalFrameBytes - bytes.count - 14 else
            {
                throw ParseError.inputTooLarge
            }
            totalBytes += bytes.count + 14
            // Locally administered MAC addresses make the generated layer visible
            // as synthetic while leaving every original IP byte unchanged.
            let header: [UInt8] = [
                2,
                0,
                0,
                0,
                0,
                1,
                2,
                0,
                0,
                0,
                0,
                2,
                UInt8(etherType >> 8),
                UInt8(etherType & 0xFF)
            ]
            return CapturedFrame(
                bytes: header + bytes, timestamp: frame.timestamp,
                originalLength: frame.originalLength + 14, linkType: linkType,
                direction: frame.direction, packetID: frame.packetID
            )
        }
    }

    private static func parseRegularText(
        _ input: Data, _ linkType: UInt32, _ pattern: String, _ encoding: RegexDataEncoding,
        _ mode: RegexPacketMode, _ isCancelled: () -> Bool, _ uptime: () -> Double
    )
        throws -> [CapturedFrame]
    {
        try validateOptions(input, linkType, .untimed, false)
        guard !pattern.isEmpty, pattern.count <= 512,
              mode == .acrossFile || (pattern.hasPrefix("^") && pattern.hasSuffix("$")) else
        {
            throw ParseError.invalidRegex
        }
        guard pattern.contains("(?<data>") else {
            throw ParseError.regexDataGroupRequired
        }
        let expression: NSRegularExpression
        do {
            expression = try NSRegularExpression(
                pattern: pattern,
                options: mode == .acrossFile ? .anchorsMatchLines : []
            )
        } catch {
            throw ParseError.invalidRegex
        }
        var frames: [CapturedFrame] = []
        var totalBytes = 0
        var lineNumber = 0
        var start = input.startIndex
        let importStarted = uptime()

        func appendMatch(_ match: NSTextCheckingResult, in text: String, line: Int) throws {
            let frame = try regexFrame(match, in: text, line: line, encoding: encoding, linkType: linkType)
            guard frames.count < maxFrames, totalBytes <= maxTotalFrameBytes - frame.bytes.count else {
                throw ParseError.inputTooLarge
            }
            totalBytes += frame.bytes.count
            frames.append(frame)
        }

        if mode == .acrossFile {
            guard let text = String(data: input, encoding: .utf8) else {
                throw ParseError.invalidLine(line: 1)
            }
            let full = NSRange(text.startIndex ..< text.endIndex, in: text)
            var cursor = text.startIndex
            var currentLine = 1
            var matchStarted = uptime()
            var failure: Error?
            expression.enumerateMatches(in: text, options: [.reportProgress], range: full) { result, _, stop in
                if isCancelled() {
                    failure = CancellationError()
                    stop.pointee = true
                } else if uptime() - matchStarted > maxRegexMatchSeconds ||
                    uptime() - importStarted > maxRegexImportSeconds
                {
                    failure = ParseError.regexTimeLimit(line: currentLine)
                    stop.pointee = true
                } else if let result {
                    do {
                        guard let range = Range(result.range, in: text), !range.isEmpty else {
                            throw ParseError.invalidLine(line: currentLine)
                        }
                        let gap = text[cursor ..< range.lowerBound]
                        if let invalidLine = regexFirstUnmatchedLine(gap, startingAt: currentLine) {
                            throw ParseError.invalidLine(line: invalidLine)
                        }
                        currentLine += gap.utf8.filter { $0 == 10 }.count
                        let lineStart = text[..<range.lowerBound].lastIndex(of: "\n")
                            .map { text.index(after: $0) } ?? text.startIndex
                        guard text[lineStart ..< range.lowerBound]
                            .trimmingCharacters(in: .whitespaces).isEmpty else
                        {
                            throw ParseError.invalidLine(line: currentLine)
                        }
                        try appendMatch(result, in: text, line: currentLine)
                        currentLine += text[range].utf8.filter { $0 == 10 }.count
                        cursor = range.upperBound
                        matchStarted = uptime()
                    } catch {
                        failure = error
                        stop.pointee = true
                    }
                }
            }
            if let failure {
                throw failure
            }
            if let invalidLine = regexFirstUnmatchedLine(text[cursor...], startingAt: currentLine) {
                throw ParseError.invalidLine(line: invalidLine)
            }
            guard !frames.isEmpty else {
                throw ParseError.noFrames
            }
            return frames
        }

        func consume(_ slice: Data.SubSequence) throws {
            let raw = slice.last == 13 ? slice.dropLast() : slice[...]
            guard raw.count <= maxLineBytes else {
                throw ParseError.lineTooLong(line: lineNumber)
            }
            guard !raw.isEmpty else {
                return
            }
            guard let line = String(data: Data(raw), encoding: .utf8) else {
                throw ParseError.invalidLine(line: lineNumber)
            }
            if line.trimmingCharacters(in: .whitespaces).isEmpty ||
                line.trimmingCharacters(in: .whitespaces).hasPrefix("#")
            {
                return
            }
            // The whole line must describe one packet. Never silently skip a
            // non-comment log line that the chosen pattern failed to capture.
            let full = NSRange(line.startIndex ..< line.endIndex, in: line)
            let matchStarted = uptime()
            var match: NSTextCheckingResult?
            var wasCancelled = false
            var timedOut = false
            // Foundation's progress callback can interrupt expensive backtracking.
            // A deadline is checked both between lines and during each match.
            expression.enumerateMatches(
                in: line, options: [.anchored, .reportProgress], range: full
            ) { result, _, stop in
                if isCancelled() {
                    wasCancelled = true
                    stop.pointee = true
                } else if uptime() - matchStarted > maxRegexMatchSeconds ||
                    uptime() - importStarted > maxRegexImportSeconds
                {
                    timedOut = true
                    stop.pointee = true
                } else if let result {
                    match = result
                    stop.pointee = true
                }
            }
            if wasCancelled {
                throw CancellationError()
            }
            if timedOut {
                throw ParseError.regexTimeLimit(line: lineNumber)
            }
            guard let match, match.range == full else {
                throw ParseError.invalidLine(line: lineNumber)
            }
            try appendMatch(match, in: line, line: lineNumber)
        }

        for index in input.indices where input[index] == 10 {
            if isCancelled() {
                throw CancellationError()
            }
            lineNumber += 1
            if uptime() - importStarted > maxRegexImportSeconds {
                throw ParseError.regexTimeLimit(line: lineNumber)
            }
            try consume(input[start ..< index])
            start = input.index(after: index)
        }
        if start < input.endIndex {
            if isCancelled() {
                throw CancellationError()
            }
            lineNumber += 1
            if uptime() - importStarted > maxRegexImportSeconds {
                throw ParseError.regexTimeLimit(line: lineNumber)
            }
            try consume(input[start ..< input.endIndex])
        }
        guard !frames.isEmpty else {
            throw ParseError.noFrames
        }
        return frames
    }

    private static func regexFirstUnmatchedLine(_ gap: Substring, startingAt firstLine: Int) -> Int? {
        var lineNumber = firstLine
        for line in gap.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty, !trimmed.hasPrefix("#") {
                return lineNumber
            }
            lineNumber += 1
        }
        return nil
    }

    private static func regexFrame(
        _ match: NSTextCheckingResult, in text: String, line: Int,
        encoding: RegexDataEncoding, linkType: UInt32
    )
        throws -> CapturedFrame
    {
        guard let dataRange = Range(match.range(withName: "data"), in: text) else {
            throw ParseError.invalidLine(line: line)
        }
        let bytes = try decodeRegexData(text[dataRange], encoding: encoding, line: line)
        guard bytes.count <= maxFrameBytes else {
            throw ParseError.frameTooLarge(line: line)
        }
        let timestamp: Date?
        if let timeRange = Range(match.range(withName: "time"), in: text) {
            guard let parsed = parseUTCTimestamp(Array(text[timeRange].utf8)) else {
                throw ParseError.invalidTimestamp(line: line)
            }
            timestamp = parsed
        } else {
            timestamp = nil
        }
        var direction: CaptureDirection = .unknown
        if let dirRange = Range(match.range(withName: "dir"), in: text),
           let marker = text[dirRange].utf8.first
        {
            switch marker {
            case 73,
                 105,
                 60: direction = .inbound
            case 79,
                 111,
                 62: direction = .outbound
            default: break
            }
        }
        guard direction == .unknown || timestamp != nil else {
            throw ParseError.directionRequiresTimestamp
        }
        var packetID: UInt64?
        if let sequenceRange = Range(match.range(withName: "seqno"), in: text) {
            let sequence = text[sequenceRange]
            guard timestamp != nil, !sequence.isEmpty,
                  sequence.utf8.allSatisfy({ (48 ... 57).contains($0) }),
                  let value = UInt64(sequence), value > 0 else
            {
                throw ParseError.invalidRegexSequenceNumber(line: line)
            }
            packetID = value
        }
        return CapturedFrame(
            bytes: bytes, timestamp: timestamp, originalLength: bytes.count,
            linkType: linkType, direction: direction, packetID: packetID
        )
    }

    private static func decodeRegexData(
        _ data: Substring, encoding: RegexDataEncoding, line: Int
    )
        throws -> [UInt8]
    {
        let compact = data.utf8.filter { byte in
            ![9, 10, 11, 12, 13, 32].contains(byte) && !(encoding == .hexadecimal && byte == 58)
        }
        guard !compact.isEmpty else {
            throw ParseError.invalidRegexData(line: line)
        }
        var decoded: [UInt8] = []
        switch encoding {
        case .hexadecimal:
            guard compact.count.isMultiple(of: 2) else {
                throw ParseError.invalidRegexData(line: line)
            }
            for index in stride(from: 0, to: compact.count, by: 2) {
                guard let high = hex(compact[index]), let low = hex(compact[index + 1]) else {
                    throw ParseError.invalidRegexData(line: line)
                }
                decoded.append(high << 4 | low)
            }
        case .octal:
            guard compact.count.isMultiple(of: 3) else {
                throw ParseError.invalidRegexData(line: line)
            }
            for index in stride(from: 0, to: compact.count, by: 3) {
                let digits = compact[index ..< index + 3]
                guard digits.allSatisfy({ (48 ... 55).contains($0) }) else {
                    throw ParseError.invalidRegexData(line: line)
                }
                let value = Int(compact[index] - 48) * 64
                    + Int(compact[index + 1] - 48) * 8 + Int(compact[index + 2] - 48)
                guard value <= 255 else {
                    throw ParseError.invalidRegexData(line: line)
                }
                decoded.append(UInt8(value))
            }
        case .binary:
            guard compact.count.isMultiple(of: 8), compact.allSatisfy({ $0 == 48 || $0 == 49 }) else {
                throw ParseError.invalidRegexData(line: line)
            }
            for index in stride(from: 0, to: compact.count, by: 8) {
                var value: UInt8 = 0
                for bit in compact[index ..< index + 8] {
                    value = (value << 1) | (bit - 48)
                }
                decoded.append(value)
            }
        case .base64:
            guard compact.count.isMultiple(of: 4),
                  compact.allSatisfy({ (65 ... 90).contains($0) || (97 ... 122).contains($0)
                          || (48 ... 57).contains($0) || $0 == 43 || $0 == 47 || $0 == 61 }),
                  let bytes = Data(base64Encoded: Data(compact)),
                  !bytes.isEmpty,
                  bytes.base64EncodedString() == String(bytes: compact, encoding: .ascii) else
            {
                throw ParseError.invalidRegexData(line: line)
            }
            decoded = Array(bytes)
        }
        return decoded
    }

    private static func validateOptions(
        _ input: Data, _ linkType: UInt32, _ timestampMode: TimestampMode, _ directionIndicators: Bool
    )
        throws
    {
        guard input.count <= maxInputBytes else {
            throw ParseError.inputTooLarge
        }
        guard !directionIndicators || timestampMode == .iso8601UTC else {
            throw ParseError.directionRequiresTimestamp
        }
        guard [LinkType.ethernet, LinkType.raw, LinkType.linuxSLL, LinkType.linuxSLL2].contains(linkType) else {
            throw ParseError.unsupportedLinkType
        }
    }

    private static func timestampPreamble(
        _ bytes: [UInt8], first: Int, directionIndicators: Bool, line: Int
    )
        throws -> (Date, CaptureDirection)?
    {
        var start = first
        var direction: CaptureDirection = .unknown
        if directionIndicators, [73, 105, 79, 111].contains(bytes[start]) {
            direction = bytes[start] == 73 || bytes[start] == 105 ? .inbound : .outbound
            start += 1
            guard start < bytes.count, bytes[start] == 32 || bytes[start] == 9 else {
                throw ParseError.invalidTimestamp(line: line)
            }
            while start < bytes.count, bytes[start] == 32 || bytes[start] == 9 {
                start += 1
            }
            guard start < bytes.count else {
                throw ParseError.invalidTimestamp(line: line)
            }
        }
        guard bytes[start] >= 48, bytes[start] <= 57,
              bytes.count - start >= 5, bytes[start + 4] == 45 else
        {
            if direction != .unknown {
                throw ParseError.invalidTimestamp(line: line)
            }
            return nil
        }
        guard let timestamp = parseUTCTimestamp(Array(bytes[start...])) else {
            throw ParseError.invalidTimestamp(line: line)
        }
        return (timestamp, direction)
    }

    private static func parseUTCTimestamp(_ bytes: [UInt8]) -> Date? {
        guard (20 ... 27).contains(bytes.count),
              bytes[4] == 45, bytes[7] == 45, bytes[10] == 84,
              bytes[13] == 58, bytes[16] == 58, bytes.last == 90 else
        {
            return nil
        }
        let hasFraction = bytes.count > 20
        if hasFraction {
            guard bytes[19] == 46, (1 ... 6).contains(bytes.count - 21) else {
                return nil
            }
        } else if bytes[19] != 90 {
            return nil
        }
        for index in bytes.indices where ![4, 7, 10, 13, 16, bytes.count - 1].contains(index)
            && (!hasFraction || index != 19)
        {
            guard (48 ... 57).contains(bytes[index]) else {
                return nil
            }
        }
        guard let text = String(bytes: bytes, encoding: .ascii) else {
            return nil
        }
        let formatter = ISO8601DateFormatter()
        formatter
            .formatOptions = hasFraction ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
        return formatter.date(from: text)
    }

    private static func decodeColumns(
        _ bytes: [UInt8], line: Int, byteGroupMode: ByteGroupMode
    )
        throws -> [UInt8]
    {
        // PacketBytesFormat pads the hex field to exactly 48 characters, then
        // writes two spaces and one ASCII character per captured byte. Requiring
        // the ASCII characters to agree with the bytes prevents an ambiguous
        // double space between hex groups from silently truncating a packet.
        if bytes.count >= 50, bytes[48] == 32, bytes[49] == 32,
           let decoded = try? decodeHexTokens(Array(bytes.prefix(48)), line: line, byteGroupMode: byteGroupMode),
           !decoded.isEmpty,
           bytes.count - 50 == decoded.count
        {
            guard Array(bytes.dropFirst(50)) == decoded.map({ $0 >= 0x20 && $0 < 0x7F ? $0 : 46 }) else {
                throw ParseError.invalidLine(line: line)
            }
            return decoded
        }
        return try decodeHexTokens(bytes, line: line, byteGroupMode: byteGroupMode)
    }

    private static func decodeHexTokens(
        _ bytes: [UInt8], line: Int, byteGroupMode: ByteGroupMode
    )
        throws -> [UInt8]
    {
        var decoded: [UInt8] = []
        var index = 0
        while index < bytes.count {
            while index < bytes.count, bytes[index] == 32 || bytes[index] == 9 {
                index += 1
            }
            if index == bytes.count {
                break
            }
            let start = index
            while index < bytes.count, bytes[index] != 32, bytes[index] != 9 {
                index += 1
            }
            let digitCount = index - start
            let acceptedLength = byteGroupMode == .singleBytes ? digitCount == 2 : (2 ... 8).contains(digitCount)
            guard digitCount.isMultiple(of: 2), acceptedLength else {
                throw ParseError.invalidLine(line: line)
            }
            var group: [UInt8] = []
            for byteStart in stride(from: start, to: index, by: 2) {
                guard let high = hex(bytes[byteStart]), let low = hex(bytes[byteStart + 1]) else {
                    throw ParseError.invalidLine(line: line)
                }
                group.append(high << 4 | low)
            }
            if byteGroupMode == .littleEndian {
                decoded.append(contentsOf: group.reversed())
            } else {
                decoded.append(contentsOf: group)
            }
        }
        guard !decoded.isEmpty else {
            throw ParseError.invalidLine(line: line)
        }
        return decoded
    }

    private static func hex(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 48 ... 57: byte - 48
        case 65 ... 70: byte - 55
        case 97 ... 102: byte - 87
        default: nil
        }
    }
}
