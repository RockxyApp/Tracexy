import Foundation

// MARK: - FrameSearchQuery

/// Wireshark's Find Packet over the capture's own content: a string, hex bytes or a
/// regular expression, looked for in each frame's bytes or in its decoded details.
nonisolated struct FrameSearchQuery: Hashable, Sendable {
    // MARK: Internal

    enum Kind: String, CaseIterable, Hashable, Sendable {
        case string
        case hex
        case regex
    }

    enum Target: String, CaseIterable, Hashable, Sendable {
        case bytes
        case details
    }

    enum StringEncoding: String, CaseIterable, Hashable, Sendable {
        case utf8
        case utf16LittleEndian
        case utf16BigEndian
        case all

        // MARK: Internal

        var title: String {
            switch self {
            case .utf8: "UTF-8"
            case .utf16LittleEndian: "UTF-16 LE"
            case .utf16BigEndian: "UTF-16 BE"
            case .all: "All"
            }
        }
    }

    struct Invalid: Error, Equatable {
        let message: String
    }

    var kind: Kind
    var target: Target
    var text: String
    var caseSensitive = false
    var stringEncoding = StringEncoding.utf8

    /// "de ad be ef", "deadbeef" or "de:ad:be:ef" as bytes; `nil` for anything else.
    static func hexBytes(_ text: String) -> [UInt8]? {
        let digits = text.filter { !$0.isWhitespace && $0 != ":" && $0 != "-" }
        guard !digits.isEmpty, digits.count.isMultiple(of: 2), digits.allSatisfy(\.isHexDigit) else {
            return nil
        }
        var bytes: [UInt8] = []
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            guard let byte = UInt8(digits[index ..< next], radix: 16) else {
                return nil
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    /// Whether one frame matches, given its bytes and — for the details target — its
    /// decode tree as text.
    func matcher() throws -> (_ bytes: [UInt8], _ details: () -> String, _ isCancelled: () -> Bool) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw Invalid(message: String(localized: "Type what to find."))
        }
        switch (kind, target) {
        case (.hex, .details):
            throw Invalid(message: String(localized: "Hex bytes are found in a frame's bytes, not its details."))
        case (.hex, .bytes):
            guard let needle = Self.hexBytes(trimmed) else {
                throw Invalid(message: String(localized: "Type hex bytes, such as 16 03 01 or 160301."))
            }
            let compiled = Self.makeNeedle(needle.map(Int.init), encoding: .utf8)
            return { bytes, _, isCancelled in
                Self.containsBytes(bytes, needle: compiled, caseSensitive: true, isCancelled: isCancelled)
            }
        case (.string, .bytes):
            let needles = Self.needles(for: trimmed, encoding: stringEncoding, caseSensitive: caseSensitive)
            let respectsCase = caseSensitive
            return { bytes, _, isCancelled in
                needles.contains { needle in
                    switch needle.encoding {
                    case .utf8:
                        Self.containsBytes(
                            bytes, needle: needle, caseSensitive: respectsCase, isCancelled: isCancelled
                        )
                    case .littleEndian:
                        Self.containsUTF16(
                            bytes, needle: needle, caseSensitive: respectsCase,
                            order: .littleEndian, isCancelled: isCancelled
                        )
                    case .bigEndian:
                        Self.containsUTF16(
                            bytes, needle: needle, caseSensitive: respectsCase,
                            order: .bigEndian, isCancelled: isCancelled
                        )
                    }
                }
            }
        case (.string, .details):
            let sensitive = caseSensitive
            return { _, details, _ in
                details().range(of: trimmed, options: sensitive ? [] : [.caseInsensitive]) != nil
            }
        case (.regex, _):
            let expression: NSRegularExpression
            do {
                expression = try NSRegularExpression(
                    pattern: trimmed, options: caseSensitive ? [] : [.caseInsensitive]
                )
            } catch {
                throw Invalid(message: String(localized: "That regular expression is not valid."))
            }
            let target = target
            return { bytes, details, _ in
                // Bytes are read one character per byte, so a pattern can span any value.
                let text = target == .bytes ? String(bytes.map { Character(Unicode.Scalar($0)) }) : details()
                return expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
            }
        }
    }

    // MARK: Private

    private enum UTF16Order {
        case littleEndian
        case bigEndian
    }

    private enum NeedleEncoding {
        case utf8
        case littleEndian
        case bigEndian
    }

    private struct Needle {
        let encoding: NeedleEncoding
        let values: [Int]
        let prefix: [Int]
    }

    private static func needles(for text: String, encoding: StringEncoding, caseSensitive: Bool) -> [Needle] {
        let utf8 = makeNeedle(
            text.utf8.map { Int(compared($0, caseSensitive: caseSensitive)) }, encoding: .utf8
        )
        let units = text.utf16.map { compared($0, caseSensitive: caseSensitive) }
        let littleEndian = makeNeedle(units.map(Int.init), encoding: .littleEndian)
        let bigEndian = makeNeedle(units.map(Int.init), encoding: .bigEndian)
        return switch encoding {
        case .utf8: [utf8]
        case .utf16LittleEndian: [littleEndian]
        case .utf16BigEndian: [bigEndian]
        case .all: [utf8, littleEndian, bigEndian]
        }
    }

    private static func makeNeedle(_ values: [Int], encoding: NeedleEncoding) -> Needle {
        var prefix = [Int](repeating: 0, count: values.count)
        var matched = 0
        if values.count > 1 {
            for index in 1 ..< values.count {
                while matched > 0, values[index] != values[matched] {
                    matched = prefix[matched - 1]
                }
                if values[index] == values[matched] {
                    matched += 1
                }
                prefix[index] = matched
            }
        }
        return Needle(encoding: encoding, values: values, prefix: prefix)
    }

    private static func compared(_ byte: UInt8, caseSensitive: Bool) -> UInt8 {
        guard !caseSensitive, (0x41 ... 0x5A).contains(byte) else {
            return byte
        }
        return byte + 0x20
    }

    private static func compared(_ codeUnit: UInt16, caseSensitive: Bool) -> UInt16 {
        guard !caseSensitive, (0x0041 ... 0x005A).contains(codeUnit) else {
            return codeUnit
        }
        return codeUnit + 0x20
    }

    private static func containsBytes(
        _ bytes: [UInt8], needle: Needle, caseSensitive: Bool, isCancelled: () -> Bool
    )
        -> Bool
    {
        guard !needle.values.isEmpty, bytes.count >= needle.values.count else {
            return false
        }
        var matched = 0
        for (index, byte) in bytes.enumerated() {
            if index.isMultiple(of: 4_096), isCancelled() {
                return false
            }
            let value = Int(compared(byte, caseSensitive: caseSensitive))
            while matched > 0, value != needle.values[matched] {
                matched = needle.prefix[matched - 1]
            }
            if value == needle.values[matched] {
                matched += 1
                if matched == needle.values.count {
                    return true
                }
            }
        }
        return false
    }

    private static func containsUTF16(
        _ bytes: [UInt8],
        needle: Needle,
        caseSensitive: Bool,
        order: UTF16Order,
        isCancelled: () -> Bool
    )
        -> Bool
    {
        guard !needle.values.isEmpty, bytes.count / 2 >= needle.values.count else {
            return false
        }
        for parity in 0 ... 1 {
            guard bytes.count - parity >= needle.values.count * 2 else {
                continue
            }
            var matched = 0
            var offset = parity
            var scanned = 0
            while offset + 1 < bytes.count {
                if scanned.isMultiple(of: 4_096), isCancelled() {
                    return false
                }
                let unit = codeUnit(bytes, at: offset, order: order)
                let value = Int(compared(unit, caseSensitive: caseSensitive))
                while matched > 0, value != needle.values[matched] {
                    matched = needle.prefix[matched - 1]
                }
                if value == needle.values[matched] {
                    matched += 1
                    if matched == needle.values.count {
                        return true
                    }
                }
                offset += 2
                scanned += 1
            }
        }
        return false
    }

    private static func codeUnit(_ bytes: [UInt8], at index: Int, order: UTF16Order) -> UInt16 {
        switch order {
        case .littleEndian:
            UInt16(bytes[index]) | (UInt16(bytes[index + 1]) << 8)
        case .bigEndian:
            (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1])
        }
    }
}

// MARK: - FrameContentSearch

/// Reads a stable capture file once and returns the numbers of the frames whose
/// content matches a ``FrameSearchQuery``.
nonisolated enum FrameContentSearch {
    // MARK: Internal

    struct NavigationResult: Sendable, Equatable {
        let ordinal: UInt64?
        let matchCount: Int
        let completeness: CaptureLoadCompleteness
    }

    /// Find one adjacent match in capture order, wrapping at the source boundary.
    /// Only a count and three ordinals are retained, regardless of capture size.
    static func adjacentMatch(
        in url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        query: FrameSearchQuery,
        after current: UInt64?,
        forward: Bool,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> NavigationResult
    {
        var first: UInt64?
        var last: UInt64?
        var adjacent: UInt64?
        var count = 0
        let completeness = try walk(
            in: url, expectedIdentity: expectedIdentity, query: query, isCancelled: isCancelled
        ) { ordinal in
            count += 1
            if first == nil {
                first = ordinal
            }
            last = ordinal
            if let current {
                if forward, ordinal > current, adjacent == nil {
                    adjacent = ordinal
                } else if !forward, ordinal < current {
                    adjacent = ordinal
                }
            }
        }
        return NavigationResult(
            ordinal: adjacent ?? (forward ? first : last), matchCount: count, completeness: completeness
        )
    }

    static func matches(
        in url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        query: FrameSearchQuery,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> [UInt64]
    {
        var found: [UInt64] = []
        _ = try walk(in: url, expectedIdentity: expectedIdentity, query: query, isCancelled: isCancelled) {
            found.append($0)
        }
        return found
    }

    // MARK: Private

    private static func walk(
        in url: URL,
        expectedIdentity: PcapFileIdentity?,
        query: FrameSearchQuery,
        isCancelled: @escaping @Sendable () -> Bool,
        onMatch: (UInt64) -> Void
    )
        throws -> CaptureLoadCompleteness
    {
        let matcher = try query.matcher()
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(maxCapturedLength: CapturedFrame.maxReasonableLength, isCancelled: isCancelled)
        )
        if let expectedIdentity, !reader.identity.matches(expectedIdentity) {
            throw FollowStreamError.identityMismatch
        }
        var ordinal: UInt64 = 0
        // A details search reads every frame's decode, so it decodes in capture order
        // and sees rebuilt datagrams; a bytes search never decodes.
        var sequential = SequentialFrameDecoder()
        let completion: CaptureStreamCompletion
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                ordinal += 1
                var details = ""
                if query.target == .details {
                    let frame = CapturedFrame(
                        bytes: event.bytes, timestamp: event.reference.timestamp,
                        originalLength: event.reference.originalLength, linkType: event.reference.linkType
                    )
                    let packet = sequential.decode(
                        frame,
                        linkType: reader.defaultLinkType ?? event.reference.linkType,
                        ordinal: ordinal
                    )
                    details = DissectionExporter.layersText(packet.layers)
                }
                if matcher(event.bytes, { details }, isCancelled) {
                    onMatch(ordinal)
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard PcapFileIdentity.snapshot(of: handle).matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
        return switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }
    }
}

// MARK: - FrameExpressionSearch

/// Capture-wide navigation using the same typed facts as the All Frames filter.
/// Unknown evaluations are counted and never treated as matches.
nonisolated enum FrameExpressionSearch {
    struct NavigationResult: Sendable, Equatable {
        let ordinal: UInt64?
        let matchCount: Int
        let unknownCount: Int
        let completeness: CaptureLoadCompleteness
    }

    static func adjacentMatch(
        in url: URL,
        expectedIdentity: PcapFileIdentity,
        sourceToken: UUID,
        expression: FrameExpression,
        after current: UInt64?,
        forward: Bool,
        timeCorrection: CaptureTimeCorrection? = nil,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> NavigationResult
    {
        let scanner = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: expectedIdentity, sourceToken: sourceToken,
            configuration: .init(maxRetainedFrames: 1, timeCorrection: timeCorrection, isCancelled: isCancelled)
        )
        var first: UInt64?
        var last: UInt64?
        var adjacent: UInt64?
        var count = 0
        var unknown = 0
        let list = try scanner.scan(onRow: { row in
            if isCancelled() {
                throw CancellationError()
            }
            switch expression.evaluate(row.filterFacts) {
            case .yes:
                count += 1
                if first == nil {
                    first = row.ordinal
                }
                last = row.ordinal
                if let current {
                    if forward, row.ordinal > current, adjacent == nil {
                        adjacent = row.ordinal
                    } else if !forward, row.ordinal < current {
                        adjacent = row.ordinal
                    }
                }
            case .unknown:
                unknown += 1
            case .no:
                break
            }
        })
        if isCancelled() {
            throw CancellationError()
        }
        return NavigationResult(
            ordinal: adjacent ?? (forward ? first : last), matchCount: count,
            unknownCount: unknown, completeness: list.completeness
        )
    }
}
