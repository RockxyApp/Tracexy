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

    struct Invalid: Error, Equatable {
        let message: String
    }

    var kind: Kind
    var target: Target
    var text: String
    var caseSensitive = false

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
    func matcher() throws -> (_ bytes: [UInt8], _ details: () -> String) -> Bool {
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
            return { bytes, _ in Self.contains(bytes, needle) }
        case (.string, .bytes):
            let needle = Array(trimmed.utf8)
            return caseSensitive
                ? { bytes, _ in Self.contains(bytes, needle) }
                : { bytes, _ in Self.contains(bytes.map(Self.lowercased), needle.map(Self.lowercased)) }
        case (.string, .details):
            let sensitive = caseSensitive
            return { _, details in
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
            return { bytes, details in
                // Bytes are read one character per byte, so a pattern can span any value.
                let text = target == .bytes ? String(bytes.map { Character(Unicode.Scalar($0)) }) : details()
                return expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
            }
        }
    }

    // MARK: Private

    private static func lowercased(_ byte: UInt8) -> UInt8 {
        (0x41 ... 0x5A).contains(byte) ? byte + 0x20 : byte
    }

    private static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count, let first = needle.first else {
            return false
        }
        var index = 0
        let last = haystack.count - needle.count
        while index <= last {
            if haystack[index] == first, haystack[index ..< index + needle.count].elementsEqual(needle) {
                return true
            }
            index += 1
        }
        return false
    }
}

// MARK: - FrameContentSearch

/// Reads a stable capture file once and returns the numbers of the frames whose
/// content matches a ``FrameSearchQuery``.
nonisolated enum FrameContentSearch {
    static func matches(
        in url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        query: FrameSearchQuery,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> [UInt64]
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
        var found: [UInt64] = []
        // A details search reads every frame's decode, so it decodes in capture order
        // and sees rebuilt datagrams; a bytes search never decodes.
        var sequential = SequentialFrameDecoder()
        while case let .frame(event) = try reader.next() {
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
            if matcher(event.bytes, { details }) {
                found.append(ordinal)
            }
        }
        return found
    }
}
