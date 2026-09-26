import Foundation

// MARK: - FieldKey

/// A decode-tree field by its layer's protocol and its own name, such as DNS's
/// "Query name" — what Statistics ▸ Value Distribution counts.
nonisolated struct FieldKey: Hashable, Sendable {
    let proto: ProtocolKind
    let name: String

    var title: String {
        "\(proto.label) › \(name)"
    }
}

// MARK: - FieldValueDistribution

/// Each value a field took in the frames scanned, with its occurrences and share,
/// and the normalized Shannon entropy of the whole — Wireshark's Distribution
/// window. A frame that carries the field several times counts each occurrence.
nonisolated struct FieldValueDistribution: Equatable, Sendable {
    struct Row: Identifiable, Hashable, Sendable {
        let value: String
        let count: Int
        /// Percent of all occurrences.
        let percent: Double

        var id: String {
            value
        }
    }

    /// Distinct values kept at most; the rest are counted together.
    static let maximumDistinctValues = 50_000
    /// Characters of a value kept.
    static let maximumValueLength = 200

    let key: FieldKey
    /// Most frequent first; ties by value.
    let rows: [Row]
    let occurrences: Int
    let framesWithField: Int
    let framesScanned: Int
    /// Occurrences of values past ``maximumDistinctValues``, not listed.
    let otherOccurrences: Int
    /// 0 when every occurrence has the same value, 1 when all values are equally
    /// common; `nil` with fewer than two distinct values.
    let entropy: Double?

    /// `normalized_shannon`: H = −Σ p·log₂p over the distinct values, divided by
    /// log₂ of how many there are.
    static func normalizedEntropy(_ counts: [Int]) -> Double? {
        let total = counts.reduce(0, +)
        guard total > 0, counts.count >= 2 else {
            return nil
        }
        let entropy = counts.reduce(0.0) { sum, count in
            guard count > 0 else {
                return sum
            }
            let share = Double(count) / Double(total)
            return sum - share * log2(share)
        }
        return entropy / log2(Double(counts.count))
    }

    /// Builds the table from counted values.
    static func make(
        key: FieldKey,
        counts: [String: Int],
        framesWithField: Int,
        framesScanned: Int,
        otherOccurrences: Int
    )
        -> FieldValueDistribution
    {
        let occurrences = counts.values.reduce(0, +) + otherOccurrences
        let rows = counts
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .map { Row(value: $0.key, count: $0.value, percent: Double($0.value) * 100 / Double(max(occurrences, 1))) }
        return FieldValueDistribution(
            key: key, rows: rows, occurrences: occurrences, framesWithField: framesWithField,
            framesScanned: framesScanned, otherOccurrences: otherOccurrences,
            entropy: normalizedEntropy(Array(counts.values))
        )
    }

    /// Value, occurrences and percent, as Wireshark's Copy.
    func csv() -> String {
        func field(_ text: String) -> String {
            text.contains { [",", "\"", "\n", "\r"].contains($0) }
                ? "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\"" : text
        }
        let lines = rows.map { "\(field($0.value)),\($0.count),\(String(format: "%.2f", $0.percent))" }
        return (["Field Value,Occurrences,Percent"] + lines).joined(separator: "\r\n") + "\r\n"
    }
}

// MARK: - FieldPlot

/// A field's numeric values over time, for Statistics ▸ Plot (Wireshark's Plots
/// window): one point per occurrence, at its frame's time.
nonisolated struct FieldPlot: Equatable, Sendable {
    struct Point: Identifiable, Hashable, Sendable {
        /// The frame's number in the capture.
        let frame: UInt64
        /// Seconds since the capture's first frame.
        let time: Double
        let value: Double

        var id: String {
            "\(frame)-\(time)-\(value)"
        }
    }

    /// Points kept at most, so the chart stays responsive; beyond it every n-th point
    /// is kept and the plot says so.
    static let maximumPoints = 20_000

    let key: FieldKey
    let points: [Point]
    /// Occurrences whose value is not a number (a name, a flag list).
    let nonNumericCount: Int
    /// All numeric occurrences, before thinning.
    let numericCount: Int

    var isThinned: Bool {
        numericCount > points.count
    }

    /// A field value as a number: decimal, with a leading sign or fraction, or `0x`
    /// hexadecimal, read from the start of the text ("64", "1500 bytes", "0x0800").
    static func number(_ text: String) -> Double? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.lowercased().hasPrefix("0x") {
            let digits = trimmed.dropFirst(2).prefix { $0.isHexDigit }
            return digits.isEmpty ? nil : UInt64(digits, radix: 16).map { Double($0) }
        }
        var end = trimmed.startIndex
        var seenDigit = false
        var seenPoint = false
        for (offset, character) in trimmed.enumerated() {
            if character.isASCII, character.isNumber {
                seenDigit = true
            } else if character == ".", !seenPoint, seenDigit {
                seenPoint = true
            } else if character == "-" || character == "+", offset == 0 {
                // A sign only leads.
            } else {
                break
            }
            end = trimmed.index(after: end)
        }
        guard seenDigit else {
            return nil
        }
        var numeric = String(trimmed[..<end])
        if numeric.hasSuffix(".") {
            numeric.removeLast()
        }
        return Double(numeric)
    }
}

// MARK: - FieldValueScanner

/// Reads a stable capture file once and counts every value of one field, in every
/// frame or only in the frames of the given sessions.
nonisolated final class FieldValueScanner {
    // MARK: Lifecycle

    init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws
    {
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(maxCapturedLength: CapturedFrame.maxReasonableLength, isCancelled: isCancelled)
        )
        guard reader.identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        self.reader = reader
    }

    // MARK: Internal

    /// Every value `key` has in `layers`, nested layers included.
    static func values(of key: FieldKey, in layers: [DecodedLayer]) -> [String] {
        layers.flatMap { layer in
            let own = layer.proto == key.proto
                ? layer.fields.filter { $0.name == key.name }
                .map { String($0.value.prefix(FieldValueDistribution.maximumValueLength)) }
                : []
            return own + values(of: key, in: layer.children)
        }
    }

    /// The numeric values `key` took, each at its frame's time since the first frame.
    func scanPoints(_ key: FieldKey, sessions: Set<UUID>? = nil) throws -> FieldPlot {
        var points: [FieldPlot.Point] = []
        var nonNumeric = 0
        var ordinal: UInt64 = 0
        var origin: Date?
        while case let .frame(event) = try reader.next() {
            ordinal += 1
            if origin == nil {
                origin = event.reference.timestamp
            }
            let frame = CapturedFrame(
                bytes: event.bytes, timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength, capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = SessionBuilder.decodePacket(
                frame,
                linkType: reader.defaultLinkType ?? event.reference.linkType
            )
            if let sessions {
                guard let tuple = packet.fiveTuple, sessions.contains(SessionBuilder.sessionID(for: tuple)) else {
                    continue
                }
            }
            guard let time = event.reference.timestamp, let origin else {
                continue
            }
            for value in Self.values(of: key, in: packet.layers) {
                guard let number = FieldPlot.number(value) else {
                    nonNumeric += 1
                    continue
                }
                points.append(FieldPlot.Point(frame: ordinal, time: time.timeIntervalSince(origin), value: number))
            }
        }
        let numeric = points.count
        if numeric > FieldPlot.maximumPoints {
            let stride = (numeric + FieldPlot.maximumPoints - 1) / FieldPlot.maximumPoints
            points = points.enumerated().filter { $0.offset % stride == 0 }.map(\.element)
        }
        return FieldPlot(key: key, points: points, nonNumericCount: nonNumeric, numericCount: numeric)
    }

    /// The values `key` took in the file's frames; `sessions` limits the count to
    /// the frames of those sessions.
    func scan(_ key: FieldKey, sessions: Set<UUID>? = nil) throws -> FieldValueDistribution {
        var counts: [String: Int] = [:]
        var other = 0
        var framesWithField = 0
        var scanned = 0
        while case let .frame(event) = try reader.next() {
            let frame = CapturedFrame(
                bytes: event.bytes, timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength, capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = SessionBuilder.decodePacket(
                frame,
                linkType: reader.defaultLinkType ?? event.reference.linkType
            )
            if let sessions {
                guard let tuple = packet.fiveTuple, sessions.contains(SessionBuilder.sessionID(for: tuple)) else {
                    continue
                }
            }
            scanned += 1
            let values = Self.values(of: key, in: packet.layers)
            if !values.isEmpty {
                framesWithField += 1
            }
            for value in values {
                if counts[value] != nil || counts.count < FieldValueDistribution.maximumDistinctValues {
                    counts[value, default: 0] += 1
                } else {
                    other += 1
                }
            }
        }
        return FieldValueDistribution.make(
            key: key, counts: counts, framesWithField: framesWithField, framesScanned: scanned,
            otherOccurrences: other
        )
    }

    // MARK: Private

    private let reader: CaptureStreamReader
}
