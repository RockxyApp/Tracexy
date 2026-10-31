import Foundation

// MARK: - DissectionExporter

/// Supported frame sections as text, summary CSV or JSON — inspired by
/// Wireshark's File ▸ Export Packet Dissections. Decoded text uses the same
/// supported layer fields as Layers; the bytes section emits captured bytes
/// as hex. Streams to `sink` in
/// chunks, so a large capture is never held whole.
nonisolated enum DissectionExporter {
    // MARK: Internal

    enum ExportError: LocalizedError, Equatable {
        case truncatedTail(completeFrameCount: Int)
        case emptyTextLayout

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case let .truncatedTail(count):
                "The capture ends with an incomplete record after \(count) complete frames. Repair the capture before exporting dissections."
            case .emptyTextLayout:
                "Choose at least one plain-text packet section before exporting."
            }
        }
    }

    enum Format: String, CaseIterable, Sendable {
        case text
        case csv
        case json
    }

    struct TextLayout: OptionSet, Sendable {
        static let details = Self(rawValue: 1 << 0)
        static let summary = Self(rawValue: 1 << 1)
        static let bytes = Self(rawValue: 1 << 2)

        let rawValue: UInt8
    }

    /// Frames written, and frames read in all.
    struct Summary: Equatable, Sendable {
        let writtenFrameCount: Int
        let scannedFrameCount: Int
        var unknownExpressionFrameCount = 0
        var excludedIgnoredFrameCount = 0
    }

    static let maximumRawFieldBytes = 4 * 1_024
    static let maximumRawFieldBytesPerFrame = 32 * 1_024
    static let maximumAppliedFieldColumns = 4
    static let maximumAppliedFieldColumnValueBytes = 8 * 1_024

    static func export(
        from url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        sessions: Set<UUID>? = nil,
        frameOrdinals: Set<UInt64>? = nil,
        frameRange: ClosedRange<UInt64>? = nil,
        frameSelection: FrameOrdinalSelection? = nil,
        frameExpression: FrameExpression? = nil,
        excludedFrameOrdinals: Set<UInt64> = [],
        format: Format,
        textLayout: TextLayout = .details,
        includeRawFieldBytes: Bool = false,
        appliedFieldColumns: [FieldKey] = [],
        includeTimestampPreamble: Bool = false,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled },
        to sink: (Data) throws -> Void
    )
        throws -> Summary
    {
        if format == .text, textLayout.isEmpty {
            throw ExportError.emptyTextLayout
        }
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(maxCapturedLength: CapturedFrame.maxReasonableLength, isCancelled: isCancelled)
        )
        if let expectedIdentity, !reader.identity.matches(expectedIdentity) {
            throw FollowStreamError.identityMismatch
        }
        var buffer = Data()
        func emit(_ text: String) throws {
            buffer.append(contentsOf: text.utf8)
            if buffer.count >= 256 * 1_024 {
                try sink(buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
        var ordinal = 0
        var written = 0
        var unknownExpressionFrameCount = 0
        var excludedIgnoredFrameCount = 0
        var sequential = SequentialFrameDecoder()
        if format == .json {
            try emit("[\n")
        } else if format == .csv {
            let columns = Array(appliedFieldColumns.prefix(maximumAppliedFieldColumns))
            try emit(csvRow(
                ["No.", "Time", "Source", "Destination", "Protocol", "Length"]
                    + columns.map { "\($0.proto.label) \($0.name)" } + ["Info"]
            ))
        }
        walk: while true {
            let outcome = try reader.next()
            guard case let .frame(event) = outcome else {
                guard case let .end(completion) = outcome else {
                    break walk
                }
                if completion.reason != .cleanEndOfFile {
                    throw ExportError.truncatedTail(completeFrameCount: ordinal)
                }
                break walk
            }
            ordinal += 1
            let frame = CapturedFrame(
                bytes: event.bytes, timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength, capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = sequential.decode(
                frame,
                linkType: event.reference.linkType,
                ordinal: UInt64(ordinal)
            )
            if let frameOrdinals, !frameOrdinals.contains(UInt64(ordinal)) {
                continue
            }
            if let frameRange, !frameRange.contains(UInt64(ordinal)) {
                continue
            }
            if let frameSelection, !frameSelection.contains(UInt64(ordinal)) {
                continue
            }
            let session = packet.fiveTuple.map(SessionBuilder.sessionID(for:))
            if let sessions {
                guard let session, sessions.contains(session) else {
                    continue
                }
            }
            if let frameExpression {
                let facts = FrameFilterFacts(
                    packet: packet,
                    capturedLength: frame.capturedLength,
                    originalLength: frame.originalLength,
                    captureDirection: event.reference.direction
                )
                switch frameExpression.evaluate(facts) {
                case .yes:
                    break
                case .no:
                    continue
                case .unknown:
                    unknownExpressionFrameCount += 1
                    continue
                }
            }
            if excludedFrameOrdinals.contains(UInt64(ordinal)) {
                excludedIgnoredFrameCount += 1
                continue
            }
            switch format {
            case .text:
                if textLayout.contains(.summary) {
                    let (name, info) = CaptureFrameListScanner.info(of: packet)
                    let addresses = CaptureFrameListScanner.addresses(of: packet)
                    let displayedInfo = packet.decodeStop
                        .map { info.isEmpty ? $0.infoSuffix : "\(info) \($0.infoSuffix)" }
                        ?? info
                    try emit(summaryText(
                        frame: ordinal, captured: frame.capturedLength,
                        time: frame.timestamp, source: addresses.source, destination: addresses.destination,
                        protocolName: name, info: displayedInfo
                    ))
                }
                if textLayout.contains(.details) {
                    try emit(text(
                        frame: ordinal, captured: frame.capturedLength,
                        original: frame.originalLength, time: frame.timestamp, layers: packet.layers
                    ))
                }
                if textLayout.contains(.bytes) {
                    if includeTimestampPreamble {
                        try emit("Timestamp: \(frame.timestamp.map(stamp) ?? "unknown")\n")
                    }
                    try emit("Frame \(ordinal): \(frame.capturedLength) captured bytes\n")
                    try emit(PacketBytesFormat.hexDump.text(for: event.bytes[...]) + "\n\n")
                }
            case .csv:
                let columns = Array(appliedFieldColumns.prefix(maximumAppliedFieldColumns))
                let (name, info) = CaptureFrameListScanner.info(of: packet)
                let addresses = CaptureFrameListScanner.addresses(of: packet)
                let displayedInfo = packet.decodeStop
                    .map { info.isEmpty ? $0.infoSuffix : "\(info) \($0.infoSuffix)" }
                    ?? info
                try emit(csvRow([
                    String(ordinal), frame.timestamp.map(stamp) ?? "", addresses.source, addresses.destination,
                    name, String(frame.capturedLength),
                ] + columns.map { csvFieldColumn($0, layers: packet.layers) }
                    + [displayedInfo]
                ))
            case .json:
                let object = json(
                    frame: ordinal, captured: frame.capturedLength, original: frame.originalLength,
                    time: frame.timestamp, session: session, layers: packet.layers,
                    rawBytes: event.bytes, includeRawFieldBytes: includeRawFieldBytes
                )
                let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                try emit((written == 0 ? "" : ",\n") + (String(bytes: data, encoding: .utf8) ?? "{}"))
            }
            written += 1
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard PcapFileIdentity.snapshot(of: handle).matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
        if format == .json {
            try emit(written == 0 ? "]\n" : "\n]\n")
        }
        if !buffer.isEmpty {
            try sink(buffer)
        }
        return Summary(
            writtenFrameCount: written, scannedFrameCount: ordinal,
            unknownExpressionFrameCount: unknownExpressionFrameCount,
            excludedIgnoredFrameCount: excludedIgnoredFrameCount
        )
    }

    /// One frame as tshark `-V` lays it out: a frame line, then each layer's title
    /// and summary with its fields indented four spaces per level.
    static func text(frame: Int, captured: Int, original: Int, time: Date?, layers: [DecodedLayer]) -> String {
        let header = "Frame \(frame): \(original) bytes on wire, \(captured) bytes captured"
            + (time.map { ", \(stamp($0))" } ?? "")
        return header + "\n" + layersText(layers) + "\n"
    }

    /// Compact one-line print output from the same decoded protocol and Info
    /// projection used by All Frames. Original capture ordinals are retained.
    static func summaryText(
        frame: Int, captured: Int, time: Date?, source: String, destination: String,
        protocolName: String, info: String
    )
        -> String
    {
        let timestamp = time.map { stamp($0) } ?? "time unknown"
        return "Frame \(frame)  \(timestamp)  \(source) → \(destination)  \(protocolName)  \(captured) bytes  \(info)\n"
    }

    /// A stable seven-column CSV record. Guard capture-derived text before
    /// quoting it so spreadsheet imports cannot execute it as a formula.
    static func csvRow(_ fields: [String]) -> String {
        fields.map { field in
            let first = field.first { !$0.isWhitespace }
            let safe = first.map { "=+-@".contains($0) } == true ? "'\(field)" : field
            return "\"\(safe.replacingOccurrences(of: "\"", with: "\"\""))\""
        }.joined(separator: ",") + "\r\n"
    }

    /// The layers alone, one line each with their fields indented below — what Find
    /// Packet searches as a frame's details.
    static func layersText(_ layers: [DecodedLayer]) -> String {
        var lines: [String] = []
        func walk(_ layers: [DecodedLayer], depth: Int) {
            let indent = String(repeating: "    ", count: depth)
            for layer in layers {
                lines.append(indent + (layer.summary.isEmpty ? layer.title : "\(layer.title), \(layer.summary)"))
                for field in layer.fields {
                    lines.append(indent + "    \(field.name): \(field.value)")
                }
                walk(layer.children, depth: depth + 1)
            }
        }
        walk(layers, depth: 0)
        return lines.map { $0 + "\n" }.joined()
    }

    static func json(
        frame: Int,
        captured: Int,
        original: Int,
        time: Date?,
        session: UUID?,
        layers: [DecodedLayer],
        rawBytes: [UInt8]? = nil,
        includeRawFieldBytes: Bool = false
    )
        -> [String: Any]
    {
        var rawBytesWritten = 0

        func rawFieldBytes(_ field: DecodedField) -> [String: Any] {
            guard includeRawFieldBytes else {
                return [:]
            }
            guard let range = field.byteRange else {
                return ["raw_hex": NSNull(), "raw_hex_status": "no_contiguous_mapping"]
            }
            guard let rawBytes else {
                return ["raw_hex": NSNull(), "raw_hex_status": "captured_bytes_unavailable"]
            }
            guard range.lowerBound >= 0, range.upperBound <= rawBytes.count else {
                return ["raw_hex": NSNull(), "raw_hex_status": "out_of_capture"]
            }
            let byteCount = range.count
            guard byteCount <= maximumRawFieldBytes else {
                return [
                    "raw_hex": NSNull(), "raw_byte_offset": range.lowerBound,
                    "raw_byte_length": byteCount, "raw_hex_status": "field_limit",
                ]
            }
            guard byteCount <= maximumRawFieldBytesPerFrame - rawBytesWritten else {
                return [
                    "raw_hex": NSNull(), "raw_byte_offset": range.lowerBound,
                    "raw_byte_length": byteCount, "raw_hex_status": "frame_limit",
                ]
            }
            rawBytesWritten += byteCount
            let hex = rawBytes[range].map { String(format: "%02x", $0) }.joined()
            return [
                "raw_hex": hex, "raw_byte_offset": range.lowerBound, "raw_byte_length": byteCount,
            ]
        }

        func describe(_ layer: DecodedLayer) -> [String: Any] {
            let fields: [[String: Any]] = layer.fields.map { field in
                var object: [String: Any] = ["name": field.name, "value": field.value]
                for (key, value) in rawFieldBytes(field) {
                    object[key] = value
                }
                return object
            }
            var object: [String: Any] = [
                "protocol": layer.proto.label,
                "title": layer.title,
                "fields": fields,
            ]
            if !layer.summary.isEmpty {
                object["summary"] = layer.summary
            }
            if !layer.children.isEmpty {
                object["layers"] = layer.children.map(describe)
            }
            return object
        }
        var object: [String: Any] = [
            "frame": frame, "captured_length": captured, "original_length": original, "layers": layers.map(describe),
        ]
        if includeRawFieldBytes {
            object["raw_field_bytes_included"] = true
        }
        object["time"] = time.map(stamp)
        object["session"] = session?.uuidString
        return object
    }

    /// ISO 8601 in UTC with microseconds, as tshark's JSON times are (4.6).
    static func stamp(_ date: Date) -> String {
        let seconds = date.timeIntervalSince1970
        var whole = floor(seconds)
        var micros = Int(((seconds - whole) * 1_000_000).rounded())
        if micros == 1_000_000 {
            whole += 1
            micros = 0
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let parts = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: Date(timeIntervalSince1970: whole)
        )
        return String(
            format: "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0,
            parts.hour ?? 0, parts.minute ?? 0, parts.second ?? 0, micros
        )
    }

    // MARK: Private

    private static func csvFieldColumn(_ key: FieldKey, layers: [DecodedLayer]) -> String {
        let value = FieldValueScanner.values(of: key, in: layers).joined(separator: ",")
        guard value.utf8.count > maximumAppliedFieldColumnValueBytes else {
            return value
        }
        var prefix = ""
        for character in value {
            guard prefix.utf8.count + character.utf8.count + 3 <= maximumAppliedFieldColumnValueBytes else {
                break
            }
            prefix.append(character)
        }
        return prefix + "…"
    }
}
