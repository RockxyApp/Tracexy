import Foundation

// MARK: - DissectionExporter

/// Every frame's decode tree as text or JSON — Wireshark's File ▸ Export Packet
/// Dissections and tshark's `-V` / `-T json`: the frame line, then each layer with
/// its summary and fields, nested layers indented. Values are exactly what Layers
/// shows (credentials are never decoded in the first place); packet bytes are not
/// written. Streams to `sink` in chunks, so a large capture is never held whole.
nonisolated enum DissectionExporter {
    enum Format: String, CaseIterable, Sendable {
        case text
        case json
    }

    /// Frames written, and frames read in all.
    struct Summary: Equatable, Sendable {
        let writtenFrameCount: Int
        let scannedFrameCount: Int
    }

    static func export(
        from url: URL,
        expectedIdentity: PcapFileIdentity? = nil,
        sessions: Set<UUID>? = nil,
        format: Format,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled },
        to sink: (Data) throws -> Void
    )
        throws -> Summary
    {
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
        var sequential = SequentialFrameDecoder()
        if format == .json {
            try emit("[\n")
        }
        while case let .frame(event) = try reader.next() {
            ordinal += 1
            let frame = CapturedFrame(
                bytes: event.bytes, timestamp: event.reference.timestamp,
                originalLength: event.reference.originalLength, capturedLength: event.reference.capturedLength,
                linkType: event.reference.linkType
            )
            let packet = sequential.decode(
                frame,
                linkType: reader.defaultLinkType ?? event.reference.linkType,
                ordinal: UInt64(ordinal)
            )
            let session = packet.fiveTuple.map(SessionBuilder.sessionID(for:))
            if let sessions {
                guard let session, sessions.contains(session) else {
                    continue
                }
            }
            switch format {
            case .text:
                try emit(text(
                    frame: ordinal,
                    captured: frame.capturedLength,
                    original: frame.originalLength,
                    time: frame.timestamp,
                    layers: packet.layers
                ))
            case .json:
                let object = json(
                    frame: ordinal, captured: frame.capturedLength, original: frame.originalLength,
                    time: frame.timestamp, session: session, layers: packet.layers
                )
                let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                try emit((written == 0 ? "" : ",\n") + (String(bytes: data, encoding: .utf8) ?? "{}"))
            }
            written += 1
        }
        if format == .json {
            try emit(written == 0 ? "]\n" : "\n]\n")
        }
        if !buffer.isEmpty {
            try sink(buffer)
        }
        return Summary(writtenFrameCount: written, scannedFrameCount: ordinal)
    }

    /// One frame as tshark `-V` lays it out: a frame line, then each layer's title
    /// and summary with its fields indented four spaces per level.
    static func text(frame: Int, captured: Int, original: Int, time: Date?, layers: [DecodedLayer]) -> String {
        let header = "Frame \(frame): \(original) bytes on wire, \(captured) bytes captured"
            + (time.map { ", \(stamp($0))" } ?? "")
        return header + "\n" + layersText(layers) + "\n"
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
        layers: [DecodedLayer]
    )
        -> [String: Any]
    {
        func describe(_ layer: DecodedLayer) -> [String: Any] {
            var object: [String: Any] = [
                "protocol": layer.proto.label,
                "title": layer.title,
                "fields": layer.fields.map { ["name": $0.name, "value": $0.value] },
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
}
