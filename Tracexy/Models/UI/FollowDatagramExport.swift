import Foundation

/// Bounded exports of a Follow Conversation result.
nonisolated enum FollowDatagramExport {
    // MARK: Internal

    enum Side: String, CaseIterable, Identifiable, Sendable {
        case both
        case aToB
        case bToA

        // MARK: Internal

        var id: String {
            rawValue
        }

        func admits(_ direction: ConnectionDirection) -> Bool {
            switch self {
            case .both: true
            case .aToB: direction == .aToB
            case .bToA: direction == .bToA
            }
        }
    }

    enum ExportError: Error, Equatable {
        case tooLarge
        case emptySelection
        case incomplete
    }

    static let maximumExportBytes = 8 << 20
    static let maximumExportMessages = 4_096

    /// Concatenate complete payloads in capture order. Raw bytes cannot carry
    /// datagram boundaries or omission metadata, so incomplete results fail closed.
    nonisolated static func raw(_ result: FollowDatagramResult, side: Side) throws -> Data {
        let messages = result.messages.filter { side.admits($0.direction) }
        guard !messages.isEmpty else {
            throw ExportError.emptySelection
        }
        guard result.completeness == .complete, result.limitations.isEmpty,
              result.omittedMessageCount == 0, result.omittedPayloadByteCount == 0 else
        {
            throw ExportError.incomplete
        }
        var total = 0
        for message in messages {
            guard let declared = message.declaredPayloadLength,
                  declared == message.capturedPayloadLength,
                  message.payload.count == message.capturedPayloadLength else
            {
                throw ExportError.incomplete
            }
            let sum = total.addingReportingOverflow(message.payload.count)
            guard !sum.overflow, sum.partialValue <= maximumExportBytes else {
                throw ExportError.tooLarge
            }
            total = sum.partialValue
        }
        var output = Data(capacity: total)
        for message in messages {
            output.append(contentsOf: message.payload)
        }
        return output
    }

    /// Serialize the selected retained datagrams in capture order. `omitted*` counts
    /// describe the whole conversation because the reader does not retain their sides.
    nonisolated static func yaml(_ result: FollowDatagramResult, side: Side) throws -> Data {
        let messages = result.messages.filter { side.admits($0.direction) }
        guard !messages.isEmpty else {
            throw ExportError.emptySelection
        }
        guard messages.count <= maximumExportMessages else {
            throw ExportError.tooLarge
        }
        let payloadBytes = messages.reduce(0) { $0 + $1.payload.count }
        let encodedEstimate = payloadBytes.multipliedReportingOverflow(by: 2)
        let recordEstimate = messages.count.multipliedReportingOverflow(by: 384)
        guard !encodedEstimate.overflow, !recordEstimate.overflow,
              encodedEstimate.partialValue <= maximumExportBytes - recordEstimate.partialValue else
        {
            throw ExportError.tooLarge
        }

        var lines = [
            "peers:",
            "  - peer: 0",
            "    host: '\(yamlQuoted(result.tuple.a.ip))'",
            "    port: \(result.tuple.a.port)",
            "  - peer: 1",
            "    host: '\(yamlQuoted(result.tuple.b.ip))'",
            "    port: \(result.tuple.b.port)",
            "packets:",
        ]
        var peerIndices = [ConnectionDirection: Int]()
        for message in messages {
            let peer = message.direction == .aToB ? 0 : 1
            let index = peerIndices[message.direction, default: 0]
            peerIndices[message.direction] = index + 1
            lines.append("  - packet: \(message.provenance.ordinal.rawValue)")
            lines.append("    peer: \(peer)")
            lines.append("    index: \(index)")
            if let timestamp = message.provenance.timestamp {
                lines.append("    timestamp: \(String(format: "%.9f", timestamp.timeIntervalSince1970))")
            }
            lines.append("    captured_payload_length: \(message.capturedPayloadLength)")
            if let declared = message.declaredPayloadLength {
                lines.append("    declared_payload_length: \(declared)")
            }
            lines.append("    retained_payload_length: \(message.payload.count)")
            lines.append("    bound_omitted_payload_bytes: \(message.boundOmittedByteCount)")
            let encoded = Data(message.payload).base64EncodedString()
            if encoded.isEmpty {
                lines.append("    data: !!binary \"\"")
            } else {
                lines.append("    data: !!binary |")
                for start in stride(from: 0, to: encoded.count, by: 76) {
                    let begin = encoded.index(encoded.startIndex, offsetBy: start)
                    let end = encoded.index(begin, offsetBy: min(76, encoded.count - start))
                    lines.append("      \(encoded[begin ..< end])")
                }
            }
        }
        lines.append("conversation:")
        lines.append("  omitted_datagrams: \(result.omittedMessageCount)")
        lines.append("  omitted_captured_payload_bytes: \(result.omittedPayloadByteCount)")
        lines.append("  source_completeness: \(result.completeness == .complete ? "complete" : "truncated_tail")")
        let limitations = limitationNames(result.limitations)
        if limitations.isEmpty {
            lines.append("  limitations: []")
        } else {
            lines.append("  limitations:")
        }
        for limitation in limitations {
            lines.append("    - \(limitation)")
        }
        let output = Data((lines.joined(separator: "\n") + "\n").utf8)
        guard output.count <= maximumExportBytes else {
            throw ExportError.tooLarge
        }
        return output
    }

    // MARK: Private

    nonisolated private static func yamlQuoted(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "''")
    }

    nonisolated private static func limitationNames(_ limitations: FollowDatagramLimitations) -> [String] {
        var names: [String] = []
        if limitations.contains(.capturedPayloadTruncated) {
            names.append("captured_payload_truncated")
        }
        if limitations.contains(.messageBytesBounded) {
            names.append("message_bytes_bounded")
        }
        if limitations.contains(.messageRetentionTruncated) {
            names.append("message_retention_truncated")
        }
        if limitations.contains(.sourceTailTruncated) {
            names.append("source_tail_truncated")
        }
        return names
    }
}
