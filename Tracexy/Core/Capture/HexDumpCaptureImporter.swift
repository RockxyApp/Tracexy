import Darwin
import Foundation

// MARK: - HexDumpCaptureImporter

/// Converts a fully validated text dump into a managed PCAPNG.
/// Parsing and writing run off the main actor; only the final link makes the
/// capture visible in the active Project's Library.
nonisolated enum HexDumpCaptureImporter {
    static let maxPcapngBytes = 32 * 1_024 * 1_024

    static func importCapture(
        from source: URL,
        linkType: UInt32,
        timestampMode: HexDumpCaptureParser.TimestampMode = .untimed,
        offsetRadix: HexDumpCaptureParser.OffsetRadix = .hexadecimal,
        byteGroupMode: HexDumpCaptureParser.ByteGroupMode = .singleBytes,
        directionIndicators: Bool = false,
        regexPattern: String? = nil,
        regexDataEncoding: HexDumpCaptureParser.RegexDataEncoding = .hexadecimal,
        regexPacketMode: HexDumpCaptureParser.RegexPacketMode = .onePerLine,
        syntheticEthernetForIP: Bool = false,
        syntheticUDP: SyntheticUDPPacketBuilder.Options? = nil,
        syntheticTCP: SyntheticTCPPacketBuilder.Options? = nil,
        syntheticSCTP: SyntheticSCTPPacketBuilder.Options? = nil,
        intoDirectory directory: URL
    )
        throws -> URL
    {
        try Task.checkCancellation()
        let frames = try HexDumpCaptureParser.parse(
            contentsOf: source, linkType: linkType, timestampMode: timestampMode,
            offsetRadix: offsetRadix, byteGroupMode: byteGroupMode,
            directionIndicators: directionIndicators, regexPattern: regexPattern,
            regexDataEncoding: regexDataEncoding, regexPacketMode: regexPacketMode,
            syntheticEthernetForIP: syntheticEthernetForIP, syntheticUDP: syntheticUDP,
            syntheticTCP: syntheticTCP, syntheticSCTP: syntheticSCTP
        )
        try Task.checkCancellation()
        let data = try PcapngWriter.data(defaultLinkType: linkType, frames: frames)
        guard data.count <= maxPcapngBytes else {
            throw HexDumpCaptureParser.ParseError.inputTooLarge
        }
        let temporary = directory.appendingPathComponent(".capture.hexdump-\(UUID().uuidString).tmp")
        let descriptor = temporary.path.withCString { open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600) }
        guard descriptor >= 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
        // Only the successful exclusive create gives this request ownership of
        // the staging path. A failed create never removes another file.
        defer { try? FileManager.default.removeItem(at: temporary) }
        defer { close(descriptor) }
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                return
            }
            var offset = 0
            while offset < raw.count {
                try Task.checkCancellation()
                let written = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if written < 0, errno == EINTR {
                    continue
                }
                guard written > 0 else {
                    throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
                }
                offset += written
            }
        }
        guard fsync(descriptor) == 0 else {
            throw CaptureImportError.publicationFailed(String(cString: strerror(errno)))
        }
        try Task.checkCancellation()
        let rawStem = source.deletingPathExtension().lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines)
        let stem = rawStem.isEmpty || rawStem.hasPrefix(".") ? "Imported Hex Dump" : rawStem
        let suffix: String = if syntheticSCTP != nil {
            "-synthetic-sctp"
        } else if syntheticTCP != nil {
            "-synthetic-tcp"
        } else if syntheticUDP != nil {
            "-synthetic-udp"
        } else {
            syntheticEthernetForIP ? "-synthetic-ethernet" : ""
        }
        return try CaptureImporter.publishGeneratedPcapng(temporary, as: "\(stem)\(suffix).pcapng", in: directory)
    }
}
