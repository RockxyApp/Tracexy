import Foundation

/// Stages a complete dissection export beside its destination. A failed scan
/// or write leaves an existing user file untouched.
nonisolated enum DissectionExportFileWriter {
    // MARK: Internal

    enum ExportError: LocalizedError {
        case destinationIsSource

        // MARK: Internal

        var errorDescription: String? {
            String(localized: "Choose a different export file so the capture source remains unchanged.")
        }
    }

    static func export(
        from source: URL,
        expectedIdentity: PcapFileIdentity?,
        sessions: Set<UUID>?,
        frameOrdinals: Set<UInt64>? = nil,
        frameSelection: FrameOrdinalSelection? = nil,
        frameExpression: FrameExpression? = nil,
        excludedFrameOrdinals: Set<UInt64> = [],
        format: DissectionExporter.Format,
        textLayout: DissectionExporter.TextLayout = .details,
        includeRawFieldBytes: Bool = false,
        appliedFieldColumns: [FieldKey] = [],
        includeTimestampPreamble: Bool = false,
        timeCorrection: CaptureTimeCorrection? = nil,
        to output: URL
    )
        throws -> DissectionExporter.Summary
    {
        let manager = FileManager.default
        if try refersToSameFile(source, output) {
            throw ExportError.destinationIsSource
        }
        let staging = output.deletingLastPathComponent()
            .appendingPathComponent(".\(output.lastPathComponent).\(UUID().uuidString).partial")
        guard manager.createFile(atPath: staging.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? manager.removeItem(at: staging) }

        let handle = try FileHandle(forWritingTo: staging)
        let summary: DissectionExporter.Summary
        do {
            summary = try DissectionExporter.export(
                from: source, expectedIdentity: expectedIdentity, sessions: sessions,
                frameOrdinals: frameOrdinals, frameSelection: frameSelection,
                frameExpression: frameExpression, excludedFrameOrdinals: excludedFrameOrdinals, format: format,
                textLayout: textLayout, includeRawFieldBytes: includeRawFieldBytes,
                appliedFieldColumns: appliedFieldColumns, includeTimestampPreamble: includeTimestampPreamble,
                timeCorrection: timeCorrection
            ) { try handle.write(contentsOf: $0) }
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }

        if try refersToSameFile(source, output) {
            throw ExportError.destinationIsSource
        }
        if manager.fileExists(atPath: output.path) {
            _ = try manager.replaceItemAt(output, withItemAt: staging)
        } else {
            try manager.moveItem(at: staging, to: output)
        }
        return summary
    }

    // MARK: Private

    private static func refersToSameFile(_ lhs: URL, _ rhs: URL) throws -> Bool {
        let leftPath = lhs.standardizedFileURL.resolvingSymlinksInPath()
        let rightPath = rhs.standardizedFileURL.resolvingSymlinksInPath()
        if leftPath == rightPath {
            return true
        }
        guard FileManager.default.fileExists(atPath: rhs.path) else {
            return false
        }
        let left = try FileHandle(forReadingFrom: lhs)
        defer { try? left.close() }
        let right = try FileHandle(forReadingFrom: rhs)
        defer { try? right.close() }
        let leftIdentity = PcapFileIdentity.snapshot(of: left)
        let rightIdentity = PcapFileIdentity.snapshot(of: right)
        return leftIdentity.device != 0 && leftIdentity.inode != 0
            && leftIdentity.device == rightIdentity.device && leftIdentity.inode == rightIdentity.inode
    }
}
