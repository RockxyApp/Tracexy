import CoreSpotlight
import Foundation
import UniformTypeIdentifiers
#if canImport(Tracexy)
// The unit-test host compiles this file beside the app module so the extension's
// logic is covered; the extension target itself compiles the CaptureFormat
// sources directly and has no such module.
@testable import Tracexy
#endif

// MARK: - ImportExtension

/// Spotlight importer for `.pcap` / `.pcapng`: indexes the bounded facts a
/// capture file states about itself (format, record count, first frame, elapsed,
/// interface names, application) so a capture can be found by what it is rather
/// than by its file name. No packet payload, address or host name is indexed.
final class ImportExtension: CSImportExtension {
    // MARK: Internal

    override func update(_ attributes: CSSearchableItemAttributeSet, forFileAt url: URL) throws {
        let preview = CapturePreviewScanner.scan(url, budget: .init(maxRecords: 200_000, maxDuration: .seconds(2)))
        guard case .complete = preview.status else {
            if case .timedOut = preview.status {
                try apply(preview, url: url, to: attributes)
                return
            }
            throw CocoaError(.fileReadCorruptFile)
        }
        try apply(preview, url: url, to: attributes)
    }

    // MARK: Private

    private func apply(_ preview: CapturePreview, url: URL, to attributes: CSSearchableItemAttributeSet) throws {
        var parts: [String] = [preview.formatDescription]
        let records = preview.records.formatted()
        parts.append(preview.status == .timedOut ? "at least \(records) records" : "\(records) records")
        var keywords: [String] = [preview.formatDescription, "packet capture", "network trace"]
        if let reader = try? CaptureStreamReader(contentsOf: url) {
            var steps = 0
            while steps < 2_000, case .frame = (try? reader.next()) ?? .end(
                CaptureStreamCompletion(
                    reason: .cleanEndOfFile,
                    progress: PcapStreamProgress(bytesConsumed: 0, totalBytes: 0)
                )
            ) {
                steps += 1
            }
            let properties = reader.fileProperties
            let names = properties.allInterfaces.compactMap { $0.name?.text }.filter { !$0.isEmpty }
            if !names.isEmpty {
                parts.append("interfaces: " + names.joined(separator: ", "))
                keywords.append(contentsOf: names)
            }
            if let application = properties.sections.first?.application?.text, !application.isEmpty {
                parts.append("written by \(application)")
                attributes.creator = application
            }
        }
        if let first = preview.firstTimestamp {
            attributes.contentCreationDate = first
            attributes.startDate = first
            if let last = preview.lastTimestamp {
                attributes.endDate = last
            }
            if let elapsed = preview.elapsed {
                attributes.duration = NSNumber(value: elapsed)
            }
        }
        attributes.contentDescription = parts.joined(separator: " · ")
        attributes.keywords = keywords
        attributes.kind = preview.formatDescription
    }
}
