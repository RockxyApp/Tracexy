import AppKit
import QuickLookUI
import SwiftUI
#if canImport(Tracexy)
// The unit-test host compiles this file beside the app module so the extension's
// logic is covered; the extension target itself compiles the CaptureFormat
// sources directly and has no such module.
@testable import Tracexy
#endif

// MARK: - PreviewViewController

/// Quick Look preview for `.pcap` / `.pcapng`: Finder's Space-bar preview, the
/// Open panel's column preview and Spotlight's preview all show the same bounded
/// facts the app's Open panel shows — format, size, records (with the bound
/// stated), first frame and elapsed, and the interfaces the container declares.
/// The scan is budgeted and reads no packet payload into the preview.
@MainActor
final class PreviewViewController: NSViewController, QLPreviewingController {
    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 520, height: 320))
    }

    func preparePreviewOfFile(at url: URL) async throws {
        let scanned = await Task.detached(priority: .userInitiated) {
            CapturePreviewSummary.scan(url)
        }.value
        let hosting = NSHostingView(rootView: CapturePreviewView(summary: scanned))
        hosting.translatesAutoresizingMaskIntoConstraints = false
        view.subviews.forEach { $0.removeFromSuperview() }
        view.addSubview(hosting)
        NSLayoutConstraint.activate([
            hosting.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hosting.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            hosting.topAnchor.constraint(equalTo: view.topAnchor),
            hosting.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }
}

// MARK: - CapturePreviewSummary

/// Everything the preview renders, gathered off the main actor in one bounded
/// pass: the Open-panel preview plus the container facts the scanned prefix
/// declared.
nonisolated struct CapturePreviewSummary: Sendable {
    let fileName: String
    let preview: CapturePreview
    let interfaces: [CaptureInterface]
    let sectionApplication: String?
    let sectionComment: String?

    static func scan(_ url: URL) -> CapturePreviewSummary {
        let preview = CapturePreviewScanner.scan(
            url,
            budget: .init(maxRecords: 100_000, maxDuration: .milliseconds(400))
        )
        var interfaces: [CaptureInterface] = []
        var application: String?
        var comment: String?
        switch preview.status {
        case .complete,
             .timedOut,
             .errorAfterRecords:
            // A second, tighter pass collects the container facts the prefix
            // declares (interface descriptions precede frames), without
            // decoding any payload.
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
                interfaces = Array(properties.allInterfaces.prefix(8))
                application = properties.sections.first?.application?.text
                comment = properties.sections.first?.comments.values.first?.text
            }
        default:
            break
        }
        return CapturePreviewSummary(
            fileName: url.lastPathComponent,
            preview: preview,
            interfaces: interfaces,
            sectionApplication: application,
            sectionComment: comment
        )
    }
}

// MARK: - CapturePreviewView

struct CapturePreviewView: View {
    // MARK: Internal

    let summary: CapturePreviewSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.system(size: 28))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(summary.fileName).font(.headline).lineLimit(1).truncationMode(.middle)
                    Text(formatLine).font(.subheadline).foregroundStyle(.secondary)
                }
            }
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
                row("Size", sizeText)
                row("Start / elapsed", timeText)
                if let application = summary.sectionApplication {
                    row("Application", application)
                }
                if let comment = summary.sectionComment {
                    row("Comment", comment)
                }
            }
            if !summary.interfaces.isEmpty {
                Text("Interfaces").font(.subheadline.weight(.semibold))
                ForEach(summary.interfaces) { interface in
                    HStack(spacing: 8) {
                        Text(interface.displayName)
                        if let description = interface.interfaceDescription?.text, !description.isEmpty {
                            Text(description).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("link type \(interface.linkType)").foregroundStyle(.secondary).monospacedDigit()
                    }
                    .font(.callout)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Private

    private var formatLine: String {
        switch summary.preview.status {
        case .unknownFormat: String(localized: "Not a PCAP or PCAPNG capture")
        case .unreadable: String(localized: "The file can’t be read")
        case .directory: String(localized: "Folder")
        case let .compressed(container): String(localized: "\(container) archive")
        case .complete,
             .timedOut,
             .errorAfterRecords: summary.preview.formatDescription
        }
    }

    private var sizeText: String {
        let size = ByteCountFormatter.string(fromByteCount: Int64(summary.preview.fileSize), countStyle: .file)
        let records = summary.preview.records.formatted()
        switch summary.preview.status {
        case .complete: return String(localized: "\(size), \(records) records")
        case .timedOut: return String(localized: "\(size), at least \(records) records")
        case .errorAfterRecords: return String(localized: "\(size), error after \(records) records")
        default: return size
        }
    }

    private var timeText: String {
        guard let first = summary.preview.firstTimestamp else {
            return String(localized: "unknown / unknown")
        }
        let start = first.formatted(date: .numeric, time: .standard)
        guard let elapsed = summary.preview.elapsed else {
            return String(localized: "\(start) / unknown")
        }
        let total = Int(elapsed.rounded(.down))
        let clock = String(format: "%02d:%02d:%02d", total / 3_600, (total % 3_600) / 60, total % 60)
        return "\(start) / \(clock)"
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).textSelection(.enabled)
        }
        .font(.callout)
    }
}
