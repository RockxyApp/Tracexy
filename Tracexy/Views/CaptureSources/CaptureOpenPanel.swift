import AppKit
import Foundation

// MARK: - CaptureOpenPanel

/// File ▸ Open… : the system open panel with a preview accessory.
///
/// The accessory follows the semantics of Wireshark's open-dialog preview
/// (format · size · records · start / elapsed) and adds the one Tracexy choice
/// — whether to copy the file into the Project Library — as a checkbox. The
/// preview is computed off the main actor with a record/time budget and is
/// cancelled whenever the selection changes; a late result for an earlier
/// selection is dropped by request id.
///
/// AppKit is used deliberately: SwiftUI's `fileImporter` has no accessory view,
/// and content sniffing needs every file enabled (`allowedContentTypes = []`).
@MainActor
final class CaptureOpenPanel: NSObject, NSOpenSavePanelDelegate {
    // MARK: Lifecycle

    init(copiesIntoLibrary: Bool) {
        accessory = CaptureOpenAccessoryView(copiesIntoLibrary: copiesIntoLibrary)
        super.init()
    }

    // MARK: Internal

    struct Choice {
        let url: URL
        let copiesIntoLibrary: Bool
    }

    /// Run the panel modally. Returns `nil` on Cancel.
    func run() -> Choice? {
        let panel = NSOpenPanel()
        panel.identifier = NSUserInterfaceItemIdentifier("com.amunx.tracexy.open-capture")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.resolvesAliases = true
        // No content-type gate: an extensionless capture must be selectable; the
        // format is decided from the header, and the preview says what was found.
        panel.allowedContentTypes = []
        panel.prompt = String(localized: "Open")
        panel.message = String(
            localized: "Choose a PCAP or PCAPNG capture, a gzip-compressed capture, or a TCP Viewer session. Tracexy reads the file’s contents, not its name."
        )
        panel.accessoryView = accessory
        panel.isAccessoryViewDisclosed = true
        panel.delegate = self
        defer {
            previewTask?.cancel()
            panel.delegate = nil
        }
        guard panel.runModal() == .OK, let url = panel.url else {
            return nil
        }
        return Choice(url: url, copiesIntoLibrary: accessory.copiesIntoLibrary)
    }

    // MARK: NSOpenSavePanelDelegate

    func panelSelectionDidChange(_ sender: Any?) {
        guard let panel = sender as? NSOpenPanel else {
            return
        }
        preview(panel.url)
    }

    // MARK: Private

    private let accessory: CaptureOpenAccessoryView
    private var previewTask: Task<Void, Never>?
    private var previewRequestID = 0

    private func preview(_ url: URL?) {
        previewTask?.cancel()
        previewRequestID &+= 1
        let requestID = previewRequestID
        guard let url else {
            accessory.show(nil)
            return
        }
        accessory.showPending()
        previewTask = Task.detached(priority: .userInitiated) { [weak self] in
            let preview = CapturePreviewScanner.scan(url)
            guard !Task.isCancelled else {
                return
            }
            await self?.deliver(preview, requestID: requestID)
        }
    }

    private func deliver(_ preview: CapturePreview, requestID: Int) {
        guard requestID == previewRequestID else {
            return
        }
        accessory.show(preview)
    }
}

// MARK: - CaptureOpenAccessoryView

/// Format / Size / Records / Start–elapsed rows plus the Library checkbox, laid out
/// with `NSGridView` so every value is a labelled text field for VoiceOver.
@MainActor
final class CaptureOpenAccessoryView: NSView {
    // MARK: Lifecycle

    init(copiesIntoLibrary: Bool) {
        super.init(frame: NSRect(x: 0, y: 0, width: 480, height: 128))
        let rows: [(String, NSTextField)] = [
            (String(localized: "Format:"), formatField),
            (String(localized: "Size:"), sizeField),
            (String(localized: "Start / elapsed:"), timeField),
        ]
        var gridRows: [[NSView]] = []
        for (title, field) in rows {
            let label = NSTextField(labelWithString: title)
            label.alignment = .right
            label.textColor = .secondaryLabelColor
            field.lineBreakMode = .byTruncatingMiddle
            field.setAccessibilityLabel(String(title.dropLast()))
            gridRows.append([label, field])
        }
        let grid = NSGridView(views: gridRows)
        grid.rowSpacing = 4
        grid.columnSpacing = 8
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).width = 320
        grid.translatesAutoresizingMaskIntoConstraints = false

        checkbox.state = copiesIntoLibrary ? .on : .off
        checkbox.translatesAutoresizingMaskIntoConstraints = false
        checkbox.toolTip = String(
            localized: "Keep a managed copy in this Project’s Library. Leave off to open the file where it is."
        )

        addSubview(grid)
        addSubview(checkbox)
        NSLayoutConstraint.activate([
            grid.topAnchor.constraint(equalTo: topAnchor, constant: 8),
            grid.centerXAnchor.constraint(equalTo: centerXAnchor),
            grid.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 16),
            checkbox.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 10),
            checkbox.leadingAnchor.constraint(equalTo: grid.leadingAnchor, constant: 96),
            checkbox.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -8),
        ])
        show(nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        nil
    }

    // MARK: Internal

    var copiesIntoLibrary: Bool {
        checkbox.state == .on
    }

    nonisolated static func formatText(_ preview: CapturePreview) -> String {
        switch preview.status {
        case .directory: String(localized: "Folder")
        case .unreadable: String(localized: "Can’t be read")
        case .unknownFormat: String(localized: "Unknown file format")
        case let .compressed(container): String(localized: "\(container) archive — expanded on open")
        case .complete,
             .timedOut,
             .errorAfterRecords: preview.formatDescription
        }
    }

    nonisolated static func sizeText(_ preview: CapturePreview) -> String {
        let size = ByteCountFormatter.string(fromByteCount: Int64(preview.fileSize), countStyle: .file)
        switch preview.status {
        case .directory,
             .unreadable,
             .unknownFormat,
             .compressed: return size
        case .complete:
            return String(localized: "\(size), \(preview.records.formatted()) records")
        case .timedOut:
            return String(localized: "\(size), timed out at \(preview.records.formatted()) records")
        case .errorAfterRecords:
            return String(localized: "\(size), error after \(preview.records.formatted()) records")
        }
    }

    nonisolated static func timeText(_ preview: CapturePreview) -> String {
        guard let first = preview.firstTimestamp else {
            return String(localized: "unknown / unknown")
        }
        let start = first.formatted(date: .numeric, time: .standard)
        guard let elapsed = preview.elapsed else {
            return String(localized: "\(start) / unknown")
        }
        return "\(start) / \(Self.elapsedText(elapsed))"
    }

    nonisolated static func elapsedText(_ elapsed: TimeInterval) -> String {
        let total = Int(elapsed.rounded(.down))
        let days = total / 86_400
        let rest = total % 86_400
        let clock = String(format: "%02d:%02d:%02d", rest / 3_600, (rest % 3_600) / 60, rest % 60)
        return days > 0 ? String(localized: "\(days) day(s) \(clock)") : clock
    }

    func showPending() {
        formatField.stringValue = String(localized: "Checking…")
        sizeField.stringValue = "—"
        timeField.stringValue = "—"
    }

    func show(_ preview: CapturePreview?) {
        guard let preview else {
            formatField.stringValue = "—"
            sizeField.stringValue = "—"
            timeField.stringValue = "—"
            return
        }
        formatField.stringValue = Self.formatText(preview)
        sizeField.stringValue = Self.sizeText(preview)
        timeField.stringValue = Self.timeText(preview)
    }

    // MARK: Private

    private let formatField = NSTextField(labelWithString: "—")
    private let sizeField = NSTextField(labelWithString: "—")
    private let timeField = NSTextField(labelWithString: "—")
    private let checkbox = NSButton(
        checkboxWithTitle: String(localized: "Copy into Library"), target: nil, action: nil
    )
}
