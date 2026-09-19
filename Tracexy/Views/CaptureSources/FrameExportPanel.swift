import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - FrameExportPanel

/// File ▸ Export Frames… : the system save panel with the format as the panel's
/// own pop-up where the OS offers one (macOS 15+, `showsContentTypes`) and as an
/// accessory pop-up otherwise, plus an accessory for Scope, metadata
/// preservation, gzip, and a live "≈ frames · size" estimate. PCAP stays listed
/// but disabled — with the reason — when the source holds mixed link types or
/// untimed frames.
@MainActor
final class FrameExportPanel: NSObject, NSOpenSavePanelDelegate {
    // MARK: Lifecycle

    init(context: Context) {
        self.context = context
        accessory = FrameExportAccessoryView(context: context)
        super.init()
    }

    // MARK: Internal

    /// What the panel needs to know about the source and the current scope.
    struct Context {
        struct ScopeChoice {
            let scope: FrameExportScope
            let title: String
            /// Best-effort frame count for the estimate, or `nil` when unknown.
            let frameEstimate: Int?
        }

        let baseName: String
        let scopes: [ScopeChoice]
        let initialScopeIndex: Int
        /// First and last timed instant of the source; enables the Time range scope.
        let timeBounds: ClosedRange<Date>?
        let sourceIsPcapng: Bool
        /// `nil` when PCAP is representable; otherwise the reason it is not.
        let pcapUnavailableReason: String?
        let averageFrameBytes: Int
    }

    struct Choice {
        let url: URL
        let scope: FrameExportScope
        let options: FrameExportOptions
    }

    func run() -> Choice? {
        let panel = NSSavePanel()
        panel.identifier = NSUserInterfaceItemIdentifier("com.amunx.tracexy.export-frames")
        panel.title = String(localized: "Export Frames")
        panel.nameFieldLabel = String(localized: "Export As:")
        panel.nameFieldStringValue = context.baseName
        panel.canCreateDirectories = true
        panel.canSelectHiddenExtension = true
        panel.isExtensionHidden = false
        panel.allowedContentTypes = [Self.pcapngType, Self.pcapType]
        panel.delegate = self
        accessory.onChange = { [weak self, weak panel] in
            guard let self, let panel else {
                return
            }
            self.syncContentTypes(panel)
        }
        if #available(macOS 15.0, *) {
            panel.showsContentTypes = true
            panel.currentContentType = Self.pcapngType
            accessory.showsFormatControl = false
        } else {
            accessory.showsFormatControl = true
        }
        panel.accessoryView = accessory
        syncContentTypes(panel)
        defer { panel.delegate = nil }
        guard panel.runModal() == .OK, let url = panel.url else {
            return nil
        }
        let format = currentFormat(panel)
        return Choice(
            url: url,
            scope: accessory.selectedScope,
            options: FrameExportOptions(
                format: format,
                preservesMetadata: accessory.preservesMetadata && format == .pcapng && context.sourceIsPcapng,
                compressesWithGzip: accessory.compressesWithGzip
            )
        )
    }

    // MARK: NSOpenSavePanelDelegate

    @available(macOS 15.0, *)
    func panel(_ sender: Any, didSelect type: UTType?) {
        guard let panel = sender as? NSSavePanel else {
            return
        }
        accessory.systemFormat = type == Self.pcapType ? .pcap : .pcapng
        syncContentTypes(panel)
    }

    @available(macOS 15.0, *)
    func panel(_: Any, displayNameFor type: UTType) -> String? {
        if type == Self.pcapType {
            return context.pcapUnavailableReason.map { "\(FrameExportFormat.pcap.title) — \($0)" } ?? FrameExportFormat
                .pcap.title
        }
        if type == Self.pcapngType {
            return FrameExportFormat.pcapng.title
        }
        return nil
    }

    func panel(_ sender: Any, validate url: URL) throws {
        // PCAP is refused at the panel when the source proves it unrepresentable,
        // so the user is not told after a long export.
        if currentFormat(sender as? NSSavePanel) == .pcap, let reason = context.pcapUnavailableReason {
            throw NSError(
                domain: "com.amunx.tracexy.export", code: 1,
                userInfo: [NSLocalizedDescriptionKey: reason]
            )
        }
        _ = url
    }

    // MARK: Private

    private static let pcapType = UTType(filenameExtension: "pcap") ?? .data
    private static let pcapngType = UTType(filenameExtension: "pcapng") ?? .data
    private static let gzipType = UTType.gzip

    private let context: Context
    private let accessory: FrameExportAccessoryView

    private func currentFormat(_ panel: NSSavePanel?) -> FrameExportFormat {
        if #available(macOS 15.0, *), let panel, panel.showsContentTypes {
            if accessory.compressesWithGzip {
                return accessory.systemFormat
            }
            return panel.currentContentType == Self.pcapType ? .pcap : .pcapng
        }
        return accessory.selectedFormat
    }

    /// Keep the panel's content types and name extension in step with gzip and
    /// format choices. The SDK allows `allowedContentTypes` to change while the
    /// panel runs.
    private func syncContentTypes(_ panel: NSSavePanel) {
        let format = currentFormat(panel)
        let base = URL(fileURLWithPath: panel.nameFieldStringValue)
        var stem = base.lastPathComponent
        for ext in ["gz", "pcapng", "pcap"] where stem.lowercased().hasSuffix(".\(ext)") {
            stem = String(stem.dropLast(ext.count + 1))
        }
        if accessory.compressesWithGzip {
            panel.allowedContentTypes = [Self.gzipType]
            panel.nameFieldStringValue = "\(stem).\(format.fileExtension)"
        } else {
            panel.allowedContentTypes = [Self.pcapngType, Self.pcapType]
            if #available(macOS 15.0, *), panel.showsContentTypes {
                panel.currentContentType = format == .pcap ? Self.pcapType : Self.pcapngType
            }
            panel.nameFieldStringValue = stem
        }
        accessory.refreshEstimate(format: format)
    }
}

// MARK: - FrameExportAccessoryView

@MainActor
final class FrameExportAccessoryView: NSView {
    // MARK: Lifecycle

    init(context: FrameExportPanel.Context) {
        self.context = context
        super.init(frame: NSRect(x: 0, y: 0, width: 480, height: 150))

        scopePopUp.addItems(withTitles: context.scopes.map(\.title))
        scopePopUp.selectItem(at: min(max(context.initialScopeIndex, 0), max(context.scopes.count - 1, 0)))
        scopePopUp.target = self
        scopePopUp.action = #selector(controlChanged)
        scopePopUp.setAccessibilityLabel(String(localized: "Scope"))

        formatPopUp.addItems(withTitles: FrameExportFormat.allCases.map(\.title))
        formatPopUp.selectItem(at: 0)
        formatPopUp.target = self
        formatPopUp.action = #selector(controlChanged)
        formatPopUp.setAccessibilityLabel(String(localized: "Format"))
        if let reason = context.pcapUnavailableReason, let item = formatPopUp.item(at: 1) {
            item.isEnabled = false
            item.toolTip = reason
        }

        preserveCheckbox.state = context.sourceIsPcapng ? .on : .off
        preserveCheckbox.isEnabled = context.sourceIsPcapng
        preserveCheckbox.toolTip = context.sourceIsPcapng
            ?
            String(
                localized: "Copy section and interface names, descriptions, filters and frame comments from the source."
            )
            : String(localized: "The source is a classic PCAP, which carries no capture metadata.")
        preserveCheckbox.target = self
        preserveCheckbox.action = #selector(controlChanged)
        gzipCheckbox.target = self
        gzipCheckbox.action = #selector(controlChanged)

        estimateLabel.textColor = .secondaryLabelColor
        estimateLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        estimateLabel.setAccessibilityLabel(String(localized: "Estimate"))

        let scopeLabel = NSTextField(labelWithString: String(localized: "Scope:"))
        scopeLabel.alignment = .right
        formatLabel.alignment = .right
        let optionsLabel = NSTextField(labelWithString: String(localized: "Options:"))
        optionsLabel.alignment = .right
        let stack = NSStackView(views: [preserveCheckbox, gzipCheckbox])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4

        for picker in [startPicker, endPicker] {
            picker.datePickerStyle = .textFieldAndStepper
            picker.datePickerElements = [.yearMonthDay, .hourMinuteSecond]
            picker.target = self
            picker.action = #selector(controlChanged)
            if let bounds = context.timeBounds {
                picker.minDate = bounds.lowerBound
                picker.maxDate = bounds.upperBound
            }
        }
        startPicker.dateValue = context.timeBounds?.lowerBound ?? Date()
        endPicker.dateValue = context.timeBounds?.upperBound ?? Date()
        startPicker.setAccessibilityLabel(String(localized: "From"))
        endPicker.setAccessibilityLabel(String(localized: "To"))
        let rangeStack = NSStackView(views: [
            NSTextField(labelWithString: String(localized: "From")), startPicker,
            NSTextField(labelWithString: String(localized: "to")), endPicker,
        ])
        rangeStack.orientation = .horizontal
        rangeStack.spacing = 6
        let rangeLabel = NSTextField(labelWithString: String(localized: "Time range:"))
        rangeLabel.alignment = .right

        grid = NSGridView(views: [
            [scopeLabel, scopePopUp],
            [rangeLabel, rangeStack],
            [formatLabel, formatPopUp],
            [optionsLabel, stack],
            [NSGridCell.emptyContentView, estimateLabel],
        ])
        grid.rowSpacing = 6
        grid.columnSpacing = 8
        grid.column(at: 0).xPlacement = .trailing
        grid.column(at: 1).width = 300
        grid.translatesAutoresizingMaskIntoConstraints = false
        addSubview(grid)
        NSLayoutConstraint.activate([
            grid.topAnchor.constraint(equalTo: topAnchor, constant: 8),
            grid.centerXAnchor.constraint(equalTo: centerXAnchor),
            grid.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -8),
        ])
        updateTimeRangeVisibility()
        refreshEstimate(format: .pcapng)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        nil
    }

    // MARK: Internal

    var onChange: (() -> Void)?
    /// The format chosen through the system pop-up (macOS 15+), mirrored here so
    /// the gzip name extension follows it.
    var systemFormat: FrameExportFormat = .pcapng

    var showsFormatControl = true {
        didSet {
            grid.row(at: 2).isHidden = !showsFormatControl
        }
    }

    var selectedScope: FrameExportScope {
        let choice = context.scopes[max(0, min(scopePopUp.indexOfSelectedItem, context.scopes.count - 1))]
        if case .timeRange = choice.scope {
            let start = min(startPicker.dateValue, endPicker.dateValue)
            let end = max(startPicker.dateValue, endPicker.dateValue)
            return .timeRange(start: start, end: end)
        }
        return choice.scope
    }

    var selectedFormat: FrameExportFormat {
        showsFormatControl ? (formatPopUp.indexOfSelectedItem == 1 ? .pcap : .pcapng) : systemFormat
    }

    var preservesMetadata: Bool {
        preserveCheckbox.state == .on
    }

    var compressesWithGzip: Bool {
        gzipCheckbox.state == .on
    }

    func refreshEstimate(format: FrameExportFormat) {
        preserveCheckbox.isEnabled = context.sourceIsPcapng && format == .pcapng
        let choice = context.scopes[max(0, min(scopePopUp.indexOfSelectedItem, context.scopes.count - 1))]
        if let frames = choice.frameEstimate {
            let bytes = Int64(frames) * Int64(context.averageFrameBytes + (format == .pcap ? 16 : 32))
            let size = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
            estimateLabel.stringValue = String(localized: "≈ \(frames.formatted()) frames · ≈ \(size)")
        } else {
            estimateLabel.stringValue = String(localized: "Frame count is determined while exporting.")
        }
    }

    // MARK: Private

    private let context: FrameExportPanel.Context
    private let scopePopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let formatPopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let formatLabel = NSTextField(labelWithString: String(localized: "Format:"))
    private let preserveCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Preserve capture metadata"), target: nil, action: nil
    )
    private let gzipCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Compress with gzip"), target: nil, action: nil
    )
    private let estimateLabel = NSTextField(labelWithString: "")
    private let startPicker = NSDatePicker()
    private let endPicker = NSDatePicker()
    private var grid: NSGridView = .init(views: [])

    private func updateTimeRangeVisibility() {
        let choice = context.scopes[max(0, min(scopePopUp.indexOfSelectedItem, context.scopes.count - 1))]
        var isRange = false
        if case .timeRange = choice.scope {
            isRange = true
        }
        grid.row(at: 1).isHidden = !isRange
    }

    @objc
    private func controlChanged() {
        updateTimeRangeVisibility()
        onChange?()
    }
}
