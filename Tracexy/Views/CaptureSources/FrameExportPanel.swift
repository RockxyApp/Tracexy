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
        /// Notes written about this capture; the "include notes" option shows only
        /// when there are some.
        var noteCount = 0
        /// Address names known for this capture; "Include address names" shows only
        /// when there are some.
        var nameCount = 0
    }

    struct Choice {
        let url: URL
        let scope: FrameExportScope
        let options: FrameExportOptions
        /// Write the notes on the exported sessions as PCAPNG capture comments.
        var includesNotes = false
        /// Write the known address names as a PCAPNG Name Resolution Block.
        var includesNames = false
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
                preservesMetadata: accessory.preservesMetadata && format == .pcapng && context.sourceIsPcapng
                    && !accessory.anonymizesAddresses,
                compressesWithGzip: accessory.compressesWithGzip,
                anonymizesAddresses: accessory.anonymizesAddresses,
                stripsHeaders: accessory.stripsHeaders,
                removesDuplicates: accessory.removesDuplicates,
                truncatesTo: accessory.truncatesTo,
                shiftsTimeBy: accessory.shiftsTimeBy
            ),
            includesNotes: accessory.includesNotes && format == .pcapng && !accessory.anonymizesAddresses,
            includesNames: accessory.includesNames && format == .pcapng && !accessory.anonymizesAddresses
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

    private let context: Context
    private let accessory: FrameExportAccessoryView

    private func currentFormat(_ panel: NSSavePanel?) -> FrameExportFormat {
        if #available(macOS 15.0, *), let panel, panel.showsContentTypes, !accessory.showsFormatControl {
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
        // A second pass strips ".pcapng.gz" / ".pcap.gz" back to the stem.
        for ext in ["pcapng", "pcap"] where stem.lowercased().hasSuffix(".\(ext)") {
            stem = String(stem.dropLast(ext.count + 1))
        }
        if accessory.compressesWithGzip {
            // With one allowed type the system pop-up disappears, so the format
            // choice moves into the accessory while gzip is on.
            // No content-type gate while gzip is on: the panel would otherwise
            // replace ".pcapng" with ".gz" instead of appending it. The exporter
            // writes a gzip member whatever the name says.
            panel.allowedContentTypes = []
            panel.nameFieldStringValue = "\(stem).\(format.fileExtension).gz"
            if !accessory.showsFormatControl {
                accessory.selectFormat(accessory.systemFormat)
                accessory.showsFormatControl = true
                accessory.formatControlIsGzipFallback = true
            }
        } else {
            if accessory.formatControlIsGzipFallback {
                accessory.systemFormat = accessory.selectedFormat
                accessory.showsFormatControl = false
                accessory.formatControlIsGzipFallback = false
            }
            panel.allowedContentTypes = [Self.pcapngType, Self.pcapType]
            if #available(macOS 15.0, *), panel.showsContentTypes {
                panel.currentContentType = accessory.systemFormat == .pcap ? Self.pcapType : Self.pcapngType
            }
            panel.nameFieldStringValue = stem
        }
        accessory.refreshEstimate(format: currentFormat(panel))
    }
}

// MARK: - FrameExportAccessoryView

@MainActor
final class FrameExportAccessoryView: NSView {
    // MARK: Lifecycle

    init(context: FrameExportPanel.Context) {
        self.context = context
        super.init(frame: NSRect(x: 0, y: 0, width: 480, height: 172))

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
        notesCheckbox.state = context.noteCount > 0 ? .on : .off
        notesCheckbox.isHidden = context.noteCount == 0
        notesCheckbox.toolTip = String(
            localized: """
            Write your notes on the exported sessions as capture comments (Wireshark: Capture File Properties) \
            and your frame comments on their frames (Wireshark: packet comments).
            """
        )
        notesCheckbox.target = self
        notesCheckbox.action = #selector(controlChanged)
        anonymizeCheckbox.state = .off
        anonymizeCheckbox.toolTip = String(
            localized: """
            Replace MAC, IPv4 and IPv6 addresses in packet headers with consistent stand-ins. \
            Payloads such as DNS answers, HTTP headers and TLS server names are not changed.
            """
        )
        anonymizeCheckbox.target = self
        anonymizeCheckbox.action = #selector(controlChanged)
        headersPopUp.addItems(withTitles: [
            String(localized: "Keep every header"),
            String(localized: "Strip to the inner IP packet"),
            String(localized: "Strip to the inner Ethernet frame"),
        ])
        headersPopUp.selectItem(at: 0)
        headersPopUp.toolTip = String(
            localized: """
            As Wireshark's Strip Headers: write each frame from its innermost IP header (as raw IP), or from the \
            Ethernet frame a VXLAN or GRE tunnel carries. Frames without that inner packet are left out and counted.
            """
        )
        headersPopUp.setAccessibilityLabel(String(localized: "Headers"))
        headersPopUp.target = self
        headersPopUp.action = #selector(controlChanged)
        namesCheckbox.state = context.nameCount > 0 ? .on : .off
        namesCheckbox.isHidden = context.nameCount == 0
        namesCheckbox.toolTip = String(
            localized: """
            Write the names this capture's DNS answers gave its addresses, and the names you gave them, into the \
            PCAPNG file (a Name Resolution Block), so Wireshark shows the same names.
            """
        )
        namesCheckbox.target = self
        namesCheckbox.action = #selector(controlChanged)
        duplicatesCheckbox.state = .off
        duplicatesCheckbox.toolTip = String(
            localized: "As editcap -d: leave out a frame whose bytes match one of the five frames before it exactly."
        )
        truncateCheckbox.state = .off
        truncateCheckbox.toolTip = String(
            localized: "As editcap -s: keep only the first bytes of each frame; the original length is kept."
        )
        truncateCheckbox.target = self
        truncateCheckbox.action = #selector(controlChanged)
        truncateField.integerValue = 128
        truncateField.formatter = {
            let formatter = NumberFormatter()
            formatter.minimum = NSNumber(value: FrameExportOptions.truncationRange.lowerBound)
            formatter.maximum = NSNumber(value: FrameExportOptions.truncationRange.upperBound)
            formatter.allowsFloats = false
            return formatter
        }()
        truncateField.setAccessibilityLabel(String(localized: "Bytes to keep of each frame"))
        truncateField.widthAnchor.constraint(equalToConstant: 72).isActive = true

        estimateLabel.textColor = .secondaryLabelColor
        estimateLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        estimateLabel.setAccessibilityLabel(String(localized: "Estimate"))

        let scopeLabel = NSTextField(labelWithString: String(localized: "Scope:"))
        scopeLabel.alignment = .right
        formatLabel.alignment = .right
        let optionsLabel = NSTextField(labelWithString: String(localized: "Options:"))
        optionsLabel.alignment = .right
        let headersLabel = NSTextField(labelWithString: String(localized: "Headers:"))
        headersLabel.alignment = .right
        let truncateRow = NSStackView(views: [
            truncateCheckbox, truncateField, NSTextField(labelWithString: String(localized: "bytes per frame")),
        ])
        truncateRow.orientation = .horizontal
        truncateRow.spacing = 6
        let shiftRow = makeShiftRow()
        let stack = NSStackView(views: [
            preserveCheckbox, notesCheckbox, namesCheckbox, anonymizeCheckbox, duplicatesCheckbox, truncateRow,
            shiftRow, gzipCheckbox,
        ])
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
            [headersLabel, headersPopUp],
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

    /// True while the accessory pop-up stands in for the hidden system pop-up
    /// (gzip on, macOS 15+).
    var formatControlIsGzipFallback = false

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
        guard showsFormatControl else {
            return systemFormat
        }
        let chosen: FrameExportFormat = formatPopUp.indexOfSelectedItem == 1 ? .pcap : .pcapng
        // A disabled PCAP item cannot be chosen; a stale selection falls back.
        return chosen == .pcap && context.pcapUnavailableReason != nil ? .pcapng : chosen
    }

    var preservesMetadata: Bool {
        preserveCheckbox.state == .on
    }

    var compressesWithGzip: Bool {
        gzipCheckbox.state == .on
    }

    var includesNotes: Bool {
        !notesCheckbox.isHidden && notesCheckbox.state == .on
    }

    /// The Headers pop-up: `nil` keeps every header.
    var stripsHeaders: FrameHeaderStrip? {
        switch headersPopUp.indexOfSelectedItem {
        case 1: .innerIP
        case 2: .innerEthernet
        default: nil
        }
    }

    var includesNames: Bool {
        !namesCheckbox.isHidden && namesCheckbox.state == .on
    }

    var removesDuplicates: Bool {
        duplicatesCheckbox.state == .on
    }

    /// The byte limit when "Keep at most" is on.
    var truncatesTo: Int? {
        truncateCheckbox.state == .on ? truncateField.integerValue : nil
    }

    var anonymizesAddresses: Bool {
        anonymizeCheckbox.state == .on
    }

    /// Seconds added to every frame's time when "Shift times by" is on.
    var shiftsTimeBy: TimeInterval {
        shiftCheckbox.state == .on && shiftField.doubleValue.isFinite ? shiftField.doubleValue : 0
    }

    func selectFormat(_ format: FrameExportFormat) {
        formatPopUp.selectItem(at: format == .pcap ? 1 : 0)
    }

    func refreshEstimate(format: FrameExportFormat) {
        // Replacing addresses leaves out copied metadata and notes, which can name
        // hosts too; the boxes say so by turning off.
        preserveCheckbox.isEnabled = context.sourceIsPcapng && format == .pcapng && !anonymizesAddresses
        notesCheckbox.isEnabled = format == .pcapng && !anonymizesAddresses
        namesCheckbox.isEnabled = format == .pcapng && !anonymizesAddresses
        truncateField.isEnabled = truncateCheckbox.state == .on
        shiftField.isEnabled = shiftCheckbox.state == .on
        let choice = context.scopes[max(0, min(scopePopUp.indexOfSelectedItem, context.scopes.count - 1))]
        if let frames = choice.frameEstimate {
            let bytes = Int64(frames) * Int64(context.averageFrameBytes + (format == .pcap ? 16 : 32))
            let size = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
            estimateLabel.stringValue = String(localized: "≈ \(frames.formatted()) frames, ≈ \(size)")
        } else {
            estimateLabel.stringValue = String(localized: "Frame count is determined while exporting.")
        }
    }

    // MARK: Private

    private let context: FrameExportPanel.Context
    private let scopePopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let formatPopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let headersPopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let namesCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Include address names"), target: nil, action: nil
    )
    private let duplicatesCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Remove duplicate frames"), target: nil, action: nil
    )
    private let truncateCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Keep at most"), target: nil, action: nil
    )
    private let truncateField = NSTextField()
    private let shiftCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Shift times by"), target: nil, action: nil
    )
    private let shiftField = NSTextField()
    private let formatLabel = NSTextField(labelWithString: String(localized: "Format:"))
    private let preserveCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Preserve capture metadata"), target: nil, action: nil
    )
    private let gzipCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Compress with gzip"), target: nil, action: nil
    )
    private let notesCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Include my notes and frame comments"), target: nil, action: nil
    )
    private let anonymizeCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Replace addresses"), target: nil, action: nil
    )
    private let estimateLabel = NSTextField(labelWithString: "")
    private let startPicker = NSDatePicker()
    private let endPicker = NSDatePicker()
    private var grid: NSGridView = .init(views: [])

    /// "Shift times by [n] seconds": editcap `-t` and Wireshark's Time Shift.
    private func makeShiftRow() -> NSStackView {
        shiftCheckbox.state = .off
        shiftCheckbox.toolTip = String(
            localized: "As editcap -t and Wireshark's Time Shift: move every frame's time by this many seconds."
        )
        shiftCheckbox.target = self
        shiftCheckbox.action = #selector(controlChanged)
        shiftField.doubleValue = 0
        shiftField.formatter = {
            let formatter = NumberFormatter()
            formatter.numberStyle = .decimal
            formatter.maximumFractionDigits = 6
            formatter.minimum = -3_153_600_000
            formatter.maximum = 3_153_600_000
            return formatter
        }()
        shiftField.setAccessibilityLabel(String(localized: "Seconds to shift each frame's time by"))
        shiftField.widthAnchor.constraint(equalToConstant: 96).isActive = true
        // Neither checkbox title may be clipped to make room for its field.
        for checkbox in [truncateCheckbox, shiftCheckbox] {
            checkbox.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        let row = NSStackView(views: [
            shiftCheckbox, shiftField, NSTextField(labelWithString: String(localized: "seconds")),
        ])
        row.orientation = .horizontal
        row.spacing = 6
        return row
    }

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
