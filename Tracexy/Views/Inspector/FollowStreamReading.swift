import AppKit
import Observation
import SwiftUI

// MARK: - FollowStreamReading

/// A second reading of a followed TCP stream that the composition root may supply,
/// such as the same bytes transformed by another reader.
///
/// The Stream facet asks it for controls to draw above the transcript and for the
/// result to present in place of the bytes as captured. Without one, the facet
/// presents the captured bytes and nothing else changes. The captured result itself
/// is never replaced in the coordinator: a reading only changes what is drawn,
/// searched, opened and saved from the facet.
@MainActor
protocol FollowStreamReading: AnyObject {
    /// Change this observable revision whenever the presented bytes or provenance
    /// change. Immutable readings can use the default zero revision.
    var presentationRevision: UInt64 { get }

    /// Controls and status for `result`, drawn under the summary row, or `nil` when
    /// this reading has nothing to offer for it.
    func controls(for result: FollowStreamResult) -> AnyView?

    /// The result to present in place of `result`, or `nil` to present it as captured.
    func presentedResult(for result: FollowStreamResult) -> FollowStreamResult?
}

extension FollowStreamReading {
    var presentationRevision: UInt64 {
        0
    }
}

// MARK: - FollowStreamReadings

/// Where the composition root installs its reading, once, before the first window
/// opens. The app has one workspace coordinator, so it has one reading. Held weakly:
/// the composition root owns it. `nil` presents every stream as captured.
@MainActor
enum FollowStreamReadings {
    static weak var installed: (any FollowStreamReading)?
}

// MARK: - FollowStreamExportKey

nonisolated struct FollowStreamExportKey: Hashable, Sendable {
    let projectID: UUID
    let workspaceID: UUID
    let generation: Int
    let requestID: Int
    let sessionID: UUID
    let identity: PcapFileIdentity
    let readingID: ObjectIdentifier?
    let readingRevision: UInt64
}

// MARK: - FollowStreamExportPreparation

/// One view's bounded export cache and explicit-action work. The view also checks
/// its current scope before presenting or writing a prepared result.
@MainActor @Observable
final class FollowStreamExportPreparation {
    // MARK: Internal

    private(set) var key: FollowStreamExportKey?
    private(set) var snapshot: FollowStreamExportSnapshot?
    private(set) var error: String?
    private(set) var isPreparing = false
    private(set) var isPerformingAction = false

    func prepare(_ result: FollowStreamResult?, key: FollowStreamExportKey?) async {
        guard !Task.isCancelled else {
            return
        }
        preparationID &+= 1
        let requestID = preparationID
        cancelAction()
        self.key = key
        snapshot = nil
        error = nil
        isPreparing = result != nil && key != nil
        guard let result, key != nil else {
            return
        }
        let worker = Task.detached(priority: .userInitiated) {
            try FollowStreamExport.snapshot(of: result, checkingCancellation: { !Task.isCancelled })
        }
        do {
            let prepared = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            guard requestID == preparationID, !Task.isCancelled else {
                return
            }
            snapshot = prepared
            isPreparing = false
        } catch {
            guard requestID == preparationID else {
                return
            }
            isPreparing = false
            if !(error is CancellationError) {
                self.error = String(localized: "Couldn’t prepare this stream for export: \(error.localizedDescription)")
            }
        }
    }

    func perform<Value: Sendable>(
        key: FollowStreamExportKey,
        isCurrent: @escaping @MainActor () -> Bool,
        operation: @escaping @Sendable () throws -> Value,
        completion: @escaping @MainActor (Value) async throws -> Void,
        failure: @escaping @MainActor (Error) -> Void
    ) {
        guard self.key == key, snapshot != nil, !isPerformingAction, isCurrent() else {
            return
        }
        actionID &+= 1
        let requestID = actionID
        isPerformingAction = true
        action = Task {
            defer {
                if requestID == actionID {
                    isPerformingAction = false
                    action = nil
                }
            }
            let worker = Task.detached(priority: .userInitiated) {
                try Task.checkCancellation()
                let value = try operation()
                try Task.checkCancellation()
                return value
            }
            do {
                let value = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
                guard requestID == actionID, !Task.isCancelled, self.key == key, isCurrent() else {
                    return
                }
                try await completion(value)
            } catch {
                if requestID == actionID, !Task.isCancelled, self.key == key, isCurrent(),
                   !(error is CancellationError)
                {
                    failure(error)
                }
            }
        }
    }

    func cancel() {
        preparationID &+= 1
        cancelAction()
        key = nil
        snapshot = nil
        error = nil
        isPreparing = false
    }

    // MARK: Private

    @ObservationIgnored private var preparationID = 0
    @ObservationIgnored private var actionID = 0
    @ObservationIgnored private var action: Task<Void, Never>?

    private func cancelAction() {
        actionID &+= 1
        action?.cancel()
        action = nil
        isPerformingAction = false
    }
}

// MARK: - FollowStreamExportMenus

struct FollowStreamExportMenus: View {
    // MARK: Internal

    let snapshot: FollowStreamExportSnapshot
    let tuple: FiveTuple
    let onSave: (FollowStreamExport.Format, FollowStreamExport.Side) -> Void
    let onCopy: (FollowStreamExport.Format) -> Void
    let onPrint: (FollowStreamExport.Format, FollowStreamExport.Side) -> Void

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Menu("Save Stream") {
                ForEach(FollowStreamExport.Side.allCases) { side in
                    Section(sideTitle(side)) {
                        ForEach(FollowStreamExport.Format.allCases) { format in
                            Button(String(localized: "\(format.title)…")) { onSave(format, side) }
                                .disabled(!canExport(side))
                        }
                    }
                }
                Divider()
                ForEach([FollowStreamExport.Format.cArrays, .yaml, .hexDump], id: \.self) { format in
                    Button(String(localized: "Copy as \(format.title)")) { onCopy(format) }
                        .disabled(!canExport(.both))
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .controlSize(.small)
            .help("Save one direction in TCP sequence order, or both directions when their capture order is known")
            Menu("Print Stream") {
                ForEach(FollowStreamExport.Side.allCases) { side in
                    Menu(sideTitle(side)) {
                        ForEach(FollowStreamExport.Format.allCases) { format in
                            Button(String(localized: "Print as \(printTitle(format))…")) { onPrint(format, side) }
                        }
                    }
                    .disabled(!canExport(side))
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .controlSize(.small)
            .help("Print the already-loaded stream snapshot in a selected direction and format")
        }
    }

    // MARK: Private

    private func canExport(_ side: FollowStreamExport.Side) -> Bool {
        let hasBytes = switch side {
        case .both: !snapshot.aToBChunks.isEmpty || !snapshot.bToAChunks.isEmpty
        case .aToB: !snapshot.aToBChunks.isEmpty
        case .bToA: !snapshot.bToAChunks.isEmpty
        }
        return hasBytes && snapshot.canExport(side: side)
    }

    private func sideTitle(_ side: FollowStreamExport.Side) -> String {
        switch side {
        case .both: String(localized: "Both Directions")
        case .aToB: "\(tuple.a.display) → \(tuple.b.display)"
        case .bToA: "\(tuple.b.display) → \(tuple.a.display)"
        }
    }

    private func printTitle(_ format: FollowStreamExport.Format) -> String {
        format == .raw ? String(localized: "Raw Bytes as Hex Dump") : format.title
    }
}

// MARK: - FollowStreamPrintPanel

@MainActor
enum FollowStreamPrintPanel {
    /// Check the originating stream again after each modal panel's nested run loop.
    /// A cancelled panel or retired scope produces no error and no print operation.
    static func run(_ printedText: String, isCurrent: () -> Bool) -> String? {
        guard isCurrent() else {
            return nil
        }
        let confirmation = NSAlert()
        confirmation.messageText = String(localized: "Print application data?")
        confirmation.informativeText = String(localized: """
        The selected TCP transcript can contain credentials or personal information.
        The print panel may send it to a printer or save it as a PDF.
        Review the selected direction and format before continuing.
        """)
        confirmation.addButton(withTitle: String(localized: "Continue to Print"))
        confirmation.addButton(withTitle: String(localized: "Cancel"))
        guard confirmation.runModal() == .alertFirstButtonReturn, isCurrent() else {
            return nil
        }
        let panel = NSPrintPanel()
        guard panel.runModal(with: NSPrintInfo.shared) != NSCancelButton, isCurrent() else {
            return nil
        }
        let printInfo = panel.printInfo
        let bounds = printInfo.imageablePageBounds
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: max(1, bounds.width), height: 1))
        view.string = printedText.trimmingCharacters(in: .newlines)
        view.isEditable = false
        view.font = NSFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        view.textContainer?.widthTracksTextView = true
        view.textContainer?.heightTracksTextView = false
        view.textContainer?.containerSize = NSSize(width: view.bounds.width, height: .greatestFiniteMagnitude)
        if let layoutManager = view.layoutManager, let textContainer = view.textContainer {
            layoutManager.ensureLayout(for: textContainer)
            let contentHeight = ceil(layoutManager.usedRect(for: textContainer).height)
                + view.textContainerInset.height * 2
            guard contentHeight <= 500 * max(1, bounds.height) else {
                return String(localized: "This stream exceeds the print layout limit. Save it to a file instead.")
            }
            view.setFrameSize(NSSize(width: max(1, bounds.width), height: max(1, contentHeight)))
        }
        let operation = NSPrintOperation(view: view, printInfo: printInfo)
        operation.showsPrintPanel = false
        return operation.run() ? nil : String(localized: "The stream was not printed.")
    }
}
