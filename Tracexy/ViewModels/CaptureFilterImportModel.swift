import AppKit
import Foundation
import Observation

// MARK: - CaptureFilterListRead

/// The injectable read step behind the capture-filter import sheet. The default
/// is the real one: a detached worker running the bounded `CaptureFilterList`
/// reader, wrapped so parent cancellation reaches the worker rather than only
/// abandoning the await. Tests substitute a body, never the coordination.
nonisolated struct CaptureFilterListRead: Sendable {
    static let file = Self { url in
        let worker = Task.detached(priority: .userInitiated) {
            try Task.checkCancellation()
            return try CaptureFilterList.load(from: url)
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    var run: @Sendable (URL) async throws -> [NamedCaptureFilter]
}

// MARK: - CaptureFilterImportModel

/// Read coordinator for the Settings capture-filter import sheet.
///
/// It owns one bounded read at a time and nothing else: it writes no
/// preference, starts no capture, and never retains the chosen file URL beyond
/// the read that used it — only the parsed, bounded entries. Every publication
/// is guarded by a monotonic request ID and an explicit lifecycle flag, so a
/// file chooser or worker that returns after the sheet closed (including after
/// the Settings window remounted on a different Project) can neither show a
/// list nor make an expression applicable.
///
/// Parsing is not compilation: a selected expression is a candidate BPF string,
/// and the existing capture backend is still what validates it at capture start.
@MainActor
@Observable
final class CaptureFilterImportModel {
    // MARK: Lifecycle

    init(read: CaptureFilterListRead = .file) {
        self.read = read
    }

    // MARK: Internal

    enum Phase: Equatable {
        case idle
        case loading
        case loaded
        case failed(String)
    }

    /// Which entry the list has selected. Selection on its own applies nothing.
    var selectedFilterID: NamedCaptureFilter.ID?

    private(set) var phase: Phase = .idle
    private(set) var filters: [NamedCaptureFilter] = []
    private(set) var sourceName: String?

    var isLoading: Bool {
        phase == .loading
    }

    var errorMessage: String? {
        if case let .failed(message) = phase {
            message
        } else {
            nil
        }
    }

    var selectedFilter: NamedCaptureFilter? {
        filters.first { $0.id == selectedFilterID }
    }

    /// The one gate the sheet's Use Filter control reads. False while inactive,
    /// loading, failed, or with nothing selected.
    var canApply: Bool {
        isActive && phase == .loaded && selectedFilter != nil
    }

    /// Wireshark keeps display filters, coloring rules, preferences and recent
    /// state in separate files with different formats. Naming the mistake beats
    /// letting the parser reject the file with a line number nobody can act on.
    static func rejectionMessage(forFileNamed name: String) -> String? {
        guard let contents = unsupportedFileContents[name.lowercased()] else {
            return nil
        }
        return "“\(name)” contains \(contents), not capture filters. "
            + "Choose a capture-filter list such as “cfilters”."
    }

    /// Explicit chooser. No content-type gate, because a capture-filter list is
    /// normally extensionless; the reader is what enforces regular-file, size,
    /// text and format bounds.
    func chooseFile() {
        guard isActive, !isLoading else {
            return
        }
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.prompt = String(localized: "Choose")
        panel.message = String(
            localized: "Choose a capture-filter list, such as “cfilters”. Display filters, coloring rules and preferences are different files."
        )
        let response = panel.runModal()
        // The sheet can go away while the chooser is open. A late OK must not
        // start a read for a sheet — or a Project — that is already gone.
        guard isActive, response == .OK, let url = panel.url else {
            return
        }
        load(from: url)
    }

    /// Starts a bounded read of `url`. Nothing is applied and no preference is
    /// touched here; a successful read only makes a selection possible.
    func load(from url: URL) {
        guard isActive else {
            return
        }
        let name = url.lastPathComponent
        // Invalidate first: a file rejected by name must also retire whatever
        // read is already in flight, not just refuse this one.
        invalidateReads()
        resetList()
        sourceName = name
        if let refusal = Self.rejectionMessage(forFileNamed: name) {
            phase = .failed(refusal)
            return
        }
        let requestID = self.requestID
        let read = self.read
        phase = .loading
        reads[requestID] = Task { @MainActor [weak self] in
            // Security scope covers the worker's read and is released before any
            // state is published, so no scope outlives the read that needed it.
            let scoped = url.startAccessingSecurityScopedResource()
            var loaded: [NamedCaptureFilter] = []
            var failure: String?
            var cancelled = false
            do {
                loaded = try await read.run(url)
            } catch is CancellationError {
                cancelled = true
            } catch {
                failure = "Couldn’t read “\(name)”: \(error.localizedDescription)"
            }
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
            guard let self else {
                return
            }
            self.reads[requestID] = nil
            guard self.isActive, self.requestID == requestID else {
                return
            }
            if cancelled || Task.isCancelled {
                self.resetList()
                return
            }
            if let failure {
                self.phase = .failed(failure)
                return
            }
            self.filters = loaded
            self.phase = .loaded
        }
    }

    /// Explicit cancellation of an in-flight read. Preferences and any running
    /// capture are untouched.
    func cancelRead() {
        guard isLoading else {
            return
        }
        invalidateReads()
        resetList()
    }

    /// Called when the sheet disappears. After this the model is inert: a
    /// chooser or worker that returns late can neither publish a list nor make
    /// an expression applicable.
    func deactivate() {
        isActive = false
        invalidateReads()
        resetList()
    }

    /// The expression the sheet is allowed to apply, or `nil`. Gating the apply
    /// path on one accessor keeps an inactive, loading or failed model from ever
    /// writing a preference.
    func applicableExpression() -> String? {
        guard canApply else {
            return nil
        }
        return selectedFilter?.expression
    }

    /// Awaits every outstanding read exactly, so cancellation and supersession
    /// are observable without polling or sleeping.
    func waitForReads() async {
        for task in Array(reads.values) {
            await task.value
        }
    }

    // MARK: Private

    private static let unsupportedFileContents = [
        "dfilters": String(localized: "display filters"),
        "dfilter_buttons": String(localized: "display-filter buttons"),
        "colorfilters": String(localized: "coloring rules"),
        "preferences": String(localized: "application preferences"),
        "recent": String(localized: "recently used view state"),
        "disabled_protos": String(localized: "disabled protocols"),
    ]

    private let read: CaptureFilterListRead

    private var isActive = true
    private var requestID = 0
    private var reads: [Int: Task<Void, Never>] = [:]

    private func resetList() {
        filters = []
        selectedFilterID = nil
        sourceName = nil
        phase = .idle
    }

    private func invalidateReads() {
        requestID &+= 1
        for task in reads.values {
            task.cancel()
        }
    }
}
