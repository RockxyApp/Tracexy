import Foundation
import Observation

// MARK: - FieldPlotController

/// Statistics ▸ Plot: one decode-tree field's numeric values over time, read off the
/// main actor from the same stable sources All Frames rescans (Wireshark's Plots).
@MainActor
@Observable
final class FieldPlotController {
    // MARK: Lifecycle

    /// The window uses ``shared``; tests make their own.
    init() {}

    // MARK: Internal

    static let shared = FieldPlotController()

    /// The field the window shows; setting it from Layers asks for a fresh count.
    var field: FieldKey?
    /// Count only the frames of the sessions the main window shows.
    var limitToSessionsInView = true
    private(set) var result: FieldPlot?
    private(set) var isLoading = false
    private(set) var error: String?

    /// Counts `field` now, replacing any count in flight.
    func run(from coordinator: MainContentCoordinator) {
        task?.cancel()
        requestID &+= 1
        result = nil
        error = nil
        guard let field else {
            isLoading = false
            return
        }
        if let reason = coordinator.allFramesUnavailableReason {
            isLoading = false
            error = reason
            return
        }
        let request = requestID
        let sessions = limitToSessionsInView ? Set(coordinator.visibleSessions.map(\.id)) : nil
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        isLoading = true
        task = Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-plot-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let outcome: Result<FieldPlot, Error>
            do {
                let source = try await MainContentCoordinator.frameToolSource(
                    savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
                )
                let scanner = try FieldValueScanner(contentsOf: source.url, expectedIdentity: source.identity)
                outcome = try .success(scanner.scanPoints(field, sessions: sessions))
            } catch {
                outcome = .failure(error)
            }
            await self?.finish(outcome, requestID: request)
        }
    }

    func cancel() {
        task?.cancel()
        requestID &+= 1
        isLoading = false
    }

    // MARK: Private

    private var task: Task<Void, Never>?
    private var requestID = 0

    private func finish(_ outcome: Result<FieldPlot, Error>, requestID: Int) {
        guard requestID == self.requestID else {
            return
        }
        isLoading = false
        switch outcome {
        case let .success(distribution):
            result = distribution
        case let .failure(failure):
            if !(failure is CancellationError) {
                error = String(localized: "Couldn’t plot the values: \(failure.localizedDescription)")
            }
        }
    }
}
