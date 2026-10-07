import Foundation
import Observation

// MARK: - FileStructureController

/// File ▸ Show File Structure: the open capture's pcapng blocks or pcap records, read
/// off the main actor from the same stable sources All Frames rescans.
@MainActor
@Observable
final class FileStructureController {
    // MARK: Lifecycle

    /// The window uses ``shared``; tests make their own.
    init() {}

    // MARK: Internal

    static let shared = FileStructureController()

    private(set) var structure: CaptureFileStructure?
    private(set) var isLoading = false
    private(set) var error: String?

    func run(from coordinator: MainContentCoordinator) {
        task?.cancel()
        requestID &+= 1
        structure = nil
        error = nil
        if let reason = coordinator.allFramesUnavailableReason {
            isLoading = false
            error = reason
            return
        }
        let request = requestID
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        isLoading = true
        task = Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-structure-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let outcome: Result<CaptureFileStructure, Error>
            do {
                let source = try await MainContentCoordinator.frameToolSource(
                    savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
                )
                outcome = try .success(CaptureFileStructure.read(contentsOf: source.url))
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

    private func finish(_ outcome: Result<CaptureFileStructure, Error>, requestID: Int) {
        guard requestID == self.requestID else {
            return
        }
        isLoading = false
        switch outcome {
        case let .success(structure):
            self.structure = structure
        case let .failure(failure):
            if !(failure is CancellationError) {
                error = String(localized: "Couldn’t read the file’s structure: \(failure.localizedDescription)")
            }
        }
    }
}
