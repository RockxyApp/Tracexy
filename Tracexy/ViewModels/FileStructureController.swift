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
    private(set) var listedBlocks: [CaptureFileBlock] = []
    private(set) var listedBlockTitles: [String] = []
    private(set) var selectedBlockTitle: String?
    private(set) var isFilteringListedBlocks = false
    private(set) var isLoading = false
    private(set) var error: String?

    func run(from coordinator: MainContentCoordinator) {
        task?.cancel()
        filterTask?.cancel()
        filterRequestID &+= 1
        selectedBlockTitle = nil
        listedBlocks = []
        listedBlockTitles = []
        isFilteringListedBlocks = false
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
            let titles: [String] = if case let .success(structure) = outcome {
                Array(Set(structure.blocks.map(\.title))).sorted()
            } else {
                []
            }
            await self?.finish(outcome, listedBlockTitles: titles, requestID: request)
        }
    }

    func cancel() {
        task?.cancel()
        filterTask?.cancel()
        filterRequestID &+= 1
        requestID &+= 1
        isLoading = false
        isFilteringListedBlocks = false
    }

    func selectBlockTitle(_ title: String?) {
        guard selectedBlockTitle != title, let structure else {
            return
        }
        selectedBlockTitle = title
        filterTask?.cancel()
        filterRequestID &+= 1
        let request = filterRequestID
        guard let title else {
            listedBlocks = structure.blocks
            isFilteringListedBlocks = false
            filterTask = nil
            return
        }
        listedBlocks = []
        isFilteringListedBlocks = true
        filterTask = Task.detached(priority: .userInitiated) { [weak self] in
            var blocks: [CaptureFileBlock] = []
            for block in structure.blocks {
                guard !Task.isCancelled else {
                    return
                }
                if block.title == title {
                    blocks.append(block)
                }
            }
            let matchedBlocks = blocks
            await self?.finishFiltering(matchedBlocks, requestID: request)
        }
    }

    // MARK: Private

    private var task: Task<Void, Never>?
    private var filterTask: Task<Void, Never>?
    private var requestID = 0
    private var filterRequestID = 0

    private func finish(
        _ outcome: Result<CaptureFileStructure, Error>,
        listedBlockTitles: [String],
        requestID: Int
    ) {
        guard requestID == self.requestID else {
            return
        }
        isLoading = false
        switch outcome {
        case let .success(structure):
            self.structure = structure
            listedBlocks = structure.blocks
            self.listedBlockTitles = listedBlockTitles
        case let .failure(failure):
            if !(failure is CancellationError) {
                error = String(localized: "Couldn’t read the file’s structure: \(failure.localizedDescription)")
            }
        }
    }

    private func finishFiltering(_ blocks: [CaptureFileBlock], requestID: Int) {
        guard requestID == filterRequestID else {
            return
        }
        listedBlocks = blocks
        isFilteringListedBlocks = false
        filterTask = nil
    }
}
