import Observation

// MARK: - SourceFrameCommentPresentation

enum SourceFrameCommentPresentation {
    case loading
    case loaded(CaptureFrameCommentReadOutcome)
}

// MARK: - SourceFrameCommentTarget

struct SourceFrameCommentTarget: Identifiable {
    let id: UInt64
}

// MARK: - FrameSourceCommentsPresentationModel

@MainActor
@Observable
final class FrameSourceCommentsPresentationModel {
    // MARK: Internal

    private(set) var presentation: SourceFrameCommentPresentation = .loading

    var target: SourceFrameCommentTarget? {
        didSet {
            guard target == nil else {
                return
            }
            task?.cancel()
            task = nil
            requestID &+= 1
            presentation = .loading
        }
    }

    var ordinal: UInt64? {
        target?.id
    }

    func present(_ row: CaptureFrameRow, using coordinator: MainContentCoordinator) {
        task?.cancel()
        requestID &+= 1
        let request = requestID
        target = SourceFrameCommentTarget(id: row.id)
        presentation = .loading
        task = Task {
            let outcome = await coordinator.sourceFrameComments(for: row)
            guard !Task.isCancelled, request == requestID, ordinal == row.id else {
                return
            }
            presentation = .loaded(outcome)
        }
    }

    func dismiss() {
        target = nil
    }

    // MARK: Private

    private var requestID = 0
    @ObservationIgnored private var task: Task<Void, Never>?
}
