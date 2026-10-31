import SwiftUI

@MainActor
extension AllFramesWindow {
    func resolveFrameSelections() {
        resolvePendingTableSelection()
        receiveExternalSelectionRequest()
    }

    func loadAllFramesAndReceiveSelection() {
        coordinator.loadAllFrames()
        if let request = coordinator.allFrames.externalSelectionRequest {
            bindExternalSelectionToCurrentPageRequest(request)
        }
        receiveExternalSelectionRequest()
    }

    func bindExternalSelectionToCurrentPageRequest(_ request: AllFramesExternalSelectionRequest) {
        let state = coordinator.allFrames
        guard var current = state.externalSelectionRequest, current.id == request.id else {
            return
        }
        current.frameListRequestID = state.requestID
        state.externalSelectionRequest = current
    }

    func cancelExternalSelectionForManualSelection() {
        let state = coordinator.allFrames
        state.externalSelectionRequest = nil
        state.externalSelectionRequestID = nil
    }

    var interactiveFrameSelection: Binding<CaptureFrameRow.ID?> {
        Binding(
            get: { selection },
            set: { value in
                if value != selection {
                    cancelExternalSelectionForManualSelection()
                }
                selection = value
            }
        )
    }

    var frameNavigationControls: some View {
        let state = coordinator.allFrames
        let rows = state.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        return ControlGroup {
            Button("Back", systemImage: "arrow.left") {
                navigateFrameHistory(backward: true)
            }
            .help("Go to the previously selected frame")
            .disabled(
                !state.canNavigateFrameHistoryBackward || state.isLoading
                    || state.isEvaluatingFrameExpression || pendingHistoryRestoreOrdinal != nil
            )
            Button("Forward", systemImage: "arrow.right") {
                navigateFrameHistory(backward: false)
            }
            .help("Go forward to the next frame selection")
            .disabled(
                !state.canNavigateFrameHistoryForward || state.isLoading
                    || state.isEvaluatingFrameExpression || pendingHistoryRestoreOrdinal != nil
            )
            Button("First on Page", systemImage: "chevron.up.to.line") {
                selectFrameAtPageBoundary(rows, first: true)
            }
            .help("Select the first frame currently shown on this page")
            .disabled(rows.isEmpty || state.isLoading || state.isEvaluatingFrameExpression)
            Button("Last on Page", systemImage: "chevron.down.to.line") {
                selectFrameAtPageBoundary(rows, first: false)
            }
            .help("Select the last frame currently shown on this page")
            .disabled(rows.isEmpty || state.isLoading || state.isEvaluatingFrameExpression)
        }
    }

    static func frameAtPageBoundary(_ rows: [CaptureFrameRow], first: Bool) -> UInt64? {
        (first ? rows.first : rows.last)?.ordinal
    }

    func selectFrameAtPageBoundary(_ rows: [CaptureFrameRow], first: Bool) {
        guard let ordinal = Self.frameAtPageBoundary(rows, first: first) else {
            return
        }
        cancelExternalSelectionForManualSelection()
        selection = ordinal
        revealToken &+= 1
        notice = nil
    }

    func goToFrame(_ rows: [CaptureFrameRow]) {
        guard let number = UInt64(goTo.trimmingCharacters(in: .whitespaces)) else {
            notice = String(localized: "Type a frame number.")
            return
        }
        cancelExternalSelectionForManualSelection()
        if rows.contains(where: { $0.ordinal == number }) {
            selection = number
            revealToken &+= 1
            notice = nil
        } else if coordinator.allFrames.list?.rows.contains(where: { $0.ordinal == number }) == true {
            notice = String(localized: "Frame \(number.formatted()) is hidden by the current filters.")
        } else if let list = coordinator.allFrames.list, number > 0,
                  number <= UInt64(list.scannedFrameCount)
        {
            let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
            let start = ((Int(number) - 1) / pageSize) * pageSize + 1
            coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: start)
            coordinator.allFrames.pendingTableSelection = number
            notice = nil
        } else {
            notice = String(localized: "Frame \(number.formatted()) is outside this capture.")
        }
    }

    func navigateFrameHistory(backward: Bool) {
        let state = coordinator.allFrames
        guard !state.isLoading, !state.isEvaluatingFrameExpression, pendingHistoryRestoreOrdinal == nil,
              let target = state.frameHistoryDestination(backward: backward) else
        {
            return
        }
        cancelExternalSelectionForManualSelection()
        let rows = state.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        if rows.contains(where: { $0.ordinal == target }) {
            guard state.moveFrameHistoryCursor(backward: backward, to: target) else {
                return
            }
            restoreFrameSelection(target)
            revealToken &+= 1
            notice = nil
        } else if state.list?.rows.contains(where: { $0.ordinal == target }) == true {
            notice = String(localized: "Frame \(target.formatted()) is hidden by the current filters.")
        } else if let list = state.list, target > 0, target <= UInt64(list.scannedFrameCount) {
            let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
            let start = ((Int(target) - 1) / pageSize) * pageSize + 1
            coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: start)
            guard state.isLoading else {
                clearPendingHistoryNavigation(state)
                notice = state
                    .error ?? String(localized: "Couldn’t load frame \(target.formatted()) from this capture.")
                return
            }
            pendingHistoryRestoreOrdinal = target
            pendingHistoryBackward = backward
            pendingHistoryRequestID = state.requestID
            state.pendingTableSelection = target
            notice = nil
        } else {
            notice = String(localized: "Frame \(target.formatted()) is no longer available in this capture.")
        }
    }

    func resolvePendingTableSelection() {
        let state = coordinator.allFrames
        if pendingHistoryRestoreOrdinal != nil,
           !state.isLoading,
           pendingHistoryRequestID != state.requestID
        {
            clearPendingHistoryNavigation(state)
            notice = String(localized: "Frame history navigation was superseded by another frame-list request.")
        }
        guard let target = state.pendingTableSelection, !state.isLoading, !state.isEvaluatingFrameExpression else {
            return
        }
        guard state.list?.rows.contains(where: { $0.ordinal == target }) == true else {
            if pendingHistoryRestoreOrdinal == target, !state.isLoading {
                let message = state.error
                    ?? String(localized: "Frame \(target.formatted()) could not be listed from this capture page.")
                clearPendingHistoryNavigation(state)
                notice = message
            }
            return
        }
        state.pendingTableSelection = nil
        let visible = state.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        guard visible.contains(where: { $0.ordinal == target }) else {
            if pendingHistoryRestoreOrdinal == target {
                clearPendingHistoryNavigation(state)
            }
            notice = String(localized: "Frame \(target.formatted()) is hidden by the current filters.")
            return
        }
        if pendingHistoryRestoreOrdinal == target, let backward = pendingHistoryBackward {
            guard pendingHistoryRequestID == state.requestID else {
                clearPendingHistoryNavigation(state)
                notice = String(localized: "Frame history navigation was superseded by another frame-list request.")
                return
            }
            guard state.moveFrameHistoryCursor(backward: backward, to: target) else {
                clearPendingHistoryNavigation(state)
                notice = String(localized: "The frame selection history changed. Select the frame again.")
                return
            }
            clearPendingHistoryNavigation(state)
            restoreFrameSelection(target)
        }
        selection = target
        revealToken &+= 1
        notice = nil
    }

    func receiveExternalSelectionRequest() {
        guard let request = coordinator.allFrames.externalSelectionRequest else {
            return
        }
        Task { @MainActor in
            guard await coordinator.validatesAllFramesSelection(request),
                  coordinator.allFrames.externalSelectionRequest == request else
            {
                if coordinator.allFrames.externalSelectionRequest == request {
                    clearExternalSelection(request)
                    notice = String(localized: "The traffic graph frame belongs to a capture that has changed.")
                }
                return
            }
            let state = coordinator.allFrames
            guard request.frameListRequestID == state.requestID else {
                clearExternalSelection(request)
                notice = String(localized: "Frame navigation was superseded by another All Frames request.")
                return
            }
            guard !state.isLoading, !state.isEvaluatingFrameExpression else {
                return
            }
            if let error = state.error {
                clearExternalSelection(request)
                notice = error
                return
            }
            if let list = state.list,
               list.rows.contains(where: { $0.ordinal == request.ordinal })
            {
                await resolveExternalSelection(request)
                return
            }
            guard let list = state.list,
                  request.ordinal <= UInt64(list.scannedFrameCount),
                  request.ordinal <= UInt64(Int.max) else
            {
                clearExternalSelection(request)
                notice = String(localized: "Frame \(request.ordinal.formatted()) is outside the listed capture.")
                return
            }
            let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
            let pageStart = ((Int(request.ordinal) - 1) / pageSize) * pageSize + 1
            coordinator.loadAllFrames(force: true, retainedFrameStartOrdinal: pageStart)
            bindExternalSelectionToCurrentPageRequest(request)
        }
    }

    func resolveExternalSelection(_ request: AllFramesExternalSelectionRequest) async {
        let state = coordinator.allFrames
        guard state.externalSelectionRequest == request,
              !state.isLoading, !state.isEvaluatingFrameExpression else
        {
            return
        }
        guard await coordinator.validatesAllFramesSelection(request) else {
            if state.externalSelectionRequest == request {
                clearExternalSelection(request)
                notice = String(localized: "The traffic graph frame belongs to a capture that has changed.")
            }
            return
        }
        guard state.externalSelectionRequest == request else {
            return
        }
        guard request.frameListRequestID == state.requestID,
              !state.isLoading, !state.isEvaluatingFrameExpression else
        {
            clearExternalSelection(request)
            notice = String(localized: "Frame navigation was superseded by another All Frames request.")
            return
        }
        guard state.list?.rows.contains(where: { $0.ordinal == request.ordinal }) == true else {
            clearExternalSelection(request)
            notice = state
                .error ?? String(localized: "Frame \(request.ordinal.formatted()) is not available on this page.")
            return
        }
        let visible = state.visibleRows(sessionsInView: Set(coordinator.visibleSessions.map(\.id)))
        guard visible.contains(where: { $0.ordinal == request.ordinal }) else {
            clearExternalSelection(request)
            notice = String(localized: "Frame \(request.ordinal.formatted()) is hidden by the current filters.")
            return
        }
        clearExternalSelection(request)
        selection = request.ordinal
        revealToken &+= 1
        notice = String(localized: "Selected frame \(request.ordinal.formatted()) from the traffic graph.")
    }

    private func clearExternalSelection(_ request: AllFramesExternalSelectionRequest) {
        let state = coordinator.allFrames
        guard state.externalSelectionRequest == request else {
            return
        }
        state.externalSelectionRequest = nil
        if state.externalSelectionRequestID == request.id {
            state.externalSelectionRequestID = nil
        }
    }

    private func restoreFrameSelection(_ ordinal: UInt64) {
        guard selection != ordinal else {
            historyRestoreOrdinal = nil
            return
        }
        historyRestoreOrdinal = ordinal
        selection = ordinal
    }

    private func clearPendingHistoryNavigation(_ state: CaptureFrameListState) {
        if let target = pendingHistoryRestoreOrdinal, state.pendingTableSelection == target {
            state.pendingTableSelection = nil
        }
        pendingHistoryRestoreOrdinal = nil
        pendingHistoryBackward = nil
        pendingHistoryRequestID = nil
    }
}
