import SwiftUI

// MARK: - AllFramesWindow Selection Navigation

extension AllFramesWindow {
    static func sessionEdgeOrdinal(from selected: UInt64?, last: Bool, rows: [CaptureFrameRow]) -> UInt64? {
        guard let selected, let sessionID = rows.first(where: { $0.ordinal == selected })?.sessionID else {
            return nil
        }
        let ordinals = rows.filter { $0.sessionID == sessionID }.map(\.ordinal)
        return last ? ordinals.max() : ordinals.min()
    }

    func stepInSession(_ rows: [CaptureFrameRow], forward: Bool) {
        guard let next = Self.adjacentInSession(from: selection, forward: forward, rows: rows) else {
            notice = forward
                ? String(localized: "This is the session's last frame in the list.")
                : String(localized: "This is the session's first frame in the list.")
            return
        }
        notice = nil
        cancelExternalSelectionForManualSelection()
        selection = next
        revealToken &+= 1
    }

    func toggleSelectedMark() {
        guard let row = selectedVisibleMainRow() else {
            return
        }
        coordinator.allFrames.toggleMark(row.id, sessionID: row.sessionID)
    }

    func toggleSelectedIgnore() {
        guard let row = selectedVisibleMainRow() else {
            return
        }
        coordinator.allFrames.toggleIgnore(row.id)
    }

    func selectSessionEdge(_ rows: [CaptureFrameRow], last: Bool) {
        guard let ordinal = Self.sessionEdgeOrdinal(from: selection, last: last, rows: rows) else {
            return
        }
        cancelExternalSelectionForManualSelection()
        selection = ordinal
        revealToken &+= 1
        notice = nil
    }

    func selectedVisibleMainRow() -> CaptureFrameRow? {
        let state = coordinator.allFrames
        guard !state.isLoading,
              !state.isEvaluatingFrameExpression,
              state.error == nil,
              state.list != nil,
              let selection else
        {
            return nil
        }
        let sessionsInView = Set(coordinator.visibleSessions.map(\.id))
        return state.visibleRows(sessionsInView: sessionsInView).first { $0.id == selection }
    }
}
