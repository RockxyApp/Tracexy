import Foundation
import Observation

// MARK: - CaptureFrameListState

/// View ▸ All Frames: the whole capture's frame list, its scan state, and the
/// window's filters. Capture data — cleared at every capture boundary.
@MainActor
@Observable
final class CaptureFrameListState {
    var list: CaptureFrameList?
    var isLoading = false
    var progress: PcapStreamProgress?
    var error: String?
    /// Only frames whose session is among the sessions in view (Wireshark's
    /// "displayed" frames); off shows every frame of the capture.
    var limitToSessionsInView = true
    var search = ""
    /// VoIP Calls ▸ Flow Sequence: the Flow Graph draws only this call.
    var flowCallID: String?
    /// Wireshark's marks (⌘M) and ignored frames (⌘D): capture-local, never saved.
    var marked: Set<UInt64> = []
    var ignored: Set<UInt64> = []
    var showsIgnored = false
    /// Show only frames whose decoding stopped early (malformed or cut short).
    var showsDecodeProblemsOnly = false
    /// A frame to reveal once the list has loaded (`-g` at launch). Kept across
    /// ``cancel(clearList:)`` so opening the capture does not drop it.
    @ObservationIgnored var pendingReveal: UInt64?
    /// Mirrors View ▸ Validate Checksums: wrong checksums count as decode problems.
    var countsBadChecksums = false
    /// Frame comments (Wireshark's Packet Comment…), written on Export Frames.
    var frameComments: [UInt64: String] = [:]

    @ObservationIgnored var task: Task<Void, Never>?
    @ObservationIgnored var requestID = 0

    var fraction: Double? {
        guard let progress, progress.totalBytes > 0 else {
            return nil
        }
        return min(max(Double(progress.bytesConsumed) / Double(progress.totalBytes), 0), 1)
    }

    func cancel(clearList: Bool) {
        task?.cancel()
        task = nil
        requestID &+= 1
        isLoading = false
        progress = nil
        error = nil
        if clearList {
            list = nil
            marked = []
            ignored = []
            frameComments = [:]
        }
    }

    /// The rows the window shows: in view (when limited) and matching the search.
    func visibleRows(sessionsInView: Set<UUID>) -> [CaptureFrameRow] {
        guard let rows = list?.rows else {
            return []
        }
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        return rows.filter { row in
            if !showsIgnored, ignored.contains(row.id) {
                return false
            }
            if showsDecodeProblemsOnly, row.decodeStop == nil, !(countsBadChecksums && row.hasBadChecksum) {
                return false
            }
            if limitToSessionsInView {
                // A frame whose decoding stopped before its transport header folds
                // into no session; listing decode problems still shows it.
                let sessionless = row.sessionID == nil && showsDecodeProblemsOnly
                guard sessionless || row.sessionID.map(sessionsInView.contains) == true else {
                    return false
                }
            }
            guard !needle.isEmpty else {
                return true
            }
            return row.info.localizedCaseInsensitiveContains(needle)
                || row.source.localizedCaseInsensitiveContains(needle)
                || row.destination.localizedCaseInsensitiveContains(needle)
                || row.protocolName.localizedCaseInsensitiveContains(needle)
        }
    }

    func toggleMark(_ ordinal: UInt64) {
        if marked.remove(ordinal) == nil {
            marked.insert(ordinal)
        }
    }

    func toggleIgnore(_ ordinal: UInt64) {
        if ignored.remove(ordinal) == nil {
            ignored.insert(ordinal)
        }
    }

    /// The next (or previous) marked frame after `ordinal` among `rows`, wrapping.
    func adjacentMark(from ordinal: UInt64?, in rows: [CaptureFrameRow], forward: Bool) -> UInt64? {
        let marks = rows.map(\.id).filter(marked.contains)
        guard !marks.isEmpty else {
            return nil
        }
        guard let ordinal else {
            return forward ? marks.first : marks.last
        }
        if forward {
            return marks.first { $0 > ordinal } ?? marks.first
        }
        return marks.last { $0 < ordinal } ?? marks.last
    }
}
