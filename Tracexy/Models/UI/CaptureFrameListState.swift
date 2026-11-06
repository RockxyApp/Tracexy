import Foundation
import Observation

// MARK: - AllFramesExternalSelectionRequest

struct AllFramesExternalSelectionRequest: Equatable, Sendable {
    let id: UUID
    let ordinal: UInt64
    let projectID: UUID
    let generation: Int
    let sourceToken: UUID
    let savedIdentity: PcapFileIdentity?
    var frameListRequestID: Int
}

// MARK: - TemporaryConversationColorPalette

nonisolated enum TemporaryConversationColorPalette {
    static let foregroundRGB: UInt32 = 0x172033
    static let backgroundRGB: [UInt32] = [
        0xFFF2CC, 0xE2F0D9, 0xDDEBF7, 0xFCE4D6,
        0xE4DFEC, 0xD9EAD3, 0xF4CCCC, 0xD0E0E3,
        0xEADCF8, 0xFFE0B2,
    ]
}

// MARK: - CaptureFrameListState

/// View ▸ All Frames: the whole capture's frame list, its scan state, and the
/// window's filters. Capture data — cleared at every capture boundary.
@MainActor
@Observable
final class CaptureFrameListState {
    // MARK: Internal

    nonisolated static let maximumTemporaryConversationColorSlots = TemporaryConversationColorPalette.backgroundRGB
        .count
    nonisolated static let maximumFrameNavigationHistoryCount = 64
    nonisolated static let maximumRecentFrameExpressions = 12
    nonisolated static let maximumPinnedFrameRows = 16

    var list: CaptureFrameList?
    /// Observable request from another evidence view; consumed only after its source is revalidated.
    var externalSelectionRequest: AllFramesExternalSelectionRequest?
    @ObservationIgnored var externalSelectionRequestID: UUID?
    /// The active Project's named packet-level filters, separate from capture-local state.
    let frameFilterLibrary = FrameFilterPresetLibrary()
    let frameColorRuleLibrary = FrameColorRuleLibrary()
    var isLoading = false
    var progress: PcapStreamProgress?
    var error: String?
    /// Only frames whose session is among the sessions in view (Wireshark's
    /// "displayed" frames); off shows every frame of the capture.
    var limitToSessionsInView = true
    var search = ""
    var frameExpressionDraft = ""
    private(set) var frameExpressionDraftIsValid: Bool?
    /// Bounded, in-memory expressions accepted during this capture lifetime.
    private(set) var recentFrameExpressions: [String] = []
    var frameExpressionError: FrameExpressionError?
    private(set) var acceptedFrameExpression: FrameExpression?
    private(set) var acceptedFrameExpressionText = ""
    private(set) var frameExpressionMatches: Set<UInt64>?
    private(set) var frameExpressionUnknownCount = 0
    /// One capture-local visual rule evaluated only for the currently retained page.
    private(set) var highlightedFrameExpression: FrameExpression?
    private(set) var highlightedFrameExpressionText = ""
    private(set) var highlightedFrameOrdinals: Set<UInt64> = []
    private(set) var highlightedFrameUnknownCount = 0
    private(set) var isEvaluatingFrameHighlight = false
    private(set) var frameColorRuleByOrdinal: [UInt64: UUID] = [:]
    private(set) var frameColorRuleUnknownOrdinals: Set<UInt64> = []
    private(set) var isEvaluatingFrameColorRules = false
    /// Capture-local temporary Wireshark-style conversation colors, keyed by the
    /// session identity already attached to each retained frame row.
    private(set) var temporaryConversationColorSlots: [UUID: Int] = [:]
    /// Counts and adjacent matching ordinals from a complete identity-checked
    /// source pass for the accepted expression, when available.
    var captureExpressionCoverage: FrameExpressionCaptureCoverage?
    private(set) var isEvaluatingFrameExpression = false
    /// VoIP Calls ▸ Flow Sequence: the Flow Graph draws only this call.
    var flowCallID: String?
    /// Wireshark's marks (⌘M) and ignored frames (⌘D): capture-local, never saved.
    var marked: Set<UInt64> = []
    /// Session IDs captured at mark time so page changes do not lose the
    /// session association needed for a marked-frame export's note scope.
    var markedSessionIDs: [UInt64: UUID] = [:]
    var ignored: Set<UInt64> = []
    var showsIgnored = false
    /// All Frames presentation only; protocol facts continue to keep raw values.
    var showsRelativeTCPNumbers = false
    /// Show only frames whose decoding stopped early (malformed or cut short).
    var showsDecodeProblemsOnly = false
    /// A frame to reveal once the list has loaded (`-g` at launch). Kept across
    /// ``cancel(clearList:)`` so opening the capture does not drop it.
    @ObservationIgnored var pendingReveal: UInt64?
    /// A Go to Frame request in All Frames awaiting an identity-checked page scan.
    @ObservationIgnored var pendingTableSelection: UInt64?
    /// Bounded capture-local history of distinct All Frames selections.
    private(set) var frameNavigationHistory: [UInt64] = []
    private(set) var frameNavigationHistoryIndex: Int?
    /// Mirrors View ▸ Validate Checksums: wrong checksums count as decode problems.
    var countsBadChecksums = false
    /// Frame comments (Wireshark's Packet Comment…), written on Export Frames.
    var frameComments: [UInt64: String] = [:]
    /// Invalidates on-demand reads of source-authored PCAPNG comments.
    var sourceCommentRequestID = 0
    /// The at-most-16 capture-wide reference rows remain visible when paging or
    /// filtering hides their original position.
    private(set) var captureTimeReferenceRows: [UInt64: CaptureFrameRow] = [:]
    /// Rows pinned in All Frames' separate shelf, independent of page and filters.
    private(set) var pinnedFrameRows: [UInt64: CaptureFrameRow] = [:]

    @ObservationIgnored var task: Task<Void, Never>?
    @ObservationIgnored var requestID = 0
    @ObservationIgnored var orphanFrameInspectionRequestID = 0
    /// Invalidates delayed exact-byte reads requested by All Frames copy actions.
    @ObservationIgnored var frameBytesCopyRequestID = 0

    var fraction: Double? {
        guard let progress, progress.totalBytes > 0 else {
            return nil
        }
        return min(max(Double(progress.bytesConsumed) / Double(progress.totalBytes), 0), 1)
    }

    var canNavigateFrameHistoryBackward: Bool {
        guard let index = frameNavigationHistoryIndex else {
            return false
        }
        return index > 0
    }

    var canNavigateFrameHistoryForward: Bool {
        guard let index = frameNavigationHistoryIndex else {
            return false
        }
        return index + 1 < frameNavigationHistory.count
    }

    func frameHistoryDestination(backward: Bool) -> UInt64? {
        guard let index = frameNavigationHistoryIndex else {
            return nil
        }
        guard backward ? index > 0 : index + 1 < frameNavigationHistory.count else {
            return nil
        }
        let targetIndex = backward ? index - 1 : index + 1
        guard frameNavigationHistory.indices.contains(targetIndex) else {
            return nil
        }
        return frameNavigationHistory[targetIndex]
    }

    func recordFrameSelection(_ ordinal: UInt64) {
        guard let index = frameNavigationHistoryIndex else {
            frameNavigationHistory = [ordinal]
            frameNavigationHistoryIndex = 0
            return
        }
        guard frameNavigationHistory.indices.contains(index) else {
            frameNavigationHistory = [ordinal]
            frameNavigationHistoryIndex = 0
            return
        }
        guard frameNavigationHistory[index] != ordinal else {
            return
        }
        frameNavigationHistory = Array(frameNavigationHistory.prefix(index + 1))
        frameNavigationHistory.append(ordinal)
        if frameNavigationHistory.count > Self.maximumFrameNavigationHistoryCount {
            frameNavigationHistory.removeFirst(frameNavigationHistory.count - Self.maximumFrameNavigationHistoryCount)
        }
        frameNavigationHistoryIndex = frameNavigationHistory.count - 1
    }

    @discardableResult
    func moveFrameHistoryCursor(backward: Bool, to ordinal: UInt64) -> Bool {
        guard let index = frameNavigationHistoryIndex else {
            return false
        }
        guard backward ? index > 0 : index + 1 < frameNavigationHistory.count else {
            return false
        }
        let targetIndex = backward ? index - 1 : index + 1
        guard frameNavigationHistory.indices.contains(targetIndex),
              frameNavigationHistory[targetIndex] == ordinal else
        {
            return false
        }
        frameNavigationHistoryIndex = targetIndex
        return true
    }

    func clearFrameNavigationHistory() {
        frameNavigationHistory = []
        frameNavigationHistoryIndex = nil
    }

    func clearRecentFrameExpressions() {
        recentFrameExpressions = []
    }

    func updateFrameExpressionDraft(_ text: String) {
        frameExpressionDraft = text
        frameExpressionError = nil
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            frameExpressionDraftIsValid = nil
            return
        }
        var parser = FrameExpressionParser()
        do {
            _ = try parser.parse(trimmed)
            frameExpressionDraftIsValid = true
        } catch let error as FrameExpressionError {
            frameExpressionDraftIsValid = false
            frameExpressionError = error
        } catch {
            frameExpressionDraftIsValid = false
            frameExpressionError = FrameExpressionError(position: 1, reason: "Could not parse the expression")
        }
    }

    func cancel(clearList: Bool, clearAnnotations: Bool? = nil) {
        orphanFrameInspectionRequestID &+= 1
        frameBytesCopyRequestID &+= 1
        task?.cancel()
        frameExpressionTask?.cancel()
        frameExpressionRequestID &+= 1
        frameHighlightTask?.cancel()
        frameHighlightRequestID &+= 1
        frameColorRuleTask?.cancel()
        frameColorRuleRequestID &+= 1
        frameColorRuleByOrdinal = [:]
        frameColorRuleUnknownOrdinals = []
        isEvaluatingFrameColorRules = false
        highlightedFrameOrdinals = []
        highlightedFrameUnknownCount = 0
        isEvaluatingFrameHighlight = false
        frameExpressionMatches = nil
        frameExpressionUnknownCount = 0
        captureExpressionCoverage = nil
        isEvaluatingFrameExpression = false
        task = nil
        requestID &+= 1
        isLoading = false
        progress = nil
        error = nil
        pendingTableSelection = nil
        if clearList {
            list = nil
        }
        if clearAnnotations ?? clearList {
            clearFrameNavigationHistory()
            clearRecentFrameExpressions()
            marked = []
            markedSessionIDs = [:]
            ignored = []
            showsRelativeTCPNumbers = false
            temporaryConversationColorSlots = [:]
            frameComments = [:]
            captureTimeReferenceRows = [:]
            pinnedFrameRows = [:]
        }
    }

    /// Toggle a row in the bounded capture-local Pin Row to Top shelf.
    @discardableResult
    func togglePinnedFrameRow(_ row: CaptureFrameRow) -> Bool {
        if pinnedFrameRows.removeValue(forKey: row.id) != nil {
            return true
        }
        guard pinnedFrameRows.count < Self.maximumPinnedFrameRows else {
            return false
        }
        pinnedFrameRows[row.id] = row
        return true
    }

    func unpinFrameRow(_ ordinal: UInt64) {
        pinnedFrameRows.removeValue(forKey: ordinal)
    }

    func unpinAllFrameRows() {
        pinnedFrameRows = [:]
    }

    func refreshPinnedFrameRows(from rows: [CaptureFrameRow]) {
        for row in rows where pinnedFrameRows[row.id] != nil {
            pinnedFrameRows[row.id] = row
        }
    }

    /// Custom column indices may change when a Project's applied field columns
    /// change. Blank off-page pinned values until their page is scanned again.
    func clearPinnedFrameColumnValues() {
        for ordinal in Array(pinnedFrameRows.keys) {
            guard var row = pinnedFrameRows[ordinal] else {
                continue
            }
            row.columnValues = []
            pinnedFrameRows[ordinal] = row
        }
    }

    /// Toggle the next free temporary slot for a decoded conversation. Sessionless
    /// frames cannot receive one because no conversation identity is known.
    @discardableResult
    func toggleTemporaryConversationColor(sessionID: UUID?) -> Bool {
        guard let sessionID else {
            return false
        }
        if temporaryConversationColorSlots.removeValue(forKey: sessionID) != nil {
            return true
        }
        let occupied = Set(temporaryConversationColorSlots.values)
        guard let slot = (0 ..< Self.maximumTemporaryConversationColorSlots).first(where: { !occupied.contains($0) }) else {
            return false
        }
        temporaryConversationColorSlots[sessionID] = slot
        return true
    }

    func clearTemporaryConversationColors() {
        temporaryConversationColorSlots = [:]
    }

    /// Apply the draft only after it parses. A bad replacement leaves the last
    /// accepted expression and its visible result in place.
    func applyFrameExpression() {
        let text = frameExpressionDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty {
            clearFrameExpression()
            return
        }
        var parser = FrameExpressionParser()
        do {
            let expression = try parser.parse(text)
            invalidatePendingFrameExpressionEvaluation(restoreAcceptedResult: false)
            frameExpressionError = nil
            frameExpressionDraftIsValid = true
            evaluateFrameExpression(expression, text: text, recordsRecent: true)
        } catch let error as FrameExpressionError {
            invalidatePendingFrameExpressionEvaluation(restoreAcceptedResult: true)
            frameExpressionError = error
            frameExpressionDraftIsValid = false
        } catch {
            invalidatePendingFrameExpressionEvaluation(restoreAcceptedResult: true)
            frameExpressionError = FrameExpressionError(position: 1, reason: "Could not parse the expression")
            frameExpressionDraftIsValid = false
        }
    }

    func clearFrameExpression() {
        frameExpressionTask?.cancel()
        frameExpressionRequestID &+= 1
        frameExpressionTask = nil
        frameExpressionDraft = ""
        frameExpressionDraftIsValid = nil
        frameExpressionError = nil
        acceptedFrameExpression = nil
        acceptedFrameExpressionText = ""
        frameExpressionMatches = nil
        frameExpressionUnknownCount = 0
        captureExpressionCoverage = nil
        isEvaluatingFrameExpression = false
    }

    /// Install a temporary single-rule highlight from the current draft without
    /// changing the independently applied Frame Expression filter.
    func highlightFramesFromDraft() {
        let text = frameExpressionDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            frameExpressionError = FrameExpressionError(position: 1, reason: "Enter a Frame Expression to highlight")
            return
        }
        var parser = FrameExpressionParser()
        do {
            let expression = try parser.parse(text)
            frameExpressionError = nil
            installFrameHighlight(expression, text: text)
        } catch let error as FrameExpressionError {
            frameExpressionError = error
        } catch {
            frameExpressionError = FrameExpressionError(position: 1, reason: "Could not parse the expression")
        }
    }

    /// Install a temporary highlight from a validated decoded-field term without
    /// reading or changing either expression draft or the applied filter.
    func highlightFrames(with text: String) {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            return
        }
        var parser = FrameExpressionParser()
        guard let expression = try? parser.parse(text) else {
            return
        }
        installFrameHighlight(expression, text: text)
    }

    func clearFrameHighlight() {
        frameHighlightTask?.cancel()
        frameHighlightRequestID &+= 1
        frameHighlightTask = nil
        highlightedFrameExpression = nil
        highlightedFrameExpressionText = ""
        highlightedFrameOrdinals = []
        highlightedFrameUnknownCount = 0
        isEvaluatingFrameHighlight = false
    }

    /// Re-evaluate after a page or column rescan; old ordinals are never reused.
    func refreshFrameHighlight() {
        guard let highlightedFrameExpression else {
            return
        }
        frameHighlightTask?.cancel()
        frameHighlightRequestID &+= 1
        let highlightID = frameHighlightRequestID
        let listID = requestID
        highlightedFrameOrdinals = []
        highlightedFrameUnknownCount = 0
        guard let rows = list?.rows else {
            isEvaluatingFrameHighlight = false
            return
        }
        isEvaluatingFrameHighlight = true
        frameHighlightTask = Task.detached(priority: .userInitiated) { [weak self] in
            guard let result = FrameExpressionSelection.evaluate(highlightedFrameExpression, rows: rows) else {
                // A retired evaluation still owns the progress flag it set, or the
                // view keeps reporting work that will never finish.
                await self?.finishEvaluatingFrameHighlight(requestID: highlightID)
                return
            }
            await MainActor.run {
                guard let self, self.frameHighlightRequestID == highlightID,
                      self.requestID == listID else
                {
                    return
                }
                self.highlightedFrameOrdinals = result.matchingOrdinals
                self.highlightedFrameUnknownCount = result.unknownCount
                self.isEvaluatingFrameHighlight = false
                self.frameHighlightTask = nil
            }
        }
    }

    func refreshFrameColorRules() {
        frameColorRuleTask?.cancel()
        frameColorRuleRequestID &+= 1
        let ruleRequestID = frameColorRuleRequestID
        let listID = requestID
        frameColorRuleByOrdinal = [:]
        frameColorRuleUnknownOrdinals = []
        guard let rows = list?.rows, !frameColorRuleLibrary.rules.isEmpty else {
            isEvaluatingFrameColorRules = false
            return
        }
        let rules = frameColorRuleLibrary.rules
        isEvaluatingFrameColorRules = true
        frameColorRuleTask = Task.detached(priority: .userInitiated) { [weak self] in
            guard let result = FrameColorRuleEvaluation.evaluate(rules, rows: rows),
                  !Task.isCancelled else
            {
                await self?.finishEvaluatingFrameColorRules(requestID: ruleRequestID)
                return
            }
            await MainActor.run {
                guard let self, self.frameColorRuleRequestID == ruleRequestID,
                      self.requestID == listID else
                {
                    return
                }
                self.frameColorRuleByOrdinal = result.ruleByOrdinal
                self.frameColorRuleUnknownOrdinals = result.unknownOrdinals
                self.isEvaluatingFrameColorRules = false
                self.frameColorRuleTask = nil
            }
        }
    }

    /// Called after an identity-checked frame rescan. The previous ordinal set
    /// cannot be reused for a different listing, even of the same file.
    func refreshFrameExpression() {
        guard let acceptedFrameExpression else {
            return
        }
        frameExpressionMatches = nil
        frameExpressionUnknownCount = 0
        evaluateFrameExpression(acceptedFrameExpression, text: acceptedFrameExpressionText, recordsRecent: false)
    }

    /// The rows the window shows: in view (when limited) and matching the search.
    func visibleRows(sessionsInView: Set<UUID>) -> [CaptureFrameRow] {
        guard let rows = list?.rows else {
            return []
        }
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        var visible = rows.filter { row in
            if captureTimeReferenceRows[row.id] != nil {
                return true
            }
            if acceptedFrameExpression != nil, frameExpressionMatches?.contains(row.id) != true {
                return false
            }
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
        let pinnedRows = captureTimeReferenceRows.values.sorted { $0.id < $1.id }
        for pinnedRow in pinnedRows where !visible.contains(where: { $0.id == pinnedRow.id }) {
            let insertionIndex = visible.firstIndex { $0.id > pinnedRow.id } ?? visible.endIndex
            visible.insert(pinnedRow, at: insertionIndex)
        }
        return visible
    }

    func retainCaptureTimeReferenceRow(_ row: CaptureFrameRow) {
        captureTimeReferenceRows[row.id] = row
    }

    func removeCaptureTimeReferenceRow(_ ordinal: UInt64) {
        captureTimeReferenceRows.removeValue(forKey: ordinal)
    }

    /// Expand All Frames beyond the sessions currently shown in the main workspace.
    /// Search, expression, ignored-frame and decode-problem filters remain active.
    func showFramesOutsideSessionsInView() {
        limitToSessionsInView = false
    }

    func clearCaptureTimeReferenceRows() {
        captureTimeReferenceRows = [:]
    }

    func refreshCaptureTimeReferenceRows(from rows: [CaptureFrameRow]) {
        for ordinal in Array(captureTimeReferenceRows.keys) {
            if let replacement = rows.first(where: { $0.id == ordinal }) {
                captureTimeReferenceRows[ordinal] = replacement
            }
        }
    }

    /// Custom column indices can change when a Project's applied field columns
    /// change. Blank off-page pinned values until their page is scanned again.
    func clearCaptureTimeReferenceColumnValues() {
        for ordinal in Array(captureTimeReferenceRows.keys) {
            guard var row = captureTimeReferenceRows[ordinal] else {
                continue
            }
            row.columnValues = []
            captureTimeReferenceRows[ordinal] = row
        }
    }

    func toggleMark(_ ordinal: UInt64, sessionID: UUID? = nil) {
        if marked.remove(ordinal) == nil {
            marked.insert(ordinal)
            markedSessionIDs[ordinal] = sessionID
        } else {
            markedSessionIDs.removeValue(forKey: ordinal)
        }
    }

    /// Mark every currently displayed row without toggling marks that already exist.
    /// Marks outside the visible scope remain unchanged.
    func markDisplayed(_ rows: [CaptureFrameRow]) {
        for row in rows {
            marked.insert(row.id)
            if let sessionID = row.sessionID {
                markedSessionIDs[row.id] = sessionID
            } else {
                markedSessionIDs.removeValue(forKey: row.id)
            }
        }
    }

    /// Remove marks only from rows currently displayed; marks outside this scope remain.
    func unmarkDisplayed(_ rows: [CaptureFrameRow]) {
        for row in rows {
            marked.remove(row.id)
            markedSessionIDs.removeValue(forKey: row.id)
        }
    }

    func toggleIgnore(_ ordinal: UInt64) {
        if ignored.remove(ordinal) == nil {
            ignored.insert(ordinal)
        }
    }

    /// Ignore the rows currently displayed by All Frames, after its active scope
    /// and filters have been applied.
    func ignoreDisplayed(_ rows: [CaptureFrameRow]) {
        ignored.formUnion(rows.map(\.id))
    }

    /// Unignore only rows currently displayed by All Frames.
    func unignoreDisplayed(_ rows: [CaptureFrameRow]) {
        ignored.subtract(rows.map(\.id))
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

    /// Navigate marks across retained pages. A page load may still be required
    /// before the target can be shown in the table.
    func adjacentMarkAcrossCapture(from ordinal: UInt64?, forward: Bool) -> UInt64? {
        let marks = marked.sorted()
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

    // MARK: Private

    @ObservationIgnored private var frameExpressionTask: Task<Void, Never>?
    @ObservationIgnored private var frameExpressionRequestID = 0
    @ObservationIgnored private var frameHighlightTask: Task<Void, Never>?
    @ObservationIgnored private var frameHighlightRequestID = 0
    @ObservationIgnored private var frameColorRuleTask: Task<Void, Never>?
    @ObservationIgnored private var frameColorRuleRequestID = 0

    /// Releases the progress flag a retired evaluation set, but only while it is
    /// still the current request — a newer one owns its own flag.
    private func finishEvaluatingFrameExpression(requestID: Int) {
        guard frameExpressionRequestID == requestID else {
            return
        }
        isEvaluatingFrameExpression = false
        frameExpressionTask = nil
    }

    private func finishEvaluatingFrameHighlight(requestID: Int) {
        guard frameHighlightRequestID == requestID else {
            return
        }
        isEvaluatingFrameHighlight = false
        frameHighlightTask = nil
    }

    private func finishEvaluatingFrameColorRules(requestID: Int) {
        guard frameColorRuleRequestID == requestID else {
            return
        }
        isEvaluatingFrameColorRules = false
        frameColorRuleTask = nil
    }

    private func installFrameHighlight(_ expression: FrameExpression, text: String) {
        highlightedFrameExpression = expression
        highlightedFrameExpressionText = text
        refreshFrameHighlight()
    }

    private func evaluateFrameExpression(_ expression: FrameExpression, text: String, recordsRecent: Bool) {
        frameExpressionTask?.cancel()
        frameExpressionRequestID &+= 1
        let expressionID = frameExpressionRequestID
        let listID = requestID
        guard let rows = list?.rows else {
            let didChange = text != acceptedFrameExpressionText
            if didChange {
                captureExpressionCoverage = nil
            }
            acceptedFrameExpression = expression
            acceptedFrameExpressionText = text
            if recordsRecent {
                recordRecentFrameExpression(text)
            }
            frameExpressionMatches = nil
            frameExpressionUnknownCount = 0
            isEvaluatingFrameExpression = false
            return
        }
        isEvaluatingFrameExpression = true
        frameExpressionTask = Task.detached(priority: .userInitiated) { [weak self] in
            guard let result = FrameExpressionSelection.evaluate(expression, rows: rows) else {
                await self?.finishEvaluatingFrameExpression(requestID: expressionID)
                return
            }
            await MainActor.run {
                guard let self, self.frameExpressionRequestID == expressionID,
                      self.requestID == listID else
                {
                    return
                }
                let didChange = text != self.acceptedFrameExpressionText
                if didChange {
                    self.captureExpressionCoverage = nil
                }
                self.acceptedFrameExpression = expression
                self.acceptedFrameExpressionText = text
                if recordsRecent {
                    self.recordRecentFrameExpression(text)
                }
                self.frameExpressionMatches = result.matchingOrdinals
                self.frameExpressionUnknownCount = result.unknownCount
                self.isEvaluatingFrameExpression = false
                self.frameExpressionTask = nil
            }
        }
    }

    private func invalidatePendingFrameExpressionEvaluation(restoreAcceptedResult: Bool) {
        guard isEvaluatingFrameExpression else {
            return
        }
        frameExpressionTask?.cancel()
        frameExpressionRequestID &+= 1
        frameExpressionTask = nil
        isEvaluatingFrameExpression = false
        guard restoreAcceptedResult, frameExpressionMatches == nil,
              let acceptedFrameExpression else
        {
            return
        }
        evaluateFrameExpression(acceptedFrameExpression, text: acceptedFrameExpressionText, recordsRecent: false)
    }

    private func recordRecentFrameExpression(_ text: String) {
        guard !text.isEmpty else {
            return
        }
        recentFrameExpressions.removeAll { $0 == text }
        recentFrameExpressions.insert(text, at: 0)
        if recentFrameExpressions.count > Self.maximumRecentFrameExpressions {
            recentFrameExpressions.removeLast(recentFrameExpressions.count - Self.maximumRecentFrameExpressions)
        }
    }
}
