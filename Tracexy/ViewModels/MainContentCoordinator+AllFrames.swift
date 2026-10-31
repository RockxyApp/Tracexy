import Foundation

// MARK: - OrphanFrameInspectionResult

enum OrphanFrameInspectionResult: Equatable {
    case ready
    case unavailable(String)
    case superseded
}

// MARK: - FrameBytesCopyOutcome

enum FrameBytesCopyOutcome: Equatable {
    case bytes([UInt8])
    case unavailable(String)
    case superseded
}

/// View ▸ All Frames: every frame of the capture, rescanned on demand from the same
/// stable sources the Frames facet accepts (the open saved file, identity-checked, or
/// a byte-identical copy of the stopped live spool). A growing live spool is refused.
@MainActor
extension MainContentCoordinator {
    /// Why the capture's frames cannot be listed now, or `nil` when they can.
    var allFramesUnavailableReason: String? {
        if isCapturing || isStarting {
            return String(localized: "Stop the live capture to list its frames.")
        }
        if isViewingSavedCapture {
            return savedCaptureEvidenceURL != nil && adoptedSavedCaptureIdentity != nil
                ? nil : String(localized: "The saved capture source is unavailable.")
        }
        if stoppedCaptureReadyGeneration == startGeneration {
            return nil
        }
        return sessions.isEmpty
            ? String(localized: "Open a capture file or stop a live capture to list its frames.")
            : String(localized: "The stopped capture is still being finalized.")
    }

    /// Read source-authored comments for one displayed saved-capture frame.
    /// Comment text is fetched on demand and never copied into the frame list.
    func sourceFrameComments(for row: CaptureFrameRow) async -> CaptureFrameCommentReadOutcome {
        guard isViewingSavedCapture, row.hasComment,
              let reference = row.frameCommentReference,
              let sourceURL = savedCaptureEvidenceURL,
              let identity = adoptedSavedCaptureIdentity else
        {
            return .unavailable
        }
        allFrames.sourceCommentRequestID &+= 1
        let requestID = allFrames.sourceCommentRequestID
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let worker = Task.detached(priority: .utility) {
            try CaptureFrameCommentReader.read(
                reference, from: sourceURL, expectedIdentity: identity, isCancelled: { Task.isCancelled }
            )
        }
        let result: Result<CaptureFrameCommentReadResult, Error>
        do {
            let value = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            result = .success(value)
        } catch {
            result = .failure(error)
        }
        guard requestID == allFrames.sourceCommentRequestID,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              isViewingSavedCapture,
              savedCaptureEvidenceURL == sourceURL,
              adoptedSavedCaptureIdentity == identity,
              isCurrentFrameCommentRow(row, reference: reference) else
        {
            return .superseded
        }
        switch result {
        case let .success(value):
            return CaptureFrameCommentReadOutcome.comments(value)
        case .failure:
            return CaptureFrameCommentReadOutcome.unavailable
        }
    }

    /// Reads a frame's exact bytes for a user-requested clipboard copy. Revalidates
    /// the Project, source identity and displayed row before returning bytes so a
    /// delayed read cannot copy from a replaced capture.
    func frameBytesForCopy(_ row: CaptureFrameRow) async -> FrameBytesCopyOutcome {
        guard let locator = row.provenance.locator,
              allFramesUnavailableReason == nil,
              isCurrentFrameBytesCopyRow(row) else
        {
            return .unavailable(String(localized: "This frame's exact local bytes are unavailable."))
        }
        allFrames.frameBytesCopyRequestID &+= 1
        let requestID = allFrames.frameBytesCopyRequestID
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        guard (savedURL != nil && savedIdentity != nil)
            || (stoppedCaptureReadyGeneration == generation && !isCapturing && !isStarting) else
        {
            return .unavailable(String(localized: "Stop the capture before copying exact frame bytes."))
        }
        let worker = Task.detached(priority: .userInitiated) {
            if let savedURL, let savedIdentity {
                let reference = try SavedCaptureStreamLoader.citedEvidenceReference(
                    for: row.provenance, matching: savedIdentity
                )
                return try CaptureEvidenceReader.read(reference, from: savedURL)
            }
            return try await spool.readCurrentSource(locator, capturedLength: row.provenance.capturedLength)
        }
        do {
            let bytes = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            guard requestID == allFrames.frameBytesCopyRequestID else {
                return .superseded
            }
            guard generation == startGeneration,
                  projectID == projectStore.activeProjectID,
                  isCurrentFrameBytesCopyRow(row),
                  savedURL == nil
                  ? (stoppedCaptureReadyGeneration == generation && liveCaptureSpool === spool)
                  : (isViewingSavedCapture && savedCaptureEvidenceURL == savedURL
                      && adoptedSavedCaptureIdentity == savedIdentity) else
            {
                return .superseded
            }
            return .bytes(bytes)
        } catch {
            guard requestID == allFrames.frameBytesCopyRequestID else {
                return .superseded
            }
            return .unavailable(
                String(localized: "The exact bytes for frame \(row.ordinal.formatted()) are unavailable.")
            )
        }
    }

    private func isCurrentFrameBytesCopyRow(_ row: CaptureFrameRow) -> Bool {
        let matches: (CaptureFrameRow) -> Bool = {
            $0.id == row.id && $0.provenance == row.provenance
        }
        return allFrames.list?.rows.contains(where: matches) == true
            || allFrames.captureTimeReferenceRows[row.id].map(matches) == true
    }

    private func isCurrentFrameCommentRow(
        _ row: CaptureFrameRow, reference: CaptureFrameCommentReference
    )
        -> Bool
    {
        let matches: (CaptureFrameRow) -> Bool = {
            $0.id == row.id && $0.provenance == row.provenance && $0.frameCommentReference == reference
        }
        return allFrames.list?.rows.contains(where: matches) == true
            || allFrames.captureTimeReferenceRows[row.id].map(matches) == true
    }

    func loadAllFrames(force: Bool = false, retainedFrameStartOrdinal: Int = 1) {
        let state = allFrames
        if !force, state.list != nil || state.isLoading {
            return
        }
        // A page/column rescan replaces rows but keeps capture-local annotations.
        // Capture retirement clears those separately.
        state.cancel(clearList: true, clearAnnotations: false)
        if let reason = allFramesUnavailableReason {
            state.error = reason
            return
        }
        let requestID = state.requestID
        let generation = startGeneration
        let relay = CoordinatorProgressRelay(coordinator: self, requestID: requestID) { coordinator, progress, id in
            guard id == coordinator.allFrames.requestID, coordinator.allFrames.isLoading else {
                return
            }
            if let current = coordinator.allFrames.progress, progress.bytesConsumed < current.bytesConsumed {
                return
            }
            coordinator.allFrames.progress = progress
        }
        state.isLoading = true
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let columns = packetDetailOptions.frameColumns
        let captureTimeReferenceOrdinals = Set(sessionTimeDisplay.captureReferences().map(\.ordinal))
        let auxiliaryFrameOrdinals = Set(state.pinnedFrameRows.keys).union(state.captureTimeReferenceRows.keys)
        let showsRelativeTCPNumbers = state.showsRelativeTCPNumbers
        let timeCorrection = activeSavedCapture?.timeCorrection
        let expression = state.acceptedFrameExpression
        let expressionText = state.acceptedFrameExpressionText
        let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
        state.task = Task.detached(priority: .userInitiated) { [weak self] in
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-all-frames-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            do {
                let source = try await Self.frameToolSource(
                    savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
                )
                let scanner = try CaptureFrameListScanner(
                    contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                    configuration: .init(
                        retainedFrameStartOrdinal: retainedFrameStartOrdinal, columns: columns,
                        captureTimeReferenceOrdinals: captureTimeReferenceOrdinals,
                        auxiliaryFrameOrdinals: auxiliaryFrameOrdinals,
                        showsRelativeTCPNumbers: showsRelativeTCPNumbers,
                        timeCorrection: savedURL == nil ? nil : timeCorrection
                    )
                )
                var counter = expression.map {
                    FrameExpressionCaptureCounter(
                        expression: $0, pageStart: retainedFrameStartOrdinal, pageSize: pageSize
                    )
                }
                let list = try scanner.scan(
                    onProgress: relay.submit,
                    onRow: expression == nil ? nil : { row in counter?.record(row) }
                )
                try Task.checkCancellation()
                await self?.finishAllFrames(
                    list, coverage: counter?.coverage, expressionText: expressionText,
                    captureTimeReferenceOrdinals: captureTimeReferenceOrdinals,
                    requestID: requestID, generation: generation
                )
            } catch is CancellationError {
                await self?.finishAllFrames(
                    nil, coverage: nil, expressionText: expressionText,
                    captureTimeReferenceOrdinals: captureTimeReferenceOrdinals,
                    requestID: requestID, generation: generation
                )
            } catch {
                await self?.failAllFrames(error, requestID: requestID, generation: generation)
            }
        }
    }

    /// The stable file the frame tools rescan: the open saved capture itself, or a
    /// byte-identical copy of the stopped live spool written to `temporaryURL`.
    nonisolated static func frameToolSource(
        savedURL: URL?,
        savedIdentity: PcapFileIdentity?,
        spool: LiveCaptureSpool,
        temporaryURL: URL
    )
        async throws -> (url: URL, identity: PcapFileIdentity, token: UUID)
    {
        if let savedURL, let savedIdentity {
            return (savedURL, savedIdentity, SavedCaptureStreamLoader.sourceToken(for: savedIdentity))
        }
        guard let token = await spool.currentSourceToken() else {
            throw FollowStreamError.identityMismatch
        }
        try await spool.copy(to: temporaryURL)
        let handle = try FileHandle(forReadingFrom: temporaryURL)
        let identity = PcapFileIdentity.snapshot(of: handle)
        try handle.close()
        return (temporaryURL, identity, token)
    }

    /// Recomputes capture-wide SMB2 response times without coupling the result to
    /// All Frames paging. The scan reads a stable saved file or stopped-spool copy.
    func scanSMB2ServiceResponseTime(
        sessionsInScope: Set<UUID>?
    )
        async throws -> ServiceResponseTime.StreamingSMB2Accumulator.Result
    {
        guard allFramesUnavailableReason == nil else {
            throw ServiceResponseTime.ScanError.sourceUnavailable(
                allFramesUnavailableReason ?? String(localized: "The capture source is unavailable.")
            )
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-smb2-srt-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let scanner = try CaptureFrameListScanner(
                contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                configuration: .init(
                    maxRetainedFrames: 1, timeCorrection: savedURL == nil ? nil : correction
                )
            )
            var accumulator = ServiceResponseTime.StreamingSMB2Accumulator()
            let list = try scanner.scan(onRow: { row in
                if let sessionsInScope, row.sessionID.map(sessionsInScope.contains) != true {
                    return
                }
                accumulator.record(row)
            })
            guard list.completeness == .complete else {
                throw ServiceResponseTime.ScanError.incomplete
            }
            return (accumulator.result(), source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await liveCaptureSpool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity else
        {
            throw CancellationError()
        }
        return result
    }

    /// Capture-wide stable-source scan for the bounded LDAP/Kerberos SRT reducers.
    func scanServiceResponseTime(
        _ service: ServiceResponseTime.Service,
        sessionsInScope: Set<UUID>?
    )
        async throws -> ServiceResponseTime.StreamingAccumulator.Result
    {
        guard service == .ldap || service == .kerberos else {
            throw ServiceResponseTime.ScanError
                .sourceUnavailable("This service does not use the LDAP/Kerberos scanner.")
        }
        guard allFramesUnavailableReason == nil else {
            throw ServiceResponseTime.ScanError.sourceUnavailable(
                allFramesUnavailableReason ?? String(localized: "The capture source is unavailable.")
            )
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-\(service.rawValue)-srt-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let scanner = try CaptureFrameListScanner(
                contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                configuration: .init(maxRetainedFrames: 1, timeCorrection: savedURL == nil ? nil : correction)
            )
            var accumulator = ServiceResponseTime.StreamingAccumulator(service: service)
            let list = try scanner.scan(onRow: { row in
                if let sessionsInScope, row.sessionID.map(sessionsInScope.contains) != true {
                    return
                }
                accumulator.record(row)
            })
            guard list.completeness == .complete else {
                throw ServiceResponseTime.ScanError.incomplete
            }
            return (accumulator.result(), source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await liveCaptureSpool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity else
        {
            throw CancellationError()
        }
        return result
    }

    /// Capture-wide ICMP/ICMPv6 echo SRT scan. Exact medians require retaining every
    /// measured duration; the reducer bounds both outstanding requests and samples
    /// and fails the scan explicitly if either ceiling is exceeded.
    func scanEchoResponseTime(
        ipv6: Bool,
        sessionsInScope: Set<UUID>?
    )
        async throws -> EchoResponseTime
    {
        guard allFramesUnavailableReason == nil else {
            throw ServiceResponseTime.ScanError.sourceUnavailable(
                allFramesUnavailableReason ?? String(localized: "The capture source is unavailable.")
            )
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-icmp-srt-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let scanner = try CaptureFrameListScanner(
                contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                configuration: .init(maxRetainedFrames: 1, timeCorrection: savedURL == nil ? nil : correction)
            )
            var accumulator = EchoResponseTimeStreamingAccumulator(ipv6: ipv6)
            let list = try scanner.scan(onRow: { row in
                if let sessionsInScope, row.sessionID.map(sessionsInScope.contains) != true {
                    return
                }
                accumulator.record(row)
            })
            guard list.completeness == .complete else {
                throw ServiceResponseTime.ScanError.incomplete
            }
            return (accumulator.result(), source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await liveCaptureSpool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity else
        {
            throw CancellationError()
        }
        return result
    }

    /// Rescan one selected TCP conversation without changing the shared live fold's
    /// per-session retention. The result represents every decoded segment in the
    /// stable source, or fails explicitly at the per-scan bound.
    func scanFullTCPHealth(
        sessionID: UUID,
        onProgress: @escaping @Sendable (PcapStreamProgress) -> Void = { _ in }
    )
        async throws -> FullTCPHealthScanResult
    {
        guard let selectedSession, selectedSession.id == sessionID,
              selectedSession.protocolStack.contains(.tcp) else
        {
            throw TCPHealthSourceScanError.sourceUnavailable(String(localized: "Select a TCP session to analyze."))
        }
        if let reason = allFramesUnavailableReason {
            throw TCPHealthSourceScanError.sourceUnavailable(reason)
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let workspaceID = activeWorkspace.id
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-tcp-health-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let health = try Self.readTCPHealthSource(
                url: source.url, identity: source.identity, token: source.token, sessionID: sessionID,
                correction: savedURL == nil ? nil : correction, onProgress: onProgress
            )
            return (health, source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await spool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              workspaceID == activeWorkspace.id,
              activeWorkspace.selectedSessionID == sessionID,
              selectedSession.id == sessionID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity,
              correction == activeSavedCapture?.timeCorrection,
              allFramesUnavailableReason == nil else
        {
            throw CancellationError()
        }
        return result
    }

    /// Reads a stable source with one retained list row; useful without UI state and
    /// with a small injectable limit for deterministic capacity checks.
    nonisolated static func readTCPHealthSource(
        url: URL,
        identity: PcapFileIdentity,
        token: UUID,
        sessionID: UUID,
        correction: CaptureTimeCorrection?,
        maximumSegments: Int = TCPHealthSourceAccumulator.maximumSegments,
        onProgress: (PcapStreamProgress) -> Void = { _ in }
    )
        throws -> FullTCPHealthScanResult
    {
        let scanner = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: identity, sourceToken: token,
            configuration: .init(maxRetainedFrames: 1, timeCorrection: correction)
        )
        var accumulator = TCPHealthSourceAccumulator(sessionID: sessionID, maximumSegments: maximumSegments)
        let list = try scanner.scan(onProgress: onProgress, onDecodedPacket: { packet, provenance in
            try accumulator.offer(packet, provenance: provenance)
        })
        guard list.completeness == .complete else {
            throw TCPHealthSourceScanError.incompleteSource
        }
        try Task.checkCancellation()
        let summary = try accumulator.summary()
        let health = try TCPStreamHealth(summary: summary, checkingCancellation: { !Task.isCancelled })
        try Task.checkCancellation()
        let result = FullTCPHealthScanResult(
            health: SessionStreamHealth(
                health: health, maximumPointsPerLine: SessionStreamHealth.fullScanMaximumPointsPerLine
            ),
            segmentCount: summary.observations.count
        )
        try Task.checkCancellation()
        return result
    }

    /// Applies an I/O Graph expression to every frame of a stable capture. Zero and
    /// unknown matches still contribute their timestamps to the capture-wide axis.
    func scanFilteredTrafficTimeline(_ expression: FrameExpression) async throws -> FilteredTrafficTimeline {
        if isCapturing || isStarting {
            throw FilteredTrafficTimeline.ScanError.sourceUnavailable(
                String(localized: "Stop the live capture before applying an I/O Graph filter.")
            )
        }
        if let reason = allFramesUnavailableReason {
            throw FilteredTrafficTimeline.ScanError.sourceUnavailable(reason)
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-filtered-traffic-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let scanner = try CaptureFrameListScanner(
                contentsOf: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                configuration: .init(maxRetainedFrames: 1, timeCorrection: savedURL == nil ? nil : correction)
            )
            var accumulator = FilteredTrafficTimelineAccumulator(expression: expression)
            let list = try scanner.scan(onRow: { accumulator.record($0) })
            guard list.completeness == .complete else {
                throw FilteredTrafficTimeline.ScanError.incomplete
            }
            return (accumulator.result(), source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await spool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity,
              correction == activeSavedCapture?.timeCorrection,
              allFramesUnavailableReason == nil else
        {
            throw CancellationError()
        }
        return result
    }

    /// Search typed facts without modifying the applied All Frames expression or scope.
    func findAdjacentFrame(
        matching expression: FrameExpression, after current: UInt64?, forward: Bool
    )
        async throws -> FrameExpressionSearch.NavigationResult
    {
        if let reason = allFramesUnavailableReason {
            throw FrameSearchQuery.Invalid(message: reason)
        }
        let generation = startGeneration
        let projectID = projectStore.activeProjectID
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let correction = activeSavedCapture?.timeCorrection
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-find-expression-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let result = try FrameExpressionSearch.adjacentMatch(
                in: source.url, expectedIdentity: source.identity, sourceToken: source.token,
                expression: expression, after: current, forward: forward,
                timeCorrection: savedURL == nil ? nil : correction
            )
            return (result, source.token)
        }
        let (result, sourceToken) = try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
        if savedURL == nil {
            let currentToken = await spool.currentSourceToken()
            guard liveCaptureSpool === spool, currentToken == sourceToken else {
                throw CancellationError()
            }
        }
        guard !Task.isCancelled,
              generation == startGeneration,
              projectID == projectStore.activeProjectID,
              savedURL == (isViewingSavedCapture ? savedCaptureEvidenceURL : nil),
              savedIdentity == adoptedSavedCaptureIdentity,
              correction == activeSavedCapture?.timeCorrection,
              allFramesUnavailableReason == nil else
        {
            throw CancellationError()
        }
        return result
    }

    /// Find Packet scans the same stable source as All Frames while retaining only
    /// the adjacent match and count, regardless of source length.
    func findAdjacentFrame(
        matching query: FrameSearchQuery, after current: UInt64?, forward: Bool
    )
        async throws -> FrameContentSearch.NavigationResult
    {
        if let reason = allFramesUnavailableReason {
            throw FrameSearchQuery.Invalid(message: reason)
        }
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        let worker = Task.detached(priority: .userInitiated) {
            let temporaryURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("tracexy-find-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            return try FrameContentSearch.adjacentMatch(
                in: source.url, expectedIdentity: source.identity, query: query,
                after: current, forward: forward
            )
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    /// Go to frame `ordinal` as a click on its All Frames row would, listing the
    /// frames first when they are not listed yet. Returns why it cannot, if it cannot.
    @discardableResult
    func goToFrame(_ ordinal: UInt64) -> String? {
        guard let list = allFrames.list, !allFrames.isLoading else {
            allFrames.pendingReveal = ordinal
            loadAllFrames()
            return nil
        }
        if let row = list.rows.first(where: { $0.ordinal == ordinal }) {
            return revealFrame(row) ? nil : String(localized: "Frame \(ordinal.formatted())'s session is not in view.")
        }
        guard ordinal > 0, ordinal <= UInt64(list.scannedFrameCount) else {
            return String(localized: "Frame \(ordinal.formatted()) is outside this capture.")
        }
        let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
        let start = ((Int(ordinal) - 1) / pageSize) * pageSize + 1
        allFrames.pendingReveal = ordinal
        loadAllFrames(force: true, retainedFrameStartOrdinal: start)
        return nil
    }

    /// Open exact bytes for a frame that has no folded session. The source and
    /// generation are rechecked before the bytes window is updated.
    func inspectOrphanFrameBytes(_ row: CaptureFrameRow) async -> OrphanFrameInspectionResult {
        guard row.sessionID == nil, let locator = row.provenance.locator else {
            return .unavailable(String(localized: "This frame has no exact local byte locator."))
        }
        allFrames.orphanFrameInspectionRequestID &+= 1
        let requestID = allFrames.orphanFrameInspectionRequestID
        let generation = startGeneration
        let inspectionRevision = packetBytesInspection.revision
        let savedURL = isViewingSavedCapture ? savedCaptureEvidenceURL : nil
        let savedIdentity = adoptedSavedCaptureIdentity
        let spool = liveCaptureSpool
        do {
            let bytes: [UInt8]
            if let savedURL, let savedIdentity {
                let reference = try SavedCaptureStreamLoader.citedEvidenceReference(
                    for: row.provenance, matching: savedIdentity
                )
                bytes = try await Task.detached(priority: .userInitiated) {
                    try CaptureEvidenceReader.read(reference, from: savedURL)
                }.value
            } else {
                bytes = try await Task.detached(priority: .userInitiated) {
                    try await spool.readCurrentSource(locator, capturedLength: row.provenance.capturedLength)
                }.value
            }
            guard requestID == allFrames.orphanFrameInspectionRequestID,
                  inspectionRevision == packetBytesInspection.revision else
            {
                return .superseded
            }
            guard generation == startGeneration,
                  allFrames.list?.rows.contains(where: { $0.provenance == row.provenance }) == true,
                  !isViewingSavedCapture || (savedCaptureEvidenceURL == savedURL
                      && adoptedSavedCaptureIdentity == savedIdentity) else
            {
                return .unavailable(String(localized: "The capture source changed before this frame could be opened."))
            }
            let frame = CapturedFrame(
                bytes: bytes, timestamp: row.provenance.timestamp,
                originalLength: row.provenance.originalLength,
                capturedLength: row.provenance.capturedLength, linkType: row.provenance.linkType
            )
            let layers = await Task.detached(priority: .userInitiated) {
                SessionBuilder.decodePacket(frame, linkType: row.provenance.linkType).layers
            }.value
            guard requestID == allFrames.orphanFrameInspectionRequestID,
                  inspectionRevision == packetBytesInspection.revision,
                  generation == startGeneration,
                  allFrames.list?.rows.contains(where: { $0.provenance == row.provenance }) == true,
                  !isViewingSavedCapture || (savedCaptureEvidenceURL == savedURL
                      && adoptedSavedCaptureIdentity == savedIdentity) else
            {
                return .superseded
            }
            packetBytesInspection.show(PacketBytesSubject(
                title: String(localized: "Frame \(row.ordinal.formatted())"), bytes: bytes,
                layers: layers, suggestedPresentation: .hexDump
            ))
            return .ready
        } catch {
            guard requestID == allFrames.orphanFrameInspectionRequestID,
                  inspectionRevision == packetBytesInspection.revision else
            {
                return .superseded
            }
            return .unavailable(
                String(localized: "The exact bytes for frame \(row.ordinal.formatted()) are unavailable.")
            )
        }
    }

    /// A row's double-click: select its session in the full table and load that
    /// exact frame in Layers. A frame whose session is not in view (or that belongs
    /// to none) cannot be shown there, and says so.
    @discardableResult
    func revealFrame(_ row: CaptureFrameRow) -> Bool {
        guard let sessionID = row.sessionID, let session = visibleSessions.first(where: { $0.id == sessionID }) else {
            return false
        }
        openSessionsPreservingScope()
        // Open the inspector first, so the row is scrolled into the table's final,
        // shorter viewport rather than into one the inspector then covers.
        if activeWorkspace.inspectorLayout == .hidden {
            toggleInspectorBottom()
        }
        select(session)
        inspectCitedFrame(sessionID: session.id, provenance: row.provenance)
        return true
    }

    /// Clears what the frame tools hold about the capture being replaced: its frame
    /// list, marks, ignores and comments, time references naming its frames,
    /// the bytes Show Packet Bytes shows, and the pending Decode Again prompt (a
    /// capture decoded from here on uses the current Decode As rules).
    func retireCaptureLocalTools() {
        sessionTimeDisplay.clearTimeReferences()
        sessionTimeDisplay.selectedFrame = nil
        packetBytesInspection.subject = nil
        allFrames.cancel(clearList: true)
        allFrames.pendingTableSelection = nil
        allFrames.clearFrameExpression()
        allFrames.clearFrameHighlight()
        exportObjects.cancel(clearLists: true)
        decodeAs.needsRedecode = false
    }

    func retireCaptureLocalToolsForTimeShift(
        from oldCorrection: CaptureTimeCorrection?, to newCorrection: CaptureTimeCorrection?
    )
        -> (shouldReload: Bool, firstOrdinal: Int)
    {
        func shifted(_ reference: FrameTimeReference?) -> FrameTimeReference? {
            guard let reference else {
                return nil
            }
            do {
                let original = try oldCorrection?.inverse().apply(
                    reference.timestamp, frameOrdinal: reference.ordinal
                ) ?? reference.timestamp
                let timestamp = try newCorrection?.apply(original, frameOrdinal: reference.ordinal) ?? original
                return FrameTimeReference(
                    sessionID: reference.sessionID, ordinal: reference.ordinal, timestamp: timestamp
                )
            } catch {
                return nil
            }
        }
        let firstOrdinal = allFrames.list?.firstRetainedOrdinal ?? 1
        let shouldReload = allFrames.list != nil || !allFrames.pinnedFrameRows.isEmpty
            || !allFrames.captureTimeReferenceRows.isEmpty
        sessionTimeDisplay.remapReferences(using: shifted)
        packetBytesInspection.subject = nil
        allFrames.cancel(clearList: true, clearAnnotations: false)
        allFrames.pendingTableSelection = nil
        exportObjects.cancel(clearLists: true)
        decodeAs.needsRedecode = false
        return (shouldReload, firstOrdinal)
    }

    /// ⌘T follows the active frame list: a Session Frames selection remains
    /// session-scoped, while an All Frames selection is capture-wide and keeps
    /// its bounded row visible across pages and display filters.
    func toggleSelectedFrameTimeReference() {
        guard let selected = sessionTimeDisplay.selectedFrame else {
            return
        }
        guard selected.sessionID == nil else {
            let wasCaptureReference = sessionTimeDisplay.isCaptureTimeReference(ordinal: selected.ordinal)
            sessionTimeDisplay.toggleReferenceOnSelectedFrame()
            if wasCaptureReference {
                allFrames.removeCaptureTimeReferenceRow(selected.ordinal)
            }
            return
        }
        if sessionTimeDisplay.isCaptureTimeReference(ordinal: selected.ordinal) {
            sessionTimeDisplay.toggleTimeReference(selected)
            allFrames.removeCaptureTimeReferenceRow(selected.ordinal)
            return
        }
        guard let row = allFrames.captureTimeReferenceRows[selected.ordinal]
            ?? allFrames.list?.rows.first(where: { $0.ordinal == selected.ordinal }) else
        {
            return
        }
        if sessionTimeDisplay.toggleTimeReference(selected) {
            allFrames.retainCaptureTimeReferenceRow(row)
        }
    }

    /// The focused scene supplies its own selection; never infer it from the
    /// last frame selected in another window.
    func toggleFrameTimeReference(_ selected: FrameTimeReference, captureRow: CaptureFrameRow?) {
        if selected.sessionID == nil {
            guard let captureRow, captureRow.ordinal == selected.ordinal,
                  captureRow.provenance.timestamp == selected.timestamp,
                  !allFrames.isLoading, allFrames.list != nil else
            {
                return
            }
        }
        sessionTimeDisplay.selectedFrame = selected
        toggleSelectedFrameTimeReference()
    }

    // MARK: Private

    private func finishAllFrames(
        _ list: CaptureFrameList?, coverage: FrameExpressionCaptureCoverage?, expressionText: String,
        captureTimeReferenceOrdinals: Set<UInt64>,
        requestID: Int, generation: Int
    ) {
        guard requestID == allFrames.requestID, generation == startGeneration else {
            return
        }
        if let list,
           Set(sessionTimeDisplay.captureReferences().map(\.ordinal)) != captureTimeReferenceOrdinals
        {
            loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
            return
        }
        allFrames.isLoading = false
        allFrames.progress = nil
        allFrames.task = nil
        if let list {
            allFrames.list = list
            let refreshedRows = list.rows + list.auxiliaryRows
            allFrames.refreshPinnedFrameRows(from: refreshedRows)
            allFrames.refreshCaptureTimeReferenceRows(from: refreshedRows)
            let expressionChanged = expressionText != allFrames.acceptedFrameExpressionText
            allFrames.captureExpressionCoverage = expressionChanged ? nil : coverage
            allFrames.refreshFrameExpression()
            allFrames.refreshFrameHighlight()
            if expressionChanged {
                loadAllFrames(force: true, retainedFrameStartOrdinal: list.firstRetainedOrdinal)
                return
            }
            // `-g N` at launch: go to that frame once it is listed.
            if let ordinal = allFrames.pendingReveal {
                if let row = list.rows.first(where: { $0.ordinal == ordinal }) {
                    allFrames.pendingReveal = nil
                    if !revealFrame(row) {
                        captureError = String(localized: "Frame \(ordinal.formatted())'s session is not in view.")
                    }
                } else if ordinal > 0, ordinal <= UInt64(list.scannedFrameCount) {
                    let pageSize = CaptureFrameListScanner.Configuration.defaultMaxRetainedFrames
                    let start = ((Int(ordinal) - 1) / pageSize) * pageSize + 1
                    if start != list.firstRetainedOrdinal {
                        loadAllFrames(force: true, retainedFrameStartOrdinal: start)
                    } else {
                        allFrames.pendingReveal = nil
                        captureError = String(localized: "Frame \(ordinal.formatted()) could not be listed.")
                    }
                } else {
                    allFrames.pendingReveal = nil
                    captureError = String(localized: "Frame \(ordinal.formatted()) is outside this capture.")
                }
            }
        }
    }

    private func failAllFrames(_ error: any Error, requestID: Int, generation: Int) {
        guard requestID == allFrames.requestID, generation == startGeneration else {
            return
        }
        allFrames.isLoading = false
        allFrames.progress = nil
        allFrames.task = nil
        allFrames.error = if case FollowStreamError.identityMismatch = error {
            String(localized: "The capture file changed on disk. Reload the capture, then list its frames again.")
        } else {
            String(localized: "Couldn’t list the capture’s frames: \(error.localizedDescription)")
        }
    }
}
