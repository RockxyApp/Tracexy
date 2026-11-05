import Foundation

// MARK: - TrafficGraphComparisonScanError

nonisolated enum TrafficGraphComparisonScanError: LocalizedError, Equatable {
    case sourceUnavailable(String)
    case incomplete

    // MARK: Internal

    var errorDescription: String? {
        switch self {
        case let .sourceUnavailable(reason): reason
        case .incomplete:
            String(localized: "The capture ended before the complete I/O Graph comparison finished.")
        }
    }
}

@MainActor
extension MainContentCoordinator {
    /// Applies every accepted expression in one complete, stable-source pass.
    /// The scanner retains one display row and the comparison fold keeps only
    /// bounded interval buckets per series.
    func scanTrafficGraphComparison(
        _ configuration: TrafficGraphComparisonConfiguration,
        requestedInterval: TimeInterval
    )
        async throws -> TrafficGraphComparison
    {
        guard allFramesUnavailableReason == nil else {
            throw TrafficGraphComparisonScanError.sourceUnavailable(
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
                .appendingPathComponent("tracexy-traffic-comparison-\(UUID().uuidString).pcapng")
            defer { try? FileManager.default.removeItem(at: temporaryURL) }
            let source = try await Self.frameToolSource(
                savedURL: savedURL, savedIdentity: savedIdentity, spool: spool, temporaryURL: temporaryURL
            )
            let comparison = try Self.scanTrafficGraphComparisonSource(
                at: source.url, identity: source.identity, sourceToken: source.token,
                configuration: configuration, requestedInterval: requestedInterval,
                timeCorrection: savedURL == nil ? nil : correction
            )
            return (comparison, source.token)
        }
        let (comparison, sourceToken) = try await withTaskCancellationHandler {
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
        return comparison.usingSourceToken(sourceToken)
    }

    /// Stable-source scanner shared by the coordinator and focused tests.
    nonisolated static func scanTrafficGraphComparisonSource(
        at url: URL,
        identity: PcapFileIdentity,
        sourceToken: UUID,
        configuration: TrafficGraphComparisonConfiguration,
        requestedInterval: TimeInterval = 1,
        timeCorrection: CaptureTimeCorrection? = nil,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> TrafficGraphComparison
    {
        let scanner = try CaptureFrameListScanner(
            contentsOf: url, expectedIdentity: identity, sourceToken: sourceToken,
            configuration: .init(
                maxRetainedFrames: 1, timeCorrection: timeCorrection, isCancelled: isCancelled
            )
        )
        var accumulator = TrafficGraphComparisonAccumulator(configuration: configuration)
        let list = try scanner.scan(onRow: { row in
            guard !isCancelled() else {
                throw CancellationError()
            }
            accumulator.record(row)
        })
        guard list.completeness == .complete else {
            throw TrafficGraphComparisonScanError.incomplete
        }
        guard !isCancelled() else {
            throw CancellationError()
        }
        return accumulator.result(requestedInterval: requestedInterval)
    }
}
