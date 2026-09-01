import Foundation

// MARK: - EvidenceProjectionPipeline

/// The off-main projection of the selected session's retained connection/TLS
/// evidence, with its own request/task guard. Held on the main actor; nothing here
/// crosses actors except the pure ``SessionEvidenceSelection`` result.
struct EvidenceProjectionPipeline {
    /// The published projection for the current selection, or `nil` when nothing is
    /// selected.
    var selection: SessionEvidenceSelection?
    /// Monotonic request id; a superseded refresh cannot publish.
    var requestID = 0
    var task: Task<Void, Never>?
}

// MARK: - SelectedFrameEvidence

/// The one explicitly cited frame: its exact provenance, bounded captured bytes and
/// decoded layers. Selection-scoped and local — never persisted, exported or
/// transported. Carries no path, source token, URL or file identity.
nonisolated struct SelectedFrameEvidence: Hashable, Sendable {
    let sessionID: UUID
    let provenance: SessionFrameProvenance
    /// The exact captured bytes of this one frame, bounded by its captured length.
    let bytes: [UInt8]
    /// The layers decoded from `bytes` off-main under the frame's intrinsic link type.
    let layers: [DecodedLayer]
}

// MARK: - CitedFrameState

/// The coarse state of the one cited-frame inspection slot. It doubles as the load
/// guard: a finish callback publishes only when the slot is still `.loading` the
/// exact provenance it was started for.
nonisolated enum CitedFrameState: Equatable, Sendable {
    /// Nothing cited.
    case idle
    /// The selected citation has no locator, so there is no navigable local frame.
    /// An explicit unavailable state that triggers no read and never falls back.
    case unavailable
    /// A read/decode is in flight for exactly this provenance.
    case loading(SessionFrameProvenance)
    /// The one cited frame's bounded bytes and decoded layers.
    case loaded(SelectedFrameEvidence)
    /// A controlled failure. The message exposes no path or source token.
    case failed(String)
}

// MARK: - CitedFramePipeline

/// The one explicitly cited frame plus its request/task guard.
struct CitedFramePipeline {
    var state: CitedFrameState = .idle
    /// Monotonic request id; a superseded/cleared read cannot publish.
    var requestID = 0
    var task: Task<Void, Never>?
}

// MARK: - CitedFrameSource

/// The source context a cited-frame read was started against, re-checked verbatim
/// before publication so a late task cannot publish across a source boundary.
nonisolated private enum CitedFrameSource: Equatable, Sendable {
    case saved(url: URL, identity: PcapFileIdentity)
    case live(generation: Int)
}

// MARK: - Evidence navigation

@MainActor
extension MainContentCoordinator {
    /// The shared entry point for a direct table/workspace selection change: it retires
    /// the previously cited frame and rebuilds the off-main projection for the newly
    /// selected session. Existing `select(_:)` routes through it too.
    func evidenceNavigationDidChangeSelection() {
        cancelCitedFrame()
        refreshSelectedSessionEvidenceProjection()
    }

    /// Rebuild the selected session's connection/TLS projection off-main and publish
    /// it only behind request, workspace, session and capture-generation guards. A
    /// superseding refresh cancels/retires the prior task. `adoptInvestigation` calls
    /// this so a publication refreshes the current selection without re-assessing
    /// evidence.
    func refreshSelectedSessionEvidenceProjection() {
        evidenceProjection.task?.cancel()
        evidenceProjection.requestID &+= 1
        let requestID = evidenceProjection.requestID
        guard let sessionID = activeWorkspace.selectedSessionID else {
            evidenceProjection.selection = nil
            evidenceProjection.task = nil
            return
        }
        let snapshot = investigationSnapshot
        let workspaceID = activeWorkspace.id
        let expectedGeneration = startGeneration
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            let selection = snapshot.selectingSession(sessionID)
            await self?.publishSelectedSessionEvidenceProjection(
                selection,
                sessionID: sessionID,
                workspaceID: workspaceID,
                requestID: requestID,
                expectedGeneration: expectedGeneration
            )
        }
        evidenceProjection.task = task
    }

    /// Start one guarded exact cited-frame inspection for a session id and provenance.
    /// A nil locator is an explicit unavailable state and triggers no read. Saved and
    /// live/stopped-live sources each resolve exactly one frame; neither copies nor
    /// scans its source, and no fallback frame is ever read.
    func inspectCitedFrame(sessionID: UUID, provenance: SessionFrameProvenance) {
        cancelCitedFrame()
        citedFrame.requestID &+= 1
        let requestID = citedFrame.requestID

        // Only inspect a frame for the currently selected session.
        guard activeWorkspace.selectedSessionID == sessionID else {
            return
        }
        // Nil locator: explicit unavailable, no read, no fallback offset.
        guard let locator = provenance.locator else {
            citedFrame.state = .unavailable
            return
        }

        let workspaceID = activeWorkspace.id
        let expectedGeneration = startGeneration

        if isViewingSavedCapture {
            startSavedCitedFrameRead(
                sessionID: sessionID, provenance: provenance,
                requestID: requestID, workspaceID: workspaceID, expectedGeneration: expectedGeneration
            )
        } else {
            startLiveCitedFrameRead(
                sessionID: sessionID, provenance: provenance, locator: locator,
                requestID: requestID, workspaceID: workspaceID, expectedGeneration: expectedGeneration
            )
        }
    }

    /// Cancel and clear only the cited-frame slot (a selection change or explicit
    /// clear). The projection is left to its own refresh path.
    func cancelCitedFrame() {
        citedFrame.task?.cancel()
        citedFrame.task = nil
        citedFrame.requestID &+= 1
        citedFrame.state = .idle
    }

    /// Retire both evidence-navigation pipelines at a capture/source/clear boundary so
    /// stale projection and cited-frame state can never outlive the source they
    /// described.
    func clearEvidenceNavigation() {
        evidenceProjection.task?.cancel()
        evidenceProjection.task = nil
        evidenceProjection.requestID &+= 1
        evidenceProjection.selection = nil
        cancelCitedFrame()
    }

    /// Test/diagnostic seam for the exact projection task handle; no timing sleeps.
    func waitForEvidenceProjection() async {
        let task = evidenceProjection.task
        await task?.value
    }

    /// Test/diagnostic seam for the exact cited-frame task handle; no timing sleeps.
    func waitForCitedFrame() async {
        let task = citedFrame.task
        await task?.value
    }

    /// The adopted saved file's identity, derived from any retained evidence
    /// reference (all share the one opened file's identity). `nil` for live/idle
    /// sources, so a cited-frame source-token validation cannot pass off-source.
    var adoptedSavedCaptureIdentity: PcapFileIdentity? {
        savedCaptureEvidence.values.first?.identity
    }

    // MARK: Internal publication

    func publishSelectedSessionEvidenceProjection(
        _ selection: SessionEvidenceSelection,
        sessionID: UUID,
        workspaceID: UUID,
        requestID: Int,
        expectedGeneration: Int
    ) {
        guard requestID == evidenceProjection.requestID,
              activeWorkspace.id == workspaceID,
              activeWorkspace.selectedSessionID == sessionID,
              startGeneration == expectedGeneration else
        {
            return
        }
        evidenceProjection.selection = selection
        evidenceProjection.task = nil
    }

    // MARK: Private

    private func startSavedCitedFrameRead(
        sessionID: UUID,
        provenance: SessionFrameProvenance,
        requestID: Int,
        workspaceID: UUID,
        expectedGeneration: Int
    ) {
        guard let url = savedCaptureEvidenceURL, let identity = adoptedSavedCaptureIdentity else {
            citedFrame.state = .failed(Self.citedFrameSourceUnavailableMessage)
            return
        }
        // Validate the locator's source token against the adopted identity before
        // constructing the exact reference; the byte-level identity/length/overrun
        // checks stay in `CaptureEvidenceReader`.
        let reference: CaptureEvidenceReference
        do {
            reference = try SavedCaptureStreamLoader.citedEvidenceReference(for: provenance, matching: identity)
        } catch {
            citedFrame.state = .failed(Self.citedFrameMessage(for: error))
            return
        }
        citedFrame.state = .loading(provenance)
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let bytes = try CaptureEvidenceReader.read(reference, from: url)
                try Task.checkCancellation()
                let evidence = Self.decodeCitedFrame(sessionID: sessionID, provenance: provenance, bytes: bytes)
                await self?.finishCitedFrame(
                    evidence, sessionID: sessionID, workspaceID: workspaceID,
                    requestID: requestID, expectedGeneration: expectedGeneration,
                    source: .saved(url: url, identity: identity)
                )
            } catch is CancellationError {
                // Superseded or cleared: nothing to publish.
            } catch {
                await self?.failCitedFrame(
                    Self.citedFrameMessage(for: error), sessionID: sessionID,
                    workspaceID: workspaceID, requestID: requestID,
                    expectedGeneration: expectedGeneration,
                    source: .saved(url: url, identity: identity),
                    provenance: provenance
                )
            }
        }
        citedFrame.task = task
    }

    private func startLiveCitedFrameRead(
        sessionID: UUID,
        provenance: SessionFrameProvenance,
        locator: SessionEvidenceLocator,
        requestID: Int,
        workspaceID: UUID,
        expectedGeneration: Int
    ) {
        // A finite single-frame spool read is allowed during active capture: the
        // actor validates epoch, source token, synchronized size and exact length. It
        // does not copy or scan the spool and does not change Follow Stream eligibility.
        let spool = liveCaptureSpool
        let capturedLength = provenance.capturedLength
        citedFrame.state = .loading(provenance)
        let task = Task.detached(priority: .userInitiated) { [weak self] in
            do {
                // The coordinator generation advances when a live capture stops,
                // while the finalized spool and its locators intentionally remain
                // the same source. Validate against that source's opaque token;
                // publication still uses the stopped/current generation guards.
                let bytes = try await spool.readCurrentSource(locator, capturedLength: capturedLength)
                try Task.checkCancellation()
                let evidence = Self.decodeCitedFrame(sessionID: sessionID, provenance: provenance, bytes: bytes)
                await self?.finishCitedFrame(
                    evidence, sessionID: sessionID, workspaceID: workspaceID,
                    requestID: requestID, expectedGeneration: expectedGeneration,
                    source: .live(generation: expectedGeneration)
                )
            } catch is CancellationError {
                // Superseded or cleared: nothing to publish.
            } catch {
                await self?.failCitedFrame(
                    Self.citedFrameMessage(for: error), sessionID: sessionID,
                    workspaceID: workspaceID, requestID: requestID,
                    expectedGeneration: expectedGeneration,
                    source: .live(generation: expectedGeneration),
                    provenance: provenance
                )
            }
        }
        citedFrame.task = task
    }

    private func finishCitedFrame(
        _ evidence: SelectedFrameEvidence,
        sessionID: UUID,
        workspaceID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        source: CitedFrameSource
    ) {
        guard requestID == citedFrame.requestID,
              activeWorkspace.id == workspaceID,
              activeWorkspace.selectedSessionID == sessionID,
              startGeneration == expectedGeneration,
              currentSourceMatches(source),
              case let .loading(pending) = citedFrame.state,
              pending == evidence.provenance else
        {
            return
        }
        citedFrame.state = .loaded(evidence)
        citedFrame.task = nil
    }

    private func failCitedFrame(
        _ message: String,
        sessionID: UUID,
        workspaceID: UUID,
        requestID: Int,
        expectedGeneration: Int,
        source: CitedFrameSource,
        provenance: SessionFrameProvenance
    ) {
        guard requestID == citedFrame.requestID,
              activeWorkspace.id == workspaceID,
              activeWorkspace.selectedSessionID == sessionID,
              startGeneration == expectedGeneration,
              currentSourceMatches(source),
              case let .loading(pending) = citedFrame.state,
              pending == provenance else
        {
            return
        }
        citedFrame.state = .failed(message)
        citedFrame.task = nil
    }

    /// Re-check the source kind/URL/identity a read was started against.
    private func currentSourceMatches(_ source: CitedFrameSource) -> Bool {
        switch source {
        case let .saved(url, identity):
            isViewingSavedCapture
                && savedCaptureEvidenceURL == url
                && adoptedSavedCaptureIdentity == identity
        case .live:
            !isViewingSavedCapture
        }
    }

    nonisolated private static func decodeCitedFrame(
        sessionID: UUID,
        provenance: SessionFrameProvenance,
        bytes: [UInt8]
    )
        -> SelectedFrameEvidence
    {
        let frame = CapturedFrame(
            bytes: bytes,
            timestamp: provenance.timestamp,
            originalLength: provenance.originalLength,
            capturedLength: provenance.capturedLength,
            linkType: provenance.linkType
        )
        let packet = SessionBuilder.decodePacket(frame, linkType: provenance.linkType)
        return SelectedFrameEvidence(
            sessionID: sessionID, provenance: provenance, bytes: bytes, layers: packet.layers
        )
    }

    // MARK: Neutral copy

    static var citedFrameSourceUnavailableMessage: String {
        "The capture source for this evidence is unavailable."
    }

    /// Map an error to neutral copy that reveals no path or internal source token.
    nonisolated private static func citedFrameMessage(for error: Error) -> String {
        if let referenceError = error as? CitedFrameReferenceError {
            switch referenceError {
            case .sourceTokenMismatch:
                return "This citation belongs to a different capture source."
            case .missingLocator:
                return "This observation has no navigable local frame."
            }
        }
        if let spoolFailure = error as? LiveCaptureSpool.Failure, case .staleEvidence = spoolFailure {
            return "The requested capture evidence is no longer available."
        }
        return "The cited frame is no longer available in the current capture source."
    }
}
