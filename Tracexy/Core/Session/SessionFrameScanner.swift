import Foundation

// MARK: - SessionFrameDirection

nonisolated enum SessionFrameDirection: Sendable, Equatable {
    case clientToServer
    case serverToClient
    case unknown
}

// MARK: - SessionFrameReference

/// One frame of the selected session as the Frames facet lists it: where it is
/// in the capture, when, how big, which way it went, and a one-line decoded
/// summary. It carries no bytes; a row click resolves the exact frame through
/// the existing cited-frame path using ``provenance``.
nonisolated struct SessionFrameReference: Sendable, Equatable, Identifiable {
    /// Maximum retained summary length in characters.
    static let maxSummaryLength = 96

    let provenance: SessionFrameProvenance
    let direction: SessionFrameDirection
    let interfaceID: Int
    let tcpFlags: TCPFlags?
    let hasComment: Bool
    /// The innermost decoded layer's title and summary, bounded.
    let summary: String
    /// Seconds since the first matched frame; `nil` when either is untimed.
    let relativeTime: TimeInterval?

    var id: UInt64 {
        provenance.ordinal.rawValue
    }

    var ordinal: UInt64 {
        provenance.ordinal.rawValue
    }
}

// MARK: - SessionFramesResult

/// The bounded outcome of one ``SessionFrameScanner`` pass.
nonisolated struct SessionFramesResult: Sendable, Equatable {
    let sessionID: UUID
    let identity: PcapFileIdentity
    /// Matched frames in capture order, at most ``SessionFrameScanner/Configuration/maxRetainedFrames``.
    let frames: [SessionFrameReference]
    /// Every frame that matched the session, including those beyond the bound.
    let matchedFrameCount: Int
    let scannedFrameCount: Int
    let completeness: CaptureLoadCompleteness
    let finalProgress: PcapStreamProgress

    var omittedFrameCount: Int {
        max(0, matchedFrameCount - frames.count)
    }
}

// MARK: - SessionFrameScanner

/// A pure, synchronous, on-demand rescan of a *stable* capture that lists the
/// frames belonging to one session. It mirrors ``FollowStreamReader``'s
/// contract: one ``CaptureStreamReader``, identity checked before and after,
/// every frame decoded once through the shared decode seam, and matching by the
/// same deterministic session identity the fold uses (`SessionBuilder.sessionID`
/// over the decoded canonical tuple) — so the list agrees with the Sessions
/// table for any protocol, not only TCP.
///
/// Memory is bounded by ``Configuration/maxRetainedFrames`` references (no
/// bytes); frames past the bound are counted, never retained.
nonisolated final class SessionFrameScanner {
    // MARK: Lifecycle

    init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        sessionID: UUID,
        sourceToken: UUID,
        clientEndpoint: IPEndpoint?,
        configuration: Configuration = Configuration()
    )
        throws
    {
        self.sessionID = sessionID
        self.sourceToken = sourceToken
        self.clientEndpoint = clientEndpoint
        self.configuration = configuration
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(
                maxCapturedLength: configuration.maxCapturedLength,
                isCancelled: configuration.isCancelled
            )
        )
        guard reader.identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        self.reader = reader
        sourceURL = url
    }

    // MARK: Internal

    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            maxRetainedFrames: Int = Configuration.defaultMaxRetainedFrames,
            progressStride: Int = 512,
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.maxCapturedLength = maxCapturedLength
            self.maxRetainedFrames = min(Configuration.defaultMaxRetainedFrames, max(1, maxRetainedFrames))
            self.progressStride = max(1, progressStride)
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        static let defaultMaxRetainedFrames = 10_000

        let maxCapturedLength: Int
        let maxRetainedFrames: Int
        let progressStride: Int
        let isCancelled: @Sendable () -> Bool
    }

    func scan(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> SessionFramesResult {
        var scanned = 0
        var matched = 0
        var frames: [SessionFrameReference] = []
        var firstTimestamp: Date?
        let completion: CaptureStreamCompletion
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                if let reference = match(event, ordinal: scanned, firstTimestamp: &firstTimestamp) {
                    matched += 1
                    if frames.count < configuration.maxRetainedFrames {
                        frames.append(reference)
                    }
                }
                if scanned % configuration.progressStride == 0 {
                    onProgress(event.progress)
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        try revalidateSourceIdentity()
        onProgress(completion.progress)
        let completeness: CaptureLoadCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }
        return SessionFramesResult(
            sessionID: sessionID,
            identity: reader.identity,
            frames: frames,
            matchedFrameCount: matched,
            scannedFrameCount: scanned,
            completeness: completeness,
            finalProgress: completion.progress
        )
    }

    // MARK: Private

    private let sessionID: UUID
    private let sourceToken: UUID
    private let clientEndpoint: IPEndpoint?
    private let configuration: Configuration
    private let reader: CaptureStreamReader
    private let sourceURL: URL

    private static func summary(of packet: DecodedPacket) -> String {
        guard let layer = packet.layers.last else {
            return ""
        }
        var text = layer.title
        if !layer.summary.isEmpty {
            text += " — " + layer.summary
        }
        if text.count > SessionFrameReference.maxSummaryLength {
            text = String(text.prefix(SessionFrameReference.maxSummaryLength - 1)) + "…"
        }
        return text
    }

    private func match(
        _ event: CaptureFrameEvent,
        ordinal: Int,
        firstTimestamp: inout Date?
    )
        -> SessionFrameReference?
    {
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        let packet = SessionBuilder.decodePacket(
            frame, linkType: reader.defaultLinkType ?? event.reference.linkType
        )
        guard let tuple = packet.fiveTuple, SessionBuilder.sessionID(for: tuple) == sessionID else {
            return nil
        }
        let direction: SessionFrameDirection = if let client = clientEndpoint, let source = packet.sourceEndpoint {
            source == client ? .clientToServer : .serverToClient
        } else {
            .unknown
        }
        if firstTimestamp == nil {
            firstTimestamp = event.reference.timestamp
        }
        let relative: TimeInterval? = if let first = firstTimestamp, let own = event.reference.timestamp {
            own.timeIntervalSince(first)
        } else {
            nil
        }
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64(ordinal)),
            timestamp: event.reference.timestamp,
            capturedLength: event.reference.capturedLength,
            originalLength: event.reference.originalLength,
            linkType: event.reference.linkType,
            locator: SessionEvidenceLocator(sourceToken: sourceToken, offset: event.reference.payloadOffset)
        )
        return SessionFrameReference(
            provenance: provenance,
            direction: direction,
            interfaceID: event.reference.interfaceID,
            tcpFlags: packet.tcpFacts?.flags,
            hasComment: event.reference.hasComment,
            summary: Self.summary(of: packet),
            relativeTime: relative
        )
    }

    private func revalidateSourceIdentity() throws {
        let handle = try FileHandle(forReadingFrom: sourceURL)
        defer { try? handle.close() }
        guard PcapFileIdentity.snapshot(of: handle).matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
    }
}
