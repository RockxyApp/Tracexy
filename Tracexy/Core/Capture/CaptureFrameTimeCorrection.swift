import Foundation

/// One export's bounded correction state. Resolves at most two original anchors
/// before writing, then checks them again independently of output scope/filters.
/// The exporter owns cancellation, staged-file cleanup and final source identity.
nonisolated struct CaptureFrameTimeCorrection {
    // MARK: Lifecycle

    init(
        options: FrameExportOptions, source: URL, destination: URL, identity: PcapFileIdentity,
        isCancelled: @escaping @Sendable () -> Bool
    )
        throws
    {
        try Self.validateOptions(options)
        self.source = source
        self.destination = destination
        self.identity = identity
        legacyShift = options.shiftsTimeBy
        baseCorrection = options.baseTimeCorrection
        request = options.timeCorrection
        if let request = options.timeCorrection {
            try Self.validateDestination(destination, source: source, identity: identity)
            anchorTimes = try Self.readAnchorTimes(
                request, from: source, identity: identity, isCancelled: isCancelled
            )
            correction = try request.resolved(originalTimes: anchorTimes)
        } else {
            anchorTimes = [:]
            correction = nil
        }
        remainingAnchors = Set(anchorTimes.keys)
        remainingBaseAnchors = baseCorrection?.anchorFrameOrdinals ?? []
    }

    // MARK: Internal

    var provenanceComments: [String] {
        var requests: [CaptureTimeCorrectionRequest] = []
        if let request {
            if request.anchorOrdinals.isEmpty, let baseCorrection {
                requests.append(baseCorrection.request)
            }
            requests.append(request)
        } else if let baseCorrection {
            requests.append(baseCorrection.request)
        }
        if legacyShift != 0 {
            requests.append(.shiftBy(legacyShift))
        }
        return requests.map(\.provenanceComment)
    }

    static func validateOptions(_ options: FrameExportOptions) throws {
        if options.baseTimeCorrection != nil {
            guard options.format == .pcapng else {
                throw FrameExportError.timeCorrectionRequiresPcapng
            }
            guard !options.compressesWithGzip else {
                throw FrameExportError.timeCorrectionRequiresUncompressedOutput
            }
        }
        guard let request = options.timeCorrection else {
            return
        }
        try request.validate()
        guard options.format == .pcapng else {
            throw FrameExportError.timeCorrectionRequiresPcapng
        }
        if options.shiftsTimeBy != 0 {
            throw FrameExportError.conflictingTimeCorrections
        }
        guard !options.compressesWithGzip else {
            throw FrameExportError.timeCorrectionRequiresUncompressedOutput
        }
    }

    static func retimed(_ event: CaptureFrameEvent, to timestamp: Date?) -> CaptureFrameEvent {
        let reference = event.reference
        return CaptureFrameEvent(
            reference: CaptureFrameReference(
                payloadOffset: reference.payloadOffset, capturedLength: reference.capturedLength,
                originalLength: reference.originalLength, timestamp: timestamp,
                direction: reference.direction, packetFlags: reference.packetFlags, packetID: reference.packetID,
                linkType: reference.linkType, sectionIndex: reference.sectionIndex, interfaceID: reference.interfaceID,
                hasComment: reference.hasComment, hasPacketOptions: reference.hasPacketOptions,
                frameCommentReference: reference.frameCommentReference,
                packetOptionsReference: reference.packetOptionsReference,
                copyableOptionsRange: reference.copyableOptionsRange
            ),
            bytes: event.bytes,
            progress: event.progress
        )
    }

    mutating func validate(_ event: CaptureFrameEvent, ordinal: UInt64) throws {
        if let originalTime = anchorTimes[ordinal] {
            guard event.reference.timestamp == originalTime else {
                throw CaptureTimeCorrection.Error.changedAnchor(frameOrdinal: ordinal)
            }
            remainingAnchors.remove(ordinal)
        }
        if let baseCorrection {
            _ = try baseCorrection.apply(event.reference.timestamp, frameOrdinal: ordinal)
            remainingBaseAnchors.remove(ordinal)
        }
    }

    func apply(to event: CaptureFrameEvent, ordinal: UInt64) throws -> CaptureFrameEvent {
        let timestamp: Date?
        if let correction, request?.anchorOrdinals.isEmpty == false {
            timestamp = try correction.apply(event.reference.timestamp, frameOrdinal: ordinal)
        } else {
            let baseTimestamp: Date? = if let baseCorrection {
                try baseCorrection.apply(event.reference.timestamp, frameOrdinal: ordinal)
            } else {
                event.reference.timestamp
            }
            if let correction {
                timestamp = try correction.apply(baseTimestamp)
            } else {
                timestamp = baseTimestamp
            }
        }
        if legacyShift != 0, let timestamp {
            return Self.retimed(event, to: timestamp.addingTimeInterval(legacyShift))
        }
        return timestamp == event.reference.timestamp ? event : Self.retimed(event, to: timestamp)
    }

    func eventForScope(_ event: CaptureFrameEvent, ordinal: UInt64) throws -> CaptureFrameEvent {
        guard let baseCorrection else {
            return event
        }
        return try Self.retimed(
            event, to: baseCorrection.apply(event.reference.timestamp, frameOrdinal: ordinal)
        )
    }

    func captureComments(from sourceComments: [String], anonymizingAddresses: Bool) -> [String] {
        guard !provenanceComments.isEmpty else {
            return anonymizingAddresses ? [] : sourceComments
        }
        guard !anonymizingAddresses else {
            return provenanceComments
        }
        let generated = Set(provenanceComments)
        return sourceComments.filter { !generated.contains($0) } + provenanceComments
    }

    func finish() throws {
        if let missing = remainingAnchors.min() {
            throw CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: missing)
        }
        if let missing = remainingBaseAnchors.min() {
            throw CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: missing)
        }
        if correction != nil || baseCorrection != nil {
            try Self.validateDestination(destination, source: source, identity: identity)
        }
    }

    // MARK: Private

    private let source: URL
    private let destination: URL
    private let identity: PcapFileIdentity
    private let legacyShift: TimeInterval
    private let baseCorrection: CaptureTimeCorrection?
    private let request: CaptureTimeCorrectionRequest?
    private let correction: CaptureTimeCorrection?
    private let anchorTimes: [UInt64: Date]
    private var remainingAnchors: Set<UInt64>
    private var remainingBaseAnchors: Set<UInt64>

    private static func readAnchorTimes(
        _ request: CaptureTimeCorrectionRequest, from source: URL, identity: PcapFileIdentity,
        isCancelled: @escaping @Sendable () -> Bool
    )
        throws -> [UInt64: Date]
    {
        var remaining = request.anchorOrdinals
        guard !remaining.isEmpty else {
            return [:]
        }
        let reader = try CaptureStreamReader(contentsOf: source, configuration: .init(isCancelled: isCancelled))
        guard reader.identity.matches(identity) else {
            throw FrameExportError.identityMismatch
        }
        var ordinal: UInt64 = 0
        var result: [UInt64: Date] = [:]
        while let missing = remaining.min() {
            switch try reader.next() {
            case let .frame(event):
                let (next, overflow) = ordinal.addingReportingOverflow(1)
                guard !overflow else {
                    throw CaptureTimeCorrection.Error.anchorOrdinalOverflow
                }
                ordinal = next
                guard remaining.remove(ordinal) != nil else {
                    continue
                }
                guard let timestamp = event.reference.timestamp else {
                    throw CaptureTimeCorrection.Error.untimedAnchor(frameOrdinal: ordinal)
                }
                result[ordinal] = timestamp
            case .end:
                throw CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: missing)
            }
        }
        return result
    }

    private static func validateDestination(_ destination: URL, source: URL, identity: PcapFileIdentity) throws {
        guard destination.resolvingSymlinksInPath().standardizedFileURL != source.resolvingSymlinksInPath()
            .standardizedFileURL else
        {
            throw FrameExportError.timeCorrectionNeedsDistinctDestination
        }
        if let handle = try? FileHandle(forReadingFrom: destination) {
            defer { try? handle.close() }
            let existing = PcapFileIdentity.snapshot(of: handle)
            guard existing.device != identity.device || existing.inode != identity.inode else {
                throw FrameExportError.timeCorrectionNeedsDistinctDestination
            }
        }
    }
}
