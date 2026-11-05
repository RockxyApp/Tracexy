import Foundation

// MARK: - CaptureTimeCorrection

/// A validated, capture-wide time transform. Anchors refer to the original source;
/// resolving those frames and checking the source identity belong to the caller.
/// Results must fit the PCAPNG writer's unsigned microsecond counter. This type
/// does not round dates, read packets, change a source, or manufacture missing time.
nonisolated struct CaptureTimeCorrection: Sendable, Hashable {
    // MARK: Lifecycle

    init(shiftBy seconds: TimeInterval) throws {
        guard seconds.isFinite else {
            throw Error.nonfiniteShift
        }
        basis = .shift(seconds)
        scale = 1
    }

    init(anchor: Anchor) throws {
        try Self.validate(anchor)
        basis = .anchor(anchor)
        scale = 1
    }

    init(first: Anchor, second: Anchor) throws {
        try Self.validate(first)
        try Self.validate(second)
        guard first.frameOrdinal != second.frameOrdinal else {
            throw Error.duplicateAnchorFrames
        }
        let originalInterval = second.originalTime.timeIntervalSince(first.originalTime)
        guard originalInterval.isFinite else {
            throw Error.unrepresentableAnchorInterval
        }
        guard originalInterval != 0 else {
            throw Error.coincidentOriginalTimes
        }
        let correctedInterval = second.correctedTime.timeIntervalSince(first.correctedTime)
        let rate = correctedInterval / originalInterval
        guard rate.isFinite, rate > 0 else {
            throw Error.invalidScale
        }
        basis = .anchors(first: first, second: second)
        scale = rate
    }

    // MARK: Internal

    struct Anchor: Sendable, Hashable {
        let frameOrdinal: UInt64
        let originalTime: Date
        let correctedTime: Date
    }

    enum Basis: Sendable, Hashable {
        case shift(TimeInterval)
        case anchor(Anchor)
        case anchors(first: Anchor, second: Anchor)
    }

    enum Error: LocalizedError, Equatable {
        case nonfiniteShift
        case invalidFrameOrdinal
        case duplicateAnchorFrames
        case nonfiniteOriginalTime
        case coincidentOriginalTimes
        case unrepresentableAnchorInterval
        case invalidScale
        case unrepresentableCorrectedTime
        case anchorOrdinalOverflow
        case missingAnchor(frameOrdinal: UInt64)
        case untimedAnchor(frameOrdinal: UInt64)
        case changedAnchor(frameOrdinal: UInt64)

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case .nonfiniteShift:
                "The time shift must be a finite number of seconds."
            case .invalidFrameOrdinal:
                "A time anchor must use a frame number starting at one."
            case .duplicateAnchorFrames:
                "Choose two different frames for clock-drift correction."
            case .nonfiniteOriginalTime:
                "The original capture time is not a finite instant."
            case .coincidentOriginalTimes:
                "The two anchor frames must have different original times."
            case .unrepresentableAnchorInterval:
                "The interval between the original anchor times is too large to correct."
            case .invalidScale:
                "The corrected anchor times must preserve time order and define a finite positive clock rate."
            case .unrepresentableCorrectedTime:
                "A corrected time cannot be represented in the output PCAPNG file."
            case .anchorOrdinalOverflow:
                "An anchor frame number is too large to resolve safely."
            case let .missingAnchor(frameOrdinal):
                "Anchor frame \(frameOrdinal.formatted()) does not exist in the capture."
            case let .untimedAnchor(frameOrdinal):
                "Anchor frame \(frameOrdinal.formatted()) has no recorded capture time."
            case let .changedAnchor(frameOrdinal):
                "Anchor frame \(frameOrdinal.formatted()) changed while exporting. Reload the capture and export again."
            }
        }
    }

    /// Retains the investigator's original anchors for correction provenance.
    let basis: Basis
    /// Corrected elapsed seconds per original elapsed second. A constant shift is one.
    let scale: Double

    var anchorFrameOrdinals: Set<UInt64> {
        switch basis {
        case .shift:
            []
        case let .anchor(anchor):
            [anchor.frameOrdinal]
        case let .anchors(first, second):
            [first.frameOrdinal, second.frameOrdinal]
        }
    }

    var streamTransform: @Sendable (Date?, UInt64) throws -> Date? {
        { timestamp, ordinal in
            try apply(timestamp, frameOrdinal: ordinal)
        }
    }

    var request: CaptureTimeCorrectionRequest {
        switch basis {
        case let .shift(seconds): .shiftBy(seconds)
        case let .anchor(anchor):
            .anchor(frameOrdinal: anchor.frameOrdinal, correctedTime: anchor.correctedTime)
        case let .anchors(first, second):
            .anchors(
                firstFrameOrdinal: first.frameOrdinal, firstCorrectedTime: first.correctedTime,
                secondFrameOrdinal: second.frameOrdinal, secondCorrectedTime: second.correctedTime
            )
        }
    }

    /// Applies the same transform to any known source instant, including times
    /// outside the anchor interval. Unknown source times remain unknown. Output
    /// dates are validated without clipping, epoch substitution, or rounding.
    func apply(_ timestamp: Date?) throws -> Date? {
        guard let timestamp else {
            return nil
        }
        try Self.validateOriginal(timestamp)
        let corrected: Date = switch basis {
        case let .shift(seconds):
            timestamp.addingTimeInterval(seconds)
        case let .anchor(anchor):
            Self.corrected(timestamp, from: anchor, scale: scale)
        case let .anchors(first, second):
            // Preserve the supplied target exactly at either defining anchor.
            timestamp == second.originalTime
                ? second.correctedTime
                : Self.corrected(timestamp, from: first, scale: scale)
        }
        try Self.validateCorrected(corrected)
        return corrected
    }

    /// Applies the correction to one frame while confirming that the original
    /// timestamp at each defining anchor still matches the resolved source.
    func apply(_ timestamp: Date?, frameOrdinal: UInt64) throws -> Date? {
        if let expected = originalTime(at: frameOrdinal), timestamp != expected {
            throw Error.changedAnchor(frameOrdinal: frameOrdinal)
        }
        return try apply(timestamp)
    }

    func inverse() throws -> CaptureTimeCorrection {
        switch basis {
        case let .shift(seconds):
            try CaptureTimeCorrection(shiftBy: -seconds)
        case let .anchor(anchor):
            try CaptureTimeCorrection(anchor: .init(
                frameOrdinal: anchor.frameOrdinal,
                originalTime: anchor.correctedTime,
                correctedTime: anchor.originalTime
            ))
        case let .anchors(first, second):
            try CaptureTimeCorrection(
                first: .init(
                    frameOrdinal: first.frameOrdinal,
                    originalTime: first.correctedTime,
                    correctedTime: first.originalTime
                ),
                second: .init(
                    frameOrdinal: second.frameOrdinal,
                    originalTime: second.correctedTime,
                    correctedTime: second.originalTime
                )
            )
        }
    }

    func addingShift(_ seconds: TimeInterval) throws -> CaptureTimeCorrection {
        guard seconds.isFinite else {
            throw Error.nonfiniteShift
        }
        func shifted(_ anchor: Anchor) throws -> Anchor {
            let target = anchor.correctedTime.addingTimeInterval(seconds)
            try Self.validateCorrected(target)
            return .init(
                frameOrdinal: anchor.frameOrdinal,
                originalTime: anchor.originalTime,
                correctedTime: target
            )
        }
        switch basis {
        case let .shift(current):
            return try CaptureTimeCorrection(shiftBy: current + seconds)
        case let .anchor(anchor):
            return try CaptureTimeCorrection(anchor: shifted(anchor))
        case let .anchors(first, second):
            return try CaptureTimeCorrection(first: shifted(first), second: shifted(second))
        }
    }

    // MARK: Fileprivate

    fileprivate static func validateCorrected(_ date: Date) throws {
        guard (try? CaptureTimestampEncoding.microseconds(date)) != nil else {
            throw Error.unrepresentableCorrectedTime
        }
    }

    // MARK: Private

    private static func corrected(_ timestamp: Date, from anchor: Anchor, scale: Double) -> Date {
        if timestamp == anchor.originalTime {
            return anchor.correctedTime
        }
        let elapsed = timestamp.timeIntervalSince(anchor.originalTime)
        // Keep differences in Date's reference epoch. A fused operation avoids
        // separately overflowing or rounding the product before adding the target.
        let interval = anchor.correctedTime.timeIntervalSinceReferenceDate.addingProduct(elapsed, scale)
        return Date(timeIntervalSinceReferenceDate: interval)
    }

    private static func validate(_ anchor: Anchor) throws {
        guard anchor.frameOrdinal > 0 else {
            throw Error.invalidFrameOrdinal
        }
        try validateOriginal(anchor.originalTime)
        try validateCorrected(anchor.correctedTime)
    }

    private static func validateOriginal(_ date: Date) throws {
        guard date.timeIntervalSinceReferenceDate.isFinite else {
            throw Error.nonfiniteOriginalTime
        }
    }

    private func originalTime(at frameOrdinal: UInt64) -> Date? {
        switch basis {
        case .shift:
            nil
        case let .anchor(anchor):
            frameOrdinal == anchor.frameOrdinal ? anchor.originalTime : nil
        case let .anchors(first, second):
            if frameOrdinal == first.frameOrdinal {
                first.originalTime
            } else if frameOrdinal == second.frameOrdinal {
                second.originalTime
            } else {
                nil
            }
        }
    }
}

// MARK: - CaptureTimeCorrectionRequest

/// A UI-safe correction specification. Source timestamps are resolved off-main
/// from original frame ordinals before constructing the mathematical transform.
nonisolated enum CaptureTimeCorrectionRequest: Sendable, Equatable {
    case shiftBy(TimeInterval)
    case anchor(frameOrdinal: UInt64, correctedTime: Date)
    case anchors(
        firstFrameOrdinal: UInt64, firstCorrectedTime: Date,
        secondFrameOrdinal: UInt64, secondCorrectedTime: Date
    )

    // MARK: Internal

    static let provenanceCommentPrefix = "Tracexy timestamp correction:"

    var anchorOrdinals: Set<UInt64> {
        switch self {
        case .shiftBy: []
        case let .anchor(ordinal, _): [ordinal]
        case let .anchors(first, _, second, _): [first, second]
        }
    }

    /// Bounded to numeric values and fixed text; contains no source paths or names.
    /// Call `validate()` before using the request or writing this provenance.
    var provenanceComment: String {
        let method = switch self {
        case let .shiftBy(seconds):
            "Constant shift: \(seconds) seconds."
        case let .anchor(ordinal, target):
            "Anchor frame \(ordinal): corrected Unix time \(target.timeIntervalSince1970) seconds."
        case let .anchors(first, firstTarget, second, secondTarget):
            "Linear clock correction: frame \(first) to Unix time \(firstTarget.timeIntervalSince1970) seconds; "
                + "frame \(second) to Unix time \(secondTarget.timeIntervalSince1970) seconds."
        }
        return "\(Self.provenanceCommentPrefix) \(method) Anchor ordinals refer to the original capture. "
            + "Output timestamps use PCAPNG microseconds; source times may have finer precision."
    }

    func validate() throws {
        if anchorOrdinals.contains(0) {
            throw CaptureTimeCorrection.Error.invalidFrameOrdinal
        }
        switch self {
        case let .shiftBy(seconds):
            guard seconds.isFinite else {
                throw CaptureTimeCorrection.Error.nonfiniteShift
            }
        case let .anchor(_, target):
            try CaptureTimeCorrection.validateCorrected(target)
        case let .anchors(first, firstTarget, second, secondTarget):
            guard first != second else {
                throw CaptureTimeCorrection.Error.duplicateAnchorFrames
            }
            try CaptureTimeCorrection.validateCorrected(firstTarget)
            try CaptureTimeCorrection.validateCorrected(secondTarget)
        }
    }

    func resolved(originalTimes: [UInt64: Date]) throws -> CaptureTimeCorrection {
        try validate()
        func anchor(_ ordinal: UInt64, _ target: Date) throws -> CaptureTimeCorrection.Anchor {
            guard let original = originalTimes[ordinal] else {
                throw CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: ordinal)
            }
            return .init(frameOrdinal: ordinal, originalTime: original, correctedTime: target)
        }
        return switch self {
        case let .shiftBy(seconds):
            try CaptureTimeCorrection(shiftBy: seconds)
        case let .anchor(ordinal, target):
            try CaptureTimeCorrection(anchor: anchor(ordinal, target))
        case let .anchors(first, firstTarget, second, secondTarget):
            try CaptureTimeCorrection(first: anchor(first, firstTarget), second: anchor(second, secondTarget))
        }
    }

    func addingFrameOrdinalOffset(_ offset: UInt64) throws -> Self {
        try validate()
        func shifted(_ ordinal: UInt64) throws -> UInt64 {
            let (result, overflow) = ordinal.addingReportingOverflow(offset)
            guard !overflow else {
                throw CaptureTimeCorrection.Error.anchorOrdinalOverflow
            }
            return result
        }
        return switch self {
        case .shiftBy: self
        case let .anchor(ordinal, target):
            try .anchor(frameOrdinal: shifted(ordinal), correctedTime: target)
        case let .anchors(first, firstTarget, second, secondTarget):
            try .anchors(
                firstFrameOrdinal: shifted(first), firstCorrectedTime: firstTarget,
                secondFrameOrdinal: shifted(second), secondCorrectedTime: secondTarget
            )
        }
    }

    /// Resolve anchor ordinals against one unchanged capture before a caller
    /// publishes an in-memory correction. At most the requested two timestamps
    /// are retained, and the walk stops at the last anchor.
    func resolved(
        in source: URL,
        expectedIdentity: PcapFileIdentity,
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        throws -> CaptureTimeCorrection
    {
        try validate()
        guard !anchorOrdinals.isEmpty else {
            return try resolved(originalTimes: [:])
        }
        let reader = try CaptureStreamReader(
            contentsOf: source, configuration: .init(isCancelled: isCancelled)
        )
        guard reader.identity.matches(expectedIdentity) else {
            throw FrameExportError.identityMismatch
        }
        var remaining = anchorOrdinals
        var originalTimes: [UInt64: Date] = [:]
        var ordinal: UInt64 = 0
        while let missing = remaining.min() {
            try Task.checkCancellation()
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
                originalTimes[ordinal] = timestamp
            case .end:
                throw CaptureTimeCorrection.Error.missingAnchor(frameOrdinal: missing)
            }
        }
        let pathHandle = try FileHandle(forReadingFrom: source)
        let pathIdentity = PcapFileIdentity.snapshot(of: pathHandle)
        try pathHandle.close()
        guard pathIdentity.matches(expectedIdentity) else {
            throw FrameExportError.identityMismatch
        }
        return try resolved(originalTimes: originalTimes)
    }
}
