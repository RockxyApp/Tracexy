import Foundation

// MARK: - FollowStreamRun

/// One ordered, contiguous run of retained application bytes in a single
/// direction. `sequenceAnchor` is the absolute TCP sequence number of the run's
/// first byte, and `firstCaptureOrdinal` is the 1-based scan ordinal of the frame
/// that first established that leading byte — a later frame that only extends or
/// bridges the run never displaces the first-observed leading byte or its ordinal.
nonisolated struct FollowStreamRun: Sendable, Equatable {
    /// Absolute TCP sequence number of the first byte in `bytes`.
    let sequenceAnchor: UInt32
    /// 1-based scan ordinal of the frame that first contributed this run's first
    /// byte. Stable under retransmission, overlap and bridging (first-observed).
    let firstCaptureOrdinal: Int
    /// The retained, first-observed contiguous application bytes.
    let bytes: [UInt8]
}

// MARK: - FollowStreamDirectionSnapshot

/// The bounded, ordered reconstruction of one direction. Runs are sorted ascending
/// by sequence offset from the direction anchor and are disjoint; a single run means
/// contiguous coverage. `retainedByteCount` is the number of unique application
/// bytes actually held, while `observedOmittedByteCount` counts byte occurrences
/// that were observed but deliberately not retained because a hard byte/run bound
/// was reached. Neither is capture loss — the source file remains complete.
nonisolated struct FollowStreamDirectionSnapshot: Sendable, Equatable {
    /// The direction anchor: the first observed payload sequence number, or `nil`
    /// when this direction carried no application bytes.
    let anchorSequence: UInt32?
    /// Ordered, disjoint, first-observed byte runs.
    let runs: [FollowStreamRun]
    /// Unique application bytes retained across all runs.
    let retainedByteCount: Int
    /// Saturating count of observed-but-not-retained byte occurrences dropped by a
    /// presentation (byte/run) bound. Distinct from `retainedByteCount`; never a
    /// packet/capture-loss indicator.
    let observedOmittedByteCount: UInt64
    /// Matched frames folded into this direction (payload-bearing or not).
    let matchedFrameCount: Int
}

// MARK: - FollowStreamLimitations

/// The neutral, independently-set limitations that qualify a follow-stream result.
/// Each flag is a separate, honest observation; the absence of a flag never proves
/// the capture was complete or loss-free. Sequence gaps, out-of-order arrival,
/// conflicting overlaps, ambiguous serial distance, captured-frame (snaplen)
/// truncation, run/byte retention truncation and a truncated source tail are all
/// distinct and may co-occur.
nonisolated struct FollowStreamLimitations: OptionSet, Sendable, Equatable {
    /// An unfilled hole remained ahead of a direction's contiguous frontier.
    static let sequenceGap = FollowStreamLimitations(rawValue: 1 << 0)
    /// Segments arrived out of sequence order and were later bridged into place.
    static let outOfOrder = FollowStreamLimitations(rawValue: 1 << 1)
    /// Two frames claimed the same sequence range with disagreeing bytes;
    /// first-observed bytes were preserved.
    static let overlapConflict = FollowStreamLimitations(rawValue: 1 << 2)
    /// A segment's serial distance from its direction anchor was an exact
    /// half-space and could not be placed.
    static let serialAmbiguous = FollowStreamLimitations(rawValue: 1 << 3)
    /// A matched frame's captured length was below its original on-wire length.
    /// This proves frame truncation, but does not guess which omitted trailing bytes
    /// belonged to TCP payload rather than link/network framing.
    static let capturedFrameTruncated = FollowStreamLimitations(rawValue: 1 << 4)
    /// A direction's per-direction run bound was reached and a run was not retained.
    static let runRetentionTruncated = FollowStreamLimitations(rawValue: 1 << 5)
    /// A direction's per-direction byte bound was reached and bytes were not
    /// retained.
    static let byteRetentionTruncated = FollowStreamLimitations(rawValue: 1 << 6)
    /// The source file's tail was cut mid-record/-block; every complete prior frame
    /// was still folded.
    static let sourceTailTruncated = FollowStreamLimitations(rawValue: 1 << 7)

    let rawValue: UInt16
}

// MARK: - FollowStreamCompleteness

/// Whether the scan reached the source file's end cleanly, or stopped on a typed
/// truncated tail after folding every complete prior frame. Derived directly from
/// the streaming reader's terminal, so a truncated terminal stays distinguishable
/// from a clean end.
nonisolated enum FollowStreamCompleteness: Sendable, Equatable {
    case complete
    /// The tail was cut mid-record/-block; this carries the exact terminal reason.
    case incompleteTruncatedTail(CaptureStreamTermination)
}

// MARK: - FollowStreamResult

/// The single immutable result of one on-demand follow-stream read: the opened
/// file identity/format, the requested canonical TCP tuple, both directions'
/// bounded reconstructions, matched/scanned frame counts, the neutral limitations
/// and the source-tail completeness with its final byte progress. It carries raw
/// application bytes only here — never in a `Finding`, session summary or the
/// always-on fold.
nonisolated struct FollowStreamResult: Sendable, Equatable {
    /// Identity of the opened file, snapshotted at open.
    let identity: PcapFileIdentity
    /// The accepted on-disk format chosen by sniffing.
    let format: CaptureStreamFormat
    /// The canonical TCP tuple that was followed.
    let tuple: FiveTuple
    /// Reconstruction of `a → b`.
    let aToB: FollowStreamDirectionSnapshot
    /// Reconstruction of `b → a`.
    let bToA: FollowStreamDirectionSnapshot
    /// Total frames whose decoded tuple exactly equalled `tuple`.
    let matchedFrameCount: Int
    /// Total frames scanned from the file (matched or not).
    let scannedFrameCount: Int
    /// The neutral, independently-set limitations qualifying this result.
    let limitations: FollowStreamLimitations
    /// Whether the source tail was clean or truncated.
    let completeness: FollowStreamCompleteness
    /// Final monotonic byte progress at the streaming terminal.
    let finalProgress: PcapStreamProgress
}

// MARK: - FollowStreamError

/// The two rejections a ``FollowStreamReader`` makes before it will scan a file.
nonisolated enum FollowStreamError: Error, Equatable {
    /// The opened file no longer matches the caller's expected identity.
    case identityMismatch
    /// The requested tuple is not TCP; follow-stream is TCP-only.
    case tupleNotTCP
}
