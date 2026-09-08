import Foundation

// MARK: - CaptureLinkTypeCount

/// One encountered link-layer type and how many accepted frames declared it.
/// Ordered output uses the link type value, so the same capture always reports the
/// same sequence.
nonisolated struct CaptureLinkTypeCount: Equatable, Sendable, Identifiable {
    let linkType: UInt32
    let frameCount: Int

    var id: UInt32 {
        linkType
    }
}

// MARK: - CaptureMetadataSummary

/// The bounded, neutral metadata inventory of one opened capture: which link types
/// its accepted frames declared, how many frames carried no capture time, and how
/// many could not be decoded into any link-layer protocol at all.
///
/// Everything here is a count read off frames that were already accepted — no
/// comment, option, name-resolution or custom block is interpreted, and no meaning
/// is invented for a link type this build does not decode. The link-type map is
/// bounded to ``maxLinkTypeKeys`` distinct keys; frames whose link type arrives
/// after the bound is reached are counted in ``linkTypeOverflowFrameCount`` rather
/// than silently dropped or growing the map without limit.
nonisolated struct CaptureMetadataSummary: Equatable, Sendable {
    /// Maximum distinct link types retained in the counted map.
    static let maxLinkTypeKeys = 64

    static let empty = CaptureMetadataSummary(
        linkTypeCounts: [],
        linkTypeOverflowFrameCount: 0,
        untimedFrameCount: 0,
        undecodableLinkLayerFrameCount: 0,
        totalFrames: 0
    )

    /// Encountered link types with their frame counts, ascending by link type.
    let linkTypeCounts: [CaptureLinkTypeCount]
    /// Frames whose link type could not be retained because the key bound was
    /// already full. Their bytes and totals are unaffected.
    let linkTypeOverflowFrameCount: Int
    /// Accepted frames whose source carried no capture time.
    let untimedFrameCount: Int
    /// Accepted frames the decoder produced no link-layer protocol for. This is a
    /// coverage statement about this build's decoders, never a claim the frame was
    /// malformed.
    let undecodableLinkLayerFrameCount: Int
    /// Every accepted frame the inventory saw.
    let totalFrames: Int
    var firstTimedAt: Date?
    var lastTimedAt: Date?

    /// Whether more than one link type was observed, so a classic single-link-type
    /// representation cannot describe the whole capture.
    var hasMixedLinkTypes: Bool {
        linkTypeCounts.count > 1 || (linkTypeOverflowFrameCount > 0 && !linkTypeCounts.isEmpty)
    }

    /// Whether any counted coverage caveat applies, so a caller can decide whether
    /// to surface the inventory at all.
    var hasCoverageCaveat: Bool {
        untimedFrameCount > 0 || undecodableLinkLayerFrameCount > 0 || linkTypeOverflowFrameCount > 0
    }
}

// MARK: - CaptureMetadataAccumulator

/// A bounded, incremental inventory folded once per accepted frame beside the
/// activity accumulator. Its memory is bounded by ``CaptureMetadataSummary/maxLinkTypeKeys``
/// regardless of capture size, and it retains no bytes, offsets or per-frame history.
nonisolated struct CaptureMetadataAccumulator: Sendable {
    // MARK: Lifecycle

    init(maxLinkTypeKeys: Int = CaptureMetadataSummary.maxLinkTypeKeys) {
        cap = min(CaptureMetadataSummary.maxLinkTypeKeys, max(1, maxLinkTypeKeys))
    }

    // MARK: Internal

    /// Fold one accepted frame.
    ///
    /// - Parameters:
    ///   - linkType: the frame's own declared link type.
    ///   - timestamp: the source capture time, if present; timed bounds include undecodable frames.
    ///   - hasDecodedLinkLayer: whether decoding produced at least one protocol
    ///     layer for it.
    mutating func add(linkType: UInt32, timestamp: Date?, hasDecodedLinkLayer: Bool) {
        totalFrames += 1
        if let timestamp {
            firstTimedAt = firstTimedAt.map { min($0, timestamp) } ?? timestamp
            lastTimedAt = lastTimedAt.map { max($0, timestamp) } ?? timestamp
        } else {
            untimedFrames += 1
        }
        if !hasDecodedLinkLayer {
            undecodableFrames += 1
        }
        if counts[linkType] != nil || counts.count < cap {
            counts[linkType, default: 0] += 1
        } else {
            overflowFrames += 1
        }
    }

    func summary() -> CaptureMetadataSummary {
        CaptureMetadataSummary(
            linkTypeCounts: counts
                .map { CaptureLinkTypeCount(linkType: $0.key, frameCount: $0.value) }
                .sorted { $0.linkType < $1.linkType },
            linkTypeOverflowFrameCount: overflowFrames,
            untimedFrameCount: untimedFrames,
            undecodableLinkLayerFrameCount: undecodableFrames,
            totalFrames: totalFrames,
            firstTimedAt: firstTimedAt,
            lastTimedAt: lastTimedAt
        )
    }

    // MARK: Private

    private let cap: Int
    private var counts: [UInt32: Int] = [:]
    private var overflowFrames = 0
    private var untimedFrames = 0
    private var undecodableFrames = 0
    private var totalFrames = 0
    private var firstTimedAt: Date?
    private var lastTimedAt: Date?
}
