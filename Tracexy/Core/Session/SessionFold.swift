import Foundation

// MARK: - SessionFrameContext

/// The format-neutral, per-frame context the common session/connection fold needs
/// beyond the decoded packet itself.
///
/// It is deliberately Capture-format-agnostic: it carries the captured length, the
/// frame's intrinsic link type, an optional opaque ``SessionEvidenceLocator`` and
/// the ``CaptureLossKnowledge`` for the frame — and **no** bytes, URL, file identity
/// or Capture-layer type. The one-based capture ordinal is *not* carried here: the
/// ``SessionAccumulator`` owns and assigns it in accepted-frame order, so a caller
/// can neither fabricate nor skew capture order.
nonisolated struct SessionFrameContext: Hashable, Sendable {
    // MARK: Lifecycle

    init(
        capturedLength: Int,
        linkType: UInt32,
        locator: SessionEvidenceLocator? = nil,
        loss: CaptureLossKnowledge = .unknown
    ) {
        self.capturedLength = capturedLength
        self.linkType = linkType
        self.locator = locator
        self.loss = loss
    }

    // MARK: Internal

    /// Bytes actually captured for this frame (may be below the on-wire length).
    let capturedLength: Int
    /// The frame's intrinsic link type. The caller resolves "intrinsic per-frame
    /// wins, else the source default" before constructing the context.
    let linkType: UInt32
    /// An optional opaque pointer back to the bytes that justify an observation.
    /// Live-spool and saved-file folds mint locators when their source is available;
    /// batch callers and evidence-source failures legitimately leave this `nil`.
    let locator: SessionEvidenceLocator?
    /// What we know about capture completeness for this frame.
    let loss: CaptureLossKnowledge
}

// MARK: - SessionFoldSnapshot

/// The additive, immutable result of the common fold: the unchanged session
/// summaries in first-seen order, the connection-table snapshot for the same
/// ordered frames, and the DNS/ICMP datagram evidence folded from those frames.
///
/// The `sessions` array is byte-for-byte the value the session-only path already
/// produced; `connections` and `datagramEvidence` are additive evidence. Nothing
/// here is exposed in Views yet.
nonisolated struct SessionFoldSnapshot: Sendable {
    let sessions: [SessionSummary]
    let connections: ConnectionTable.Snapshot
    /// Bounded, cross-path-equal DNS/ICMP datagram evidence for the same ordered
    /// frames. Additive alongside `connections`; keyed by tuple-derived session id.
    let datagramEvidence: DatagramEvidenceTable.Snapshot
    /// Bounded, cross-path-equal TLS record evidence for the same ordered frames.
    /// Additive alongside `datagramEvidence`; keyed by tuple-derived session id. Direct
    /// per-frame records are retained with exact provenance; multi-frame recovered
    /// records are excluded-counted, never cited.
    let tlsEvidence: TLSEvidenceTable.Snapshot
}
