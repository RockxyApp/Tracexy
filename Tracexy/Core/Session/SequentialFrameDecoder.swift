import Foundation

// MARK: - SequentialFrameDecoder

/// Decodes the frames of one capture in capture order, rebuilding fragmented IP
/// datagrams on the frame that completes each one.
///
/// Every reader that walks a capture from its first frame — the live fold, the
/// saved-capture load, the frame and session scanners, Follow, the exporters —
/// decodes through one of these, so a datagram completes on the same frame with
/// the same layers on every path. Each frame is decoded on its own first, exactly
/// as ``SessionBuilder/decodePacket(_:linkType:)`` does; only a fragment is then
/// offered to the reassembler, and only the completing frame changes.
nonisolated struct SequentialFrameDecoder: Sendable {
    // MARK: Lifecycle

    /// - Parameter retainsFragmentFrames: keep each waiting fragment's frame, so a
    ///   reader that copies frames out (a session export) can take every frame a
    ///   datagram came from once it completes. Held with the fragment's bytes in the
    ///   reassembler, so it is bounded the same way and freed with its datagram.
    init(
        reassembly: IPReassemblyConfiguration = IPReassemblyConfiguration(),
        retainsFragmentFrames: Bool = false
    ) {
        self.retainsFragmentFrames = retainsFragmentFrames
        reassembler = IPFragmentReassembler(configuration: reassembly)
    }

    // MARK: Internal

    /// The frames whose fragments made the datagram the last decoded frame
    /// completed, in datagram-offset order; empty when it completed none. A reader
    /// that cites frames hands these to the completing frame's provenance.
    private(set) var lastReassembledFrom: [SessionFrameProvenance] = []

    /// With `retainsFragmentFrames`, the frames behind ``lastReassembledFrom``, by
    /// ordinal; empty otherwise.
    private(set) var lastReassembledFrames: [(ordinal: UInt64, frame: CapturedFrame)] = []

    /// Datagrams that could not be rebuilt, by reason.
    var discards: IPReassemblyDiscards {
        reassembler.discards
    }

    /// Datagrams waiting for fragments, and the bytes they hold.
    var pendingDatagramCount: Int {
        reassembler.pendingCount
    }

    var retainedByteCount: Int {
        reassembler.retainedByteCount
    }

    /// Decodes `frame`, the `ordinal`-th frame of the capture (one-based, counting
    /// every frame). `locator` is where the frame can be read again, when known.
    mutating func decode(
        _ frame: CapturedFrame,
        linkType: UInt32,
        ordinal: UInt64,
        locator: SessionEvidenceLocator? = nil
    )
        -> DecodedPacket
    {
        var packet = SessionBuilder.decodePacket(frame, linkType: linkType)
        reassemble(&packet, frame: frame, linkType: linkType, ordinal: ordinal, locator: locator)
        return packet
    }

    /// The reassembly step alone, for a reader that decoded `frame` itself (the live
    /// engine's decode is injectable). `packet` must be `frame`'s own decode.
    mutating func reassemble(
        _ packet: inout DecodedPacket,
        frame: CapturedFrame,
        linkType: UInt32,
        ordinal: UInt64,
        locator: SessionEvidenceLocator? = nil
    ) {
        lastReassembledFrom = []
        lastReassembledFrames = []
        guard let fragment = packet.ipFragment,
              fragment.payloadRange.upperBound <= packet.rawBytes.count else
        {
            return
        }
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(ordinal),
            timestamp: frame.timestamp,
            capturedLength: frame.capturedLength,
            originalLength: frame.originalLength,
            linkType: frame.linkType ?? linkType,
            locator: locator
        )
        let source = IPFragmentReassembler<Tag>.Source(
            ordinal: ordinal,
            timestamp: frame.timestamp,
            tag: Tag(provenance: provenance, frame: retainsFragmentFrames ? frame : nil)
        )
        guard let datagram = reassembler.add(
            fragment,
            payload: packet.rawBytes[fragment.payloadRange],
            source: source
        ) else {
            return
        }
        let frames = datagram.sources.map(\.ordinal)
        PacketDecoder.applyReassembly(datagram.bytes, fragment: fragment, frames: frames, to: &packet)
        lastReassembledFrom = datagram.sources.map(\.tag.provenance)
        lastReassembledFrames = datagram.sources.compactMap { source in
            source.tag.frame.map { (source.ordinal, $0) }
        }
    }

    // MARK: Private

    /// What each fragment carries through the reassembler.
    private struct Tag: Sendable {
        let provenance: SessionFrameProvenance
        let frame: CapturedFrame?
    }

    private let retainsFragmentFrames: Bool
    private var reassembler: IPFragmentReassembler<Tag>
}
