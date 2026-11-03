import Foundation

// MARK: - SCTPChunkType

/// The RFC 4960 §3.2 chunk type values session logic names. `initiation` and
/// `abort` are the two a fold reasons about today; the rest are named so a
/// decoded chunk reads as itself rather than as a bare number. Every type,
/// named or not, still reaches ``SCTPFacts/chunkTypes`` as its raw byte, so
/// nothing is silently dropped.
nonisolated enum SCTPChunkType {
    static let data: UInt8 = 0
    static let initiation: UInt8 = 1
    static let initiationAck: UInt8 = 2
    /// RFC 4960 §3.3.7. The association is being torn down without an orderly
    /// shutdown — the SCTP analogue of a TCP RST, and real observed evidence.
    static let abort: UInt8 = 6
    static let shutdown: UInt8 = 7
    static let shutdownComplete: UInt8 = 14
}

// MARK: - SCTPFacts

/// Typed, decode-derived facts for one SCTP packet, read from exact header offsets
/// (RFC 4960 §3.1–§3.2). `nil` for non-SCTP packets and when the fixed 12-byte
/// common header was not fully captured.
///
/// These are neutral wire facts only: ports, the verification tag and the chunk
/// types this packet carried. Session logic reads chunk types from here rather
/// than string-matching a rendered "Chunk 1 Type" field, so a display value can
/// never spoof a control chunk. Nothing here claims association establishment,
/// stream reassembly or a cause — an observed chunk is only what the sender put on
/// the wire in a frame that was captured.
nonisolated struct SCTPFacts: Sendable, Hashable {
    let sourcePort: UInt16
    let destinationPort: UInt16
    let verificationTag: UInt32
    /// Chunk type bytes in wire order, bounded by the decoder's chunk retention
    /// limit. A packet whose chunks exceed that limit sets ``chunksOmitted``.
    let chunkTypes: [UInt8]
    /// `true` when a further chunk header was present past the retention limit, so
    /// ``chunkTypes`` is an explicit truncation rather than exhaustion.
    let chunksOmitted: Bool

    /// Whether this packet carried an ABORT chunk within the retained window.
    /// `false` when chunks were omitted and none of the retained ones aborted —
    /// absence of evidence, not evidence of absence.
    var containsAbort: Bool {
        chunkTypes.contains(SCTPChunkType.abort)
    }
}
