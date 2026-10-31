import Foundation

// MARK: - PacketDecoder Application Dispatch

extension PacketDecoder {
    /// Runs the whole-frame application chain: the first candidate whose gate passes
    /// decodes and returns; a throw propagates (kept partial by `decode`'s top-level
    /// catch) and never falls through. No match leaves the frame at its transport layer.
    static func decodeFrameApplication(
        _ candidates: [ApplicationCandidate],
        context: ApplicationMatchContext,
        into packet: inout DecodedPacket
    )
        throws
    {
        for candidate in candidates where candidate.matches(context) {
            _ = try candidate.decode(context, &packet)
            return
        }
    }

    /// Runs the reassembled TCP application chain: the first passing gate decodes and
    /// returns its `isComplete`; a nil result, a throw, or no match fails the decode
    /// (nil) without falling through to a lower-priority candidate.
    static func decodeReassembledApplication(
        context: ApplicationMatchContext,
        into packet: inout DecodedPacket
    )
        -> Bool?
    {
        for candidate in DecodeAs.enabled(reassembledApplicationCandidates) where candidate.matches(context) {
            // A throwing candidate fails the whole reassembled decode (nil) rather than
            // falling through to a lower-priority gate — `try?` flattens both to nil.
            return try? candidate.decode(context, &packet)
        }
        return nil
    }
}
