import Foundation

// MARK: - FollowStreamExportChunk

/// One sequence-ordered range of retained bytes with a single first-frame
/// attribution. A missing provenance remains unknown; no earlier frame is borrowed.
nonisolated struct FollowStreamExportChunk: Equatable, Sendable {
    let direction: ConnectionDirection
    let runIndex: Int
    let sequenceOffset: Int64
    let provenance: SessionFrameProvenance?
    /// A slice shares the bounded reconstructed run's storage without copying it.
    let bytes: ArraySlice<UInt8>
}

// MARK: - FollowStreamTurn

/// A conversational turn is a range of attributed chunks in capture order. It
/// groups consecutive chunks from one direction without concatenating their bytes
/// or replacing their individual frame/time metadata with the first frame's facts.
nonisolated struct FollowStreamTurn: Equatable, Sendable {
    let direction: ConnectionDirection
    let chunkRange: Range<Int>
}

// MARK: - FollowStreamExportSnapshot

/// The bounded export projections of one followed conversation. Per-direction
/// chunks follow TCP sequence order. Capture ordering is available only when every
/// retained byte has a known first frame and no frame claims both directions.
nonisolated struct FollowStreamExportSnapshot: Equatable, Sendable {
    let aToBChunks: [FollowStreamExportChunk]
    let bToAChunks: [FollowStreamExportChunk]
    let captureOrderedChunks: [FollowStreamExportChunk]?
    let turns: [FollowStreamTurn]?
    let unknownProvenanceByteCount: Int
    /// The first retained byte's capture time, only when its capture order is known.
    let origin: Date?

    var turnCount: Int? {
        if let turns {
            return turns.count
        }
        if aToBChunks.isEmpty || bToAChunks.isEmpty {
            return aToBChunks.isEmpty && bToAChunks.isEmpty ? 0 : 1
        }
        return nil
    }

    func canExport(side: FollowStreamExport.Side) -> Bool {
        side != .both || aToBChunks.isEmpty || bToAChunks.isEmpty || captureOrderedChunks != nil
    }

    /// One-way output always follows sequence/run order. A two-way output needs
    /// proven capture ordering unless only one direction has retained bytes.
    func chunks(for side: FollowStreamExport.Side) throws -> [FollowStreamExportChunk] {
        switch side {
        case .aToB:
            return aToBChunks
        case .bToA:
            return bToAChunks
        case .both:
            if bToAChunks.isEmpty {
                return aToBChunks
            }
            if aToBChunks.isEmpty {
                return bToAChunks
            }
            guard let captureOrderedChunks else {
                throw FollowStreamExport.ExportError.orderingUnavailable
            }
            return captureOrderedChunks
        }
    }

    /// Materialize one proven turn once for a parser that needs contiguous bytes.
    /// Formatters use chunks directly so they retain every frame's attribution.
    func bytes(in turn: FollowStreamTurn) -> [UInt8] {
        guard let chunks = captureOrderedChunks,
              turn.chunkRange.lowerBound >= 0,
              turn.chunkRange.upperBound <= chunks.count else
        {
            return []
        }
        var bytes: [UInt8] = []
        for chunk in chunks[turn.chunkRange] {
            bytes.append(contentsOf: chunk.bytes)
        }
        return bytes
    }
}

// MARK: - FollowStreamExport

/// Show-as and Save-as formats over retained TCP bytes. Byte reconstruction,
/// packet attribution and conversational turns are independent projections.
nonisolated enum FollowStreamExport {
    // MARK: Internal

    enum Format: String, CaseIterable, Identifiable, Sendable {
        case raw
        case ascii
        case hexDump
        case cArrays
        case yaml

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .raw: String(localized: "Raw Bytes")
            case .ascii: String(localized: "ASCII Text")
            case .hexDump: String(localized: "Hex Dump")
            case .cArrays: String(localized: "C Arrays")
            case .yaml: String(localized: "YAML")
            }
        }

        var fileExtension: String {
            switch self {
            case .raw: "bin"
            case .ascii,
                 .hexDump: "txt"
            case .cArrays: "c"
            case .yaml: "yaml"
            }
        }
    }

    enum Side: String, CaseIterable, Identifiable, Sendable {
        case both
        case aToB
        case bToA

        // MARK: Internal

        var id: String {
            rawValue
        }

        func admits(_ direction: ConnectionDirection) -> Bool {
            switch self {
            case .both: true
            case .aToB: direction == .aToB
            case .bToA: direction == .bToA
            }
        }
    }

    enum ExportError: Error, Equatable, LocalizedError {
        case orderingUnavailable
        case invalidSnapshot

        // MARK: Internal

        var errorDescription: String? {
            switch self {
            case .orderingUnavailable:
                String(
                    localized: "The retained bytes do not have a proven order between directions. Export one direction at a time."
                )
            case .invalidSnapshot:
                String(localized: "The retained stream bytes have no valid sequence anchor and cannot be exported.")
            }
        }
    }

    enum PrintError: Error, Equatable {
        case emptySelection
        case tooLarge
    }

    static let maximumPrintBytes = 8 << 20

    /// Build off-main with the same cancellation and generation ownership as the
    /// follow read. Chunks share each run's bounded byte storage.
    static func snapshot(
        of result: FollowStreamResult,
        checkingCancellation: () -> Bool = { true }
    )
        throws -> FollowStreamExportSnapshot
    {
        try snapshot(aToB: result.aToB, bToA: result.bToA, checkingCancellation: checkingCancellation)
    }

    static func snapshot(
        aToB: FollowStreamDirectionSnapshot,
        bToA: FollowStreamDirectionSnapshot,
        checkingCancellation: () -> Bool = { true }
    )
        throws -> FollowStreamExportSnapshot
    {
        let aChunks = try chunks(aToB, direction: .aToB, checkingCancellation: checkingCancellation)
        let bChunks = try chunks(bToA, direction: .bToA, checkingCancellation: checkingCancellation)
        var unknownCount = 0
        for (index, chunk) in (aChunks + bChunks).enumerated() {
            if index.isMultiple(of: 256), !checkingCancellation() {
                throw CancellationError()
            }
            if chunk.provenance == nil {
                unknownCount += chunk.bytes.count
            }
        }
        guard checkingCancellation() else {
            throw CancellationError()
        }
        var ordered: [FollowStreamExportChunk]?
        var turns: [FollowStreamTurn]?
        if unknownCount == 0 {
            var known = aChunks + bChunks
            known.sort { lhs, rhs in
                let leftOrdinal = lhs.provenance?.ordinal.rawValue ?? 0
                let rightOrdinal = rhs.provenance?.ordinal.rawValue ?? 0
                if leftOrdinal != rightOrdinal {
                    return leftOrdinal < rightOrdinal
                }
                if lhs.direction != rhs.direction {
                    return lhs.direction == .aToB
                }
                if lhs.runIndex != rhs.runIndex {
                    return lhs.runIndex < rhs.runIndex
                }
                return lhs.sequenceOffset < rhs.sequenceOffset
            }
            guard checkingCancellation() else {
                throw CancellationError()
            }
            // One captured frame cannot carry both canonical directions. A
            // contradictory supplied snapshot does not establish an order.
            var conflictingFrame = false
            for index in known.indices.dropFirst() {
                if index.isMultiple(of: 256), !checkingCancellation() {
                    throw CancellationError()
                }
                let first = known[index - 1]
                let second = known[index]
                if first.provenance?.ordinal == second.provenance?.ordinal, first.direction != second.direction {
                    conflictingFrame = true
                    break
                }
            }
            if !conflictingFrame {
                ordered = known
                turns = try turnSpans(in: known, checkingCancellation: checkingCancellation)
            }
        }
        guard checkingCancellation() else {
            throw CancellationError()
        }
        return FollowStreamExportSnapshot(
            aToBChunks: aChunks,
            bToAChunks: bChunks,
            captureOrderedChunks: ordered,
            turns: turns,
            unknownProvenanceByteCount: unknownCount,
            origin: ordered?.first?.provenance?.timestamp
        )
    }

    static func summary(of result: FollowStreamResult, snapshot: FollowStreamExportSnapshot) -> String {
        let frames =
            String(
                localized: "\(result.aToB.matchedFrameCount.formatted()) frames A→B, \(result.bToA.matchedFrameCount.formatted()) frames B→A"
            )
        guard let turnCount = snapshot.turnCount else {
            return frames + String(localized: ", turn order unavailable")
        }
        return frames + String(localized: ", \(turnCount.formatted()) turns")
    }

    static func filterOutTerm(_ tuple: FiveTuple) -> String {
        let protocolName = tuple.proto.rawValue
        let aToB = "(source.ip == \(tuple.a.ip) and source.port == \(tuple.a.port) and "
            + "destination.ip == \(tuple.b.ip) and destination.port == \(tuple.b.port))"
        let bToA = "(source.ip == \(tuple.b.ip) and source.port == \(tuple.b.port) and "
            + "destination.ip == \(tuple.a.ip) and destination.port == \(tuple.a.port))"
        return "not (\(protocolName) and (\(aToB) or \(bToA)))"
    }

    static func data(
        _ snapshot: FollowStreamExportSnapshot,
        format: Format,
        side: Side,
        tuple: FiveTuple
    )
        throws -> Data
    {
        let selected = try snapshot.chunks(for: side)
        switch format {
        case .raw:
            var data = Data()
            data.reserveCapacity(selected.reduce(0) { $0 + $1.bytes.count })
            for chunk in selected {
                data.append(contentsOf: chunk.bytes)
            }
            return data
        case .ascii:
            return Data(selected.map { String($0.bytes.map(printable)) }.joined().utf8)
        case .hexDump:
            return Data(hexDump(selected).utf8)
        case .cArrays:
            return Data(cArrays(selected).utf8)
        case .yaml:
            return Data(yaml(selected, tuple: tuple).utf8)
        }
    }

    /// Raw bytes print as a hex dump. The preflight bounds formatter expansion
    /// before any large intermediate text is allocated.
    static func printableText(
        _ snapshot: FollowStreamExportSnapshot,
        format: Format,
        side: Side,
        tuple: FiveTuple,
        limitationLabels: [String],
        completeness: FollowStreamCompleteness,
        retainedBytes: Int,
        observedOmittedBytes: UInt64
    )
        throws -> String
    {
        let selected = try snapshot.chunks(for: side)
        let printableFormat: Format = format == .raw ? .hexDump : format
        let byteCount = selected.reduce(0) { $0 + $1.bytes.count }
        guard byteCount > 0 else {
            throw PrintError.emptySelection
        }
        let expansion: (bytes: Int, perChunk: Int) = switch printableFormat {
        case .raw,
             .hexDump: (6, 160)
        case .ascii: (1, 16)
        case .cArrays: (7, 128)
        case .yaml: (2, 240)
        }
        let estimatedSize = byteCount.multipliedReportingOverflow(by: expansion.bytes)
        let estimatedChunks = selected.count.multipliedReportingOverflow(by: expansion.perChunk)
        guard !estimatedSize.overflow, !estimatedChunks.overflow,
              estimatedChunks.partialValue <= maximumPrintBytes,
              estimatedSize.partialValue <= maximumPrintBytes - estimatedChunks.partialValue else
        {
            throw PrintError.tooLarge
        }
        let body = try data(snapshot, format: printableFormat, side: side, tuple: tuple)
        guard body.count <= maximumPrintBytes, let bodyText = String(data: body, encoding: .utf8) else {
            throw PrintError.tooLarge
        }
        let direction = switch side {
        case .both: String(localized: "Both directions")
        case .aToB: "\(tuple.a.display) → \(tuple.b.display)"
        case .bToA: "\(tuple.b.display) → \(tuple.a.display)"
        }
        let warning = limitationLabels.isEmpty
            ?
            String(
                localized: "No observed stream limitations were reported. This does not prove the capture is loss-free."
            )
            : String(localized: "Observed limitations: \(limitationLabels.joined(separator: "; "))")
        let completenessText = switch completeness {
        case .complete: String(localized: "Source scan reached a clean end.")
        case .incompleteTruncatedTail: String(localized: "Source ended in a truncated record or block.")
        }
        let unknownBytes = selected.reduce(0) { $0 + ($1.provenance == nil ? $1.bytes.count : 0) }
        let provenanceText = unknownBytes > 0
            ?
            String(
                localized: "First-frame provenance is unavailable for \(unknownBytes.formatted()) retained bytes; their frame and time are not assigned."
            )
            : String(localized: "Every exported byte has retained first-frame provenance.")
        let orderingText = side == .both && !snapshot.aToBChunks.isEmpty && !snapshot.bToAChunks.isEmpty
            ? String(localized: "Byte order: capture order between directions.")
            : String(localized: "Byte order: TCP sequence order within one direction.")
        return [
            "Tracexy TCP Follow Stream",
            "\(tuple.proto.rawValue) · \(tuple.a.display) ↔ \(tuple.b.display)",
            "\(direction) · \(printableFormat.title)",
            String(
                localized: "Retained bytes: \(retainedBytes.formatted()); observed but not retained: \(observedOmittedBytes.formatted())"
            ),
            completenessText,
            warning,
            orderingText,
            provenanceText,
            "",
            bodyText,
        ].joined(separator: "\n")
    }

    // MARK: Private

    /// Binary-search only the marks belonging to this run, then cut at their
    /// offsets and the explicit provenance-loss boundary. No raw bytes are copied.
    private static func chunks(
        _ snapshot: FollowStreamDirectionSnapshot,
        direction: ConnectionDirection,
        checkingCancellation: () -> Bool
    )
        throws -> [FollowStreamExportChunk]
    {
        guard let anchor = snapshot.anchorSequence else {
            if snapshot.runs.contains(where: { !$0.bytes.isEmpty }) {
                throw ExportError.invalidSnapshot
            }
            return []
        }
        var result: [FollowStreamExportChunk] = []
        for (runIndex, run) in snapshot.runs.enumerated() {
            guard checkingCancellation() else {
                throw CancellationError()
            }
            let runStart = Int64(Int32(bitPattern: run.sequenceAnchor &- anchor))
            let runEnd = runStart + Int64(run.bytes.count)
            guard runStart < runEnd else {
                continue
            }
            var cuts = [runStart]
            var markIndex = firstMark(after: runStart, in: snapshot.segmentMarks)
            while markIndex < snapshot.segmentMarks.count,
                  snapshot.segmentMarks[markIndex].offset < runEnd
            {
                if markIndex.isMultiple(of: 256), !checkingCancellation() {
                    throw CancellationError()
                }
                cuts.append(snapshot.segmentMarks[markIndex].offset)
                markIndex += 1
            }
            if let dropped = snapshot.segmentMarksDroppedFrom, dropped > runStart, dropped < runEnd {
                cuts.append(dropped)
            }
            cuts.append(runEnd)
            guard checkingCancellation() else {
                throw CancellationError()
            }
            cuts.sort()
            guard checkingCancellation() else {
                throw CancellationError()
            }
            var previousCut: Int64?
            let uniqueCuts = cuts.filter { cut in
                defer { previousCut = cut }
                return cut != previousCut
            }
            for index in 0 ..< uniqueCuts.count - 1 {
                if index.isMultiple(of: 256), !checkingCancellation() {
                    throw CancellationError()
                }
                let from = Int(uniqueCuts[index] - runStart)
                let to = Int(uniqueCuts[index + 1] - runStart)
                result.append(FollowStreamExportChunk(
                    direction: direction,
                    runIndex: runIndex,
                    sequenceOffset: uniqueCuts[index],
                    provenance: snapshot.firstFrame(ofByte: from, in: run),
                    bytes: run.bytes[from ..< to]
                ))
            }
        }
        return result
    }

    private static func firstMark(after offset: Int64, in marks: [FollowStreamSegmentMark]) -> Int {
        var lower = 0
        var upper = marks.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if marks[middle].offset <= offset {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        return lower
    }

    private static func turnSpans(
        in chunks: [FollowStreamExportChunk], checkingCancellation: () -> Bool
    )
        throws -> [FollowStreamTurn]
    {
        var turns: [FollowStreamTurn] = []
        var start = 0
        while start < chunks.count {
            guard checkingCancellation() else {
                throw CancellationError()
            }
            let direction = chunks[start].direction
            var end = start + 1
            while end < chunks.count, chunks[end].direction == direction {
                if end.isMultiple(of: 256), !checkingCancellation() {
                    throw CancellationError()
                }
                end += 1
            }
            turns.append(FollowStreamTurn(direction: direction, chunkRange: start ..< end))
            start = end
        }
        return turns
    }

    private static func printable(_ byte: UInt8) -> Character {
        switch byte {
        case 0x0A,
             0x0D,
             0x09: Character(UnicodeScalar(byte))
        case 0x20 ... 0x7E: Character(UnicodeScalar(byte))
        default: "."
        }
    }

    private static func hexDump(_ chunks: [FollowStreamExportChunk]) -> String {
        var offsets: [ConnectionDirection: Int] = [.aToB: 0, .bToA: 0]
        var lines: [String] = []
        for chunk in chunks {
            let indent = chunk.direction == .bToA ? "    " : ""
            let start = offsets[chunk.direction, default: 0]
            let dump = PacketBytesFormat.hexDump.text(for: chunk.bytes, startOffset: start)
            lines += dump.split(separator: "\n").map { indent + $0 }
            offsets[chunk.direction] = start + chunk.bytes.count
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func cArrays(_ chunks: [FollowStreamExportChunk]) -> String {
        var counters: [ConnectionDirection: Int] = [:]
        return chunks.map { chunk in
            let peer = chunk.direction == .aToB ? 0 : 1
            let index = counters[chunk.direction, default: 0]
            counters[chunk.direction] = index + 1
            var rows: [String] = []
            var start = chunk.bytes.startIndex
            while start < chunk.bytes.endIndex {
                let end = min(start + 8, chunk.bytes.endIndex)
                rows.append(chunk.bytes[start ..< end].map { String(format: "0x%02x", $0) }.joined(separator: ", "))
                start = end
            }
            let frame = chunk.provenance.map { "Frame \($0.ordinal.rawValue)" } ?? "Frame unavailable"
            return "char peer\(peer)_\(index)[] = { /* \(frame) */\n" + rows.joined(separator: ",\n") + " };\n"
        }.joined()
    }

    /// Emit every attributed chunk separately. Adjacent packets from one peer
    /// retain their individual packet numbers/timestamps and per-peer indexes.
    private static func yaml(_ chunks: [FollowStreamExportChunk], tuple: FiveTuple) -> String {
        var lines = [
            "peers:",
            "  - peer: 0", "    host: \(tuple.a.ip)", "    port: \(tuple.a.port)",
            "  - peer: 1", "    host: \(tuple.b.ip)", "    port: \(tuple.b.port)",
            "packets:",
        ]
        var counters: [ConnectionDirection: Int] = [:]
        for chunk in chunks {
            let index = counters[chunk.direction, default: 0]
            counters[chunk.direction] = index + 1
            if let frame = chunk.provenance {
                lines.append("  - packet: \(frame.ordinal.rawValue)")
            } else {
                lines.append("  - packet: null")
                lines.append("    provenance: unavailable")
            }
            lines.append("    peer: \(chunk.direction == .aToB ? 0 : 1)")
            lines.append("    index: \(index)")
            if let time = chunk.provenance?.timestamp {
                lines.append("    timestamp: \(String(format: "%.9f", time.timeIntervalSince1970))")
            }
            lines.append("    data: !!binary |")
            let encoded = Data(chunk.bytes).base64EncodedString()
            var start = encoded.startIndex
            while start < encoded.endIndex {
                let end = encoded.index(start, offsetBy: 76, limitedBy: encoded.endIndex) ?? encoded.endIndex
                lines.append("      " + encoded[start ..< end])
                start = end
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
