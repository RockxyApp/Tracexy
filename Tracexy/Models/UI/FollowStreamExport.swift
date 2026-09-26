import Foundation

// MARK: - FollowStreamTurn

/// One turn of a followed TCP stream: consecutive bytes one side sent before the
/// other side spoke, in capture order — Wireshark's Follow Stream unit.
nonisolated struct FollowStreamTurn: Equatable, Sendable {
    let direction: ConnectionDirection
    let firstOrdinal: UInt64
    let timestamp: Date?
    let bytes: [UInt8]
}

// MARK: - FollowStreamExport

/// Follow Stream's Show-as and Save-as formats (Wireshark: ASCII, C Arrays, Hex Dump,
/// YAML, Raw) over the reconstructed stream, split into turns by the frame that first
/// delivered each byte and interleaved in capture order. Bytes past the reader's mark
/// bound keep their direction and follow that direction's last known frame.
enum FollowStreamExport {
    // MARK: Internal

    enum Format: String, CaseIterable, Identifiable {
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

    enum Side: String, CaseIterable, Identifiable {
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

    /// The stream's turns in capture order.
    nonisolated static func turns(of result: FollowStreamResult) -> [FollowStreamTurn] {
        var chunks = chunks(result.aToB, direction: .aToB) + chunks(result.bToA, direction: .bToA)
        chunks.sort { $0.ordinal == $1.ordinal ? $0.direction == .aToB : $0.ordinal < $1.ordinal }
        var turns: [FollowStreamTurn] = []
        for chunk in chunks {
            if let last = turns.last, last.direction == chunk.direction {
                turns[turns.count - 1] = FollowStreamTurn(
                    direction: last.direction, firstOrdinal: last.firstOrdinal, timestamp: last.timestamp,
                    bytes: last.bytes + chunk.bytes
                )
            } else {
                turns.append(FollowStreamTurn(
                    direction: chunk.direction, firstOrdinal: chunk.ordinal, timestamp: chunk.timestamp,
                    bytes: chunk.bytes
                ))
            }
        }
        return turns
    }

    /// Wireshark's summary line, e.g. "3 client pkts, 2 server pkts, 4 turns".
    static func summary(of result: FollowStreamResult, turns: [FollowStreamTurn]) -> String {
        String(localized: """
        \(result.aToB.matchedFrameCount.formatted()) frames A→B, \(result.bToA.matchedFrameCount.formatted()) frames \
        B→A, \(turns.count.formatted()) turns
        """)
    }

    /// Wireshark's "Filter Out This Stream": the Session Expression that keeps
    /// every session except this stream's.
    static func filterOutTerm(_ tuple: FiveTuple) -> String {
        let ports = tuple.a.port == tuple.b.port
            ? "port == \(tuple.a.port)"
            : "port == \(tuple.a.port) and port == \(tuple.b.port)"
        return "not (ip == \(tuple.a.ip) and ip == \(tuple.b.ip) and \(ports))"
    }

    /// The time of the stream's first retained byte, the origin of each run's offset.
    static func origin(of result: FollowStreamResult) -> Date? {
        turns(of: result).compactMap(\.timestamp).min()
    }

    static func data(_ turns: [FollowStreamTurn], format: Format, side: Side, tuple: FiveTuple) -> Data {
        let kept = turns.filter { side.admits($0.direction) }
        switch format {
        case .raw:
            return Data(kept.flatMap(\.bytes))
        case .ascii:
            return Data(kept.map { String($0.bytes.map(printable)) }.joined().utf8)
        case .hexDump:
            return Data(hexDump(kept).utf8)
        case .cArrays:
            return Data(cArrays(kept).utf8)
        case .yaml:
            return Data(yaml(kept, tuple: tuple).utf8)
        }
    }

    // MARK: Private

    nonisolated private struct Chunk {
        let direction: ConnectionDirection
        let ordinal: UInt64
        let timestamp: Date?
        let bytes: [UInt8]
    }

    /// One direction's retained bytes cut at every segment mark, each piece stamped
    /// with the frame that first delivered it.
    nonisolated private static func chunks(
        _ snapshot: FollowStreamDirectionSnapshot,
        direction: ConnectionDirection
    )
        -> [Chunk]
    {
        guard let anchor = snapshot.anchorSequence else {
            return []
        }
        var result: [Chunk] = []
        for run in snapshot.runs {
            let runStart = Int64(Int32(bitPattern: run.sequenceAnchor &- anchor))
            let runEnd = runStart + Int64(run.bytes.count)
            // Mark offsets inside the run become cut points.
            var cuts = snapshot.segmentMarks.map(\.offset).filter { $0 > runStart && $0 < runEnd }
            cuts.insert(runStart, at: 0)
            cuts.append(runEnd)
            for index in 0 ..< cuts.count - 1 {
                let from = Int(cuts[index] - runStart)
                let to = Int(cuts[index + 1] - runStart)
                guard from < to else {
                    continue
                }
                let frame = snapshot.firstFrame(ofByte: from, in: run) ?? run.firstProvenance
                result.append(Chunk(
                    direction: direction,
                    ordinal: frame?.ordinal.rawValue ?? UInt64(run.firstCaptureOrdinal),
                    timestamp: frame?.timestamp,
                    bytes: Array(run.bytes[from ..< to])
                ))
            }
        }
        return result
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

    /// Wireshark's Hex Dump: offsets per direction, the second side indented.
    private static func hexDump(_ turns: [FollowStreamTurn]) -> String {
        var offsets: [ConnectionDirection: Int] = [.aToB: 0, .bToA: 0]
        var lines: [String] = []
        for turn in turns {
            let indent = turn.direction == .bToA ? "    " : ""
            let start = offsets[turn.direction, default: 0]
            let dump = PacketBytesFormat.hexDump.text(for: turn.bytes[...], startOffset: start)
            lines += dump.split(separator: "\n").map { indent + $0 }
            offsets[turn.direction] = start + turn.bytes.count
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Wireshark's C Arrays: `char peer0_0[] = { … };` per turn, numbered per peer.
    private static func cArrays(_ turns: [FollowStreamTurn]) -> String {
        var counters: [ConnectionDirection: Int] = [:]
        return turns.map { turn in
            let peer = turn.direction == .aToB ? 0 : 1
            let index = counters[turn.direction, default: 0]
            counters[turn.direction] = index + 1
            let rows = stride(from: 0, to: turn.bytes.count, by: 8).map { start in
                turn.bytes[start ..< min(start + 8, turn.bytes.count)].map { String(format: "0x%02x", $0) }
                    .joined(separator: ", ")
            }
            return "char peer\(peer)_\(index)[] = { /* Frame \(turn.firstOrdinal) */\n"
                + rows.joined(separator: ",\n") + " };\n"
        }.joined()
    }

    /// Wireshark's YAML: the two peers, then every turn with its frame, time and
    /// base64 data.
    private static func yaml(_ turns: [FollowStreamTurn], tuple: FiveTuple) -> String {
        var lines = [
            "peers:",
            "  - peer: 0",
            "    host: \(tuple.a.ip)",
            "    port: \(tuple.a.port)",
            "  - peer: 1",
            "    host: \(tuple.b.ip)",
            "    port: \(tuple.b.port)",
            "packets:",
        ]
        for (index, turn) in turns.enumerated() {
            lines.append("  - packet: \(turn.firstOrdinal)")
            lines.append("    peer: \(turn.direction == .aToB ? 0 : 1)")
            lines.append("    index: \(index)")
            if let time = turn.timestamp {
                lines.append("    timestamp: \(String(format: "%.9f", time.timeIntervalSince1970))")
            }
            lines.append("    data: !!binary |")
            let encoded = Data(turn.bytes).base64EncodedString()
            for start in stride(from: 0, to: encoded.count, by: 76) {
                let begin = encoded.index(encoded.startIndex, offsetBy: start)
                let end = encoded.index(begin, offsetBy: min(76, encoded.count - start))
                lines.append("      " + encoded[begin ..< end])
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
