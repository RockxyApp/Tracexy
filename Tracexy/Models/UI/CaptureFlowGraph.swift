import Foundation

// MARK: - CaptureFlowGraph

/// Statistics ▸ Flow Graph: Wireshark's capture-wide flow (sequence) diagram — one
/// lane per address, one arrow per frame from its source lane to its destination
/// lane, labelled with the frame's Info. Built from the All Frames list, bounded in
/// lanes and arrows so the diagram stays readable and cheap to draw.
struct CaptureFlowGraph: Equatable {
    // MARK: Lifecycle

    init(rows: [CaptureFrameRow]) {
        var lanes: [String] = []
        var laneIndex: [String: Int] = [:]
        var arrows: [Arrow] = []
        var omitted = 0
        func lane(_ address: String) -> Int? {
            if let index = laneIndex[address] {
                return index
            }
            guard lanes.count < Self.maxLanes else {
                return nil
            }
            laneIndex[address] = lanes.count
            lanes.append(address)
            return lanes.count - 1
        }
        for row in rows where row.source != "—" && row.destination != "—" {
            guard arrows.count < Self.maxArrows, let from = lane(row.source), let to = lane(row.destination) else {
                omitted += 1
                continue
            }
            arrows.append(Arrow(
                ordinal: row.ordinal, timestamp: row.provenance.timestamp, from: from, to: to,
                label: "\(row.protocolName) \(row.info)", row: row
            ))
        }
        self.lanes = lanes
        self.arrows = arrows
        omittedCount = omitted
    }

    // MARK: Internal

    struct Arrow: Identifiable, Equatable {
        let ordinal: UInt64
        let timestamp: Date?
        let from: Int
        let to: Int
        let label: String
        let row: CaptureFrameRow

        var id: UInt64 {
            ordinal
        }
    }

    /// At most this many address lanes; frames between other addresses are left out
    /// and counted.
    static let maxLanes = 12
    /// At most this many arrows.
    static let maxArrows = 5_000

    let lanes: [String]
    let arrows: [Arrow]
    /// Frames not drawn: past the arrow bound, or between addresses past the lane bound.
    let omittedCount: Int

    var isEmpty: Bool {
        arrows.isEmpty
    }

    /// Wireshark's "Export as ASCII": one line per arrow with its time since the
    /// first frame, the two addresses and the label, and the lane header above.
    func ascii() -> String {
        let origin = arrows.first?.timestamp
        let header = "Time         " + lanes.enumerated().map { "[\($0.offset)] \($0.element)" }.joined(separator: "  ")
        let lines = arrows.map { arrow -> String in
            let time = Self.elapsed(arrow.timestamp, since: origin)
            let direction = arrow.from == arrow.to ? "⟲" : (arrow.from < arrow.to ? "──▶" : "◀──")
            let pair = arrow.from <= arrow.to
                ? "[\(arrow.from)] \(direction) [\(arrow.to)]"
                : "[\(arrow.to)] \(direction) [\(arrow.from)]"
            return time.padding(toLength: 12, withPad: " ", startingAt: 0) + " " + pair + "  " + arrow.label
        }
        return ([header] + lines).joined(separator: "\n") + "\n"
    }

    // MARK: Private

    /// Seconds since the first arrow, or an em dash for an untimed frame.
    private static func elapsed(_ timestamp: Date?, since origin: Date?) -> String {
        guard let timestamp, let origin else {
            return "—"
        }
        return String(format: "%.6f", timestamp.timeIntervalSince(origin))
    }
}
