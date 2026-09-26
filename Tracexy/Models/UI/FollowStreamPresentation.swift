import Foundation

// MARK: - FollowStreamDisplayMode

nonisolated enum FollowStreamDisplayMode: String, CaseIterable, Identifiable, Sendable {
    case text
    case hex

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .text: "Text"
        case .hex: "Hex"
        }
    }
}

// MARK: - FollowStreamDirectionPresentation

/// A second, UI-only bound over the already-bounded reader result. It formats at
/// most 64 KiB per direction, preserves run/gap markers and reports the retained
/// bytes it did not render. The underlying result remains unchanged.
nonisolated struct FollowStreamDirectionPresentation: Equatable, Sendable {
    // MARK: Lifecycle

    init(
        snapshot: FollowStreamDirectionSnapshot,
        mode: FollowStreamDisplayMode,
        maxDisplayBytes: Int = maximumDisplayBytes
    ) {
        let limit = min(max(0, maxDisplayBytes), Self.maximumDisplayBytes)
        var remaining = limit
        var displayed = 0
        var sections: [String] = []
        var runSections: [RunSection] = []
        // With nothing dropped under a retention bound, every hole between runs is
        // sequence space no captured frame carried.
        let gapsAreMissing = snapshot.observedOmittedByteCount == 0
        sections.reserveCapacity(min(snapshot.runs.count, 64))

        for (index, run) in snapshot.runs.enumerated() where remaining > 0 {
            let count = min(run.bytes.count, remaining)
            let bytes = Array(run.bytes.prefix(count))
            // The hole's size is exact: runs are disjoint and in sequence order, so
            // it is the distance from the previous run's end to this run's start.
            let gap: UInt32? = index > 0
                ? run.sequenceAnchor &- (snapshot.runs[index - 1].sequenceAnchor
                    &+ UInt32(truncatingIfNeeded: snapshot.runs[index - 1].bytes.count))
                : nil
            if let gap {
                sections.append(gapsAreMissing
                    ? "[\(gap) bytes missing in the capture]"
                    : "[\(gap) bytes between retained runs not retained]")
            }
            runSections.append(RunSection(
                id: index,
                sequenceAnchor: run.sequenceAnchor,
                firstCaptureOrdinal: run.firstCaptureOrdinal,
                firstProvenance: run.firstProvenance,
                displayedByteCount: count,
                runByteCount: run.bytes.count,
                followsGap: index > 0,
                gapByteCount: gap,
                text: Self.format(bytes, mode: mode)
            ))
            let header = String(
                format: "[sequence 0x%08X · frame %d · %d/%d bytes]",
                run.sequenceAnchor,
                run.firstCaptureOrdinal,
                count,
                run.bytes.count
            )
            sections.append(header + "\n" + Self.format(bytes, mode: mode))
            displayed += count
            remaining -= count
        }

        body = sections.joined(separator: "\n\n")
        self.gapsAreMissing = gapsAreMissing
        self.runSections = runSections
        displayedByteCount = displayed
        viewOmittedByteCount = max(0, snapshot.retainedByteCount - displayed)
    }

    // MARK: Internal

    /// One retained run as the transcript draws it: its formatted bytes and the
    /// frame that established its first byte.
    nonisolated struct RunSection: Equatable, Sendable, Identifiable {
        let id: Int
        let sequenceAnchor: UInt32
        let firstCaptureOrdinal: Int
        /// Navigable only when the reader was given the source token.
        let firstProvenance: SessionFrameProvenance?
        let displayedByteCount: Int
        let runByteCount: Int
        /// An unretained stretch of the stream lies between this run and the last.
        let followsGap: Bool
        /// How many sequence bytes that stretch spans, when `followsGap`.
        let gapByteCount: UInt32?
        let text: String
    }

    static let maximumDisplayBytes = 64 << 10

    let body: String
    /// Whether each gap is sequence space missing from the capture, rather than
    /// bytes the reader saw but did not keep under a bound.
    let gapsAreMissing: Bool
    let runSections: [RunSection]
    let displayedByteCount: Int
    /// Bytes present in the bounded reader result but not formatted by the view.
    /// Separate from the reader's `observedOmittedByteCount`.
    let viewOmittedByteCount: Int

    /// Render bytes as printable text (control bytes as `.`) or an offset/hex/ASCII dump.
    static func format(_ bytes: [UInt8], mode: FollowStreamDisplayMode) -> String {
        switch mode {
        case .text:
            return String(bytes.map { byte in
                if byte == 0x0A || byte == 0x0D || byte == 0x09 {
                    return Character(UnicodeScalar(byte))
                }
                return byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
            })
        case .hex:
            var rows: [String] = []
            rows.reserveCapacity((bytes.count + 15) / 16)
            for start in stride(from: 0, to: bytes.count, by: 16) {
                let end = min(start + 16, bytes.count)
                let slice = bytes[start ..< end]
                let hex = slice.map { String(format: "%02X", $0) }.joined(separator: " ")
                let ascii = String(slice.map { byte in
                    byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
                })
                rows.append(
                    String(format: "%04X", start)
                        + "  " + hex.padding(toLength: 47, withPad: " ", startingAt: 0)
                        + "  " + ascii
                )
            }
            return rows.joined(separator: "\n")
        }
    }
}

// MARK: - FollowStreamLimitations presentation

extension FollowStreamLimitations {
    /// Fixed neutral copy for independently-set reader limitations. No item turns
    /// an observation into a security verdict or claims whole-capture completeness.
    nonisolated var presentationLabels: [String] {
        var labels: [String] = []
        if contains(.sequenceGap) {
            labels.append("Sequence gap observed")
        }
        if contains(.outOfOrder) {
            labels.append("Out-of-order segments bridged")
        }
        if contains(.overlapConflict) {
            labels.append("Conflicting overlap; first bytes kept")
        }
        if contains(.serialAmbiguous) {
            labels.append("Ambiguous TCP serial distance")
        }
        if contains(.capturedFrameTruncated) {
            labels.append("A matched frame was capture-truncated")
        }
        if contains(.runRetentionTruncated) {
            labels.append("Run retention bound reached")
        }
        if contains(.byteRetentionTruncated) {
            labels.append("Byte retention bound reached")
        }
        if contains(.sourceTailTruncated) {
            labels.append("Capture source has a truncated tail")
        }
        return labels
    }
}
