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
        sections.reserveCapacity(min(snapshot.runs.count, 64))

        for (index, run) in snapshot.runs.enumerated() where remaining > 0 {
            let count = min(run.bytes.count, remaining)
            let bytes = Array(run.bytes.prefix(count))
            if index > 0 {
                sections.append("[gap between retained runs]")
            }
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
        displayedByteCount = displayed
        viewOmittedByteCount = max(0, snapshot.retainedByteCount - displayed)
    }

    // MARK: Internal

    static let maximumDisplayBytes = 64 << 10

    let body: String
    let displayedByteCount: Int
    /// Bytes present in the bounded reader result but not formatted by the view.
    /// Separate from the reader's `observedOmittedByteCount`.
    let viewOmittedByteCount: Int

    // MARK: Private

    private static func format(_ bytes: [UInt8], mode: FollowStreamDisplayMode) -> String {
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
