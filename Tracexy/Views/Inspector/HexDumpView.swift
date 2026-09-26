import AppKit
import SwiftUI

// MARK: - HexDumpView

/// A read-only hex + ASCII dump (offset, 16 bytes, ASCII) or bits dump (8 bytes a
/// row), Wireshark-style,
/// over the representative packet's real captured bytes. Bytes inside `highlight`
/// are tinted to mirror the field selected in the decode tree.
struct HexDumpView: View {
    // MARK: Internal

    let bytes: [UInt8]
    var highlight: Range<Int>?
    /// Find matches, tinted differently from the selected field.
    var matches: [Range<Int>] = []
    /// The byte under the pointer, or `nil` when the pointer leaves the bytes.
    var onHoverByte: ((Int?) -> Void)?
    /// A click on a byte (hex or ASCII column).
    var onClickByte: ((Int) -> Void)?

    var body: some View {
        // Linked to a decode tree, a click picks the byte's field (as in Wireshark's
        // bytes pane); text selection would swallow that click, and Copy Bytes
        // covers copying. Unlinked dumps stay selectable.
        if onClickByte == nil {
            rows.textSelection(.enabled)
        } else {
            rows
        }
    }

    /// One monospaced character of the dump's font at a zoom step.
    static func characterWidth(zoom: Int = 0) -> CGFloat {
        let font = NSFont.monospacedSystemFont(
            ofSize: Theme.Typography.zoomedSize(.subheadline, zoom: zoom), weight: .regular
        )
        return max(1, ("0" as NSString).size(withAttributes: [.font: font]).width)
    }

    /// The byte column (0–15) at a character position of a dump row, or `nil` for
    /// the offset, the gaps and the padding. Row layout: `0000   ` (7), sixteen
    /// `XX ` cells with one extra space after the eighth, two spaces, sixteen ASCII.
    ///
    /// In bits, `0000   ` (7), eight `01000101 ` cells (9 each), one more space, eight ASCII.
    static func column(atCharacter position: Int, style: ByteDumpStyle = .hex) -> Int? {
        switch style {
        case .hex:
            switch position {
            case 7 ..< 31: (position - 7) / 3
            case 32 ..< 56: 8 + (position - 32) / 3
            case 58 ..< 74: position - 58
            default: nil
            }
        case .bits:
            switch position {
            case 7 ..< 79: (position - 7) / 9
            case 80 ..< 88: position - 80
            default: nil
            }
        }
    }

    /// `byte` as eight binary digits, most significant first.
    static func bits(_ byte: UInt8) -> String {
        String((0 ..< 8).map { byte & (0x80 >> $0) == 0 ? "0" : "1" })
    }

    // MARK: Private

    private enum Tint {
        case field
        case match
    }

    @Environment(\.packetTextZoom) private var zoom
    @Environment(\.byteDumpStyle) private var style

    private var rowStarts: [Int] {
        Array(stride(from: 0, to: bytes.count, by: style.bytesPerRow))
    }

    private var rows: some View {
        // One Text(AttributedString) per row (not ~32 views) — keeps the hex pane
        // light enough to stay smooth while a capture is updating. Rows never wrap,
        // so a pointer's x maps straight to a byte column.
        VStack(alignment: .leading, spacing: 2) {
            ForEach(rowStarts, id: \.self) { start in
                Text(row(start: start))
                    .font(Theme.Typography.zoomed(.subheadline, zoom: zoom, monospaced: true))
                    .fixedSize(horizontal: true, vertical: false)
                    .onContinuousHover { phase in
                        guard let onHoverByte else {
                            return
                        }
                        switch phase {
                        case let .active(point): onHoverByte(byte(atX: point.x, rowStart: start))
                        case .ended: onHoverByte(nil)
                        }
                    }
                    .onTapGesture { location in
                        if let onClickByte, let index = byte(atX: location.x, rowStart: start) {
                            onClickByte(index)
                        }
                    }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row(start: Int) -> AttributedString {
        style == .bits ? bitsRow(start: start) : hexRow(start: start)
    }

    private func bitsRow(start: Int) -> AttributedString {
        var line = attributed(String(format: "%04X   ", start), color: .secondary)
        for col in 0 ..< 8 {
            let index = start + col
            if index < bytes.count {
                line += attributed(Self.bits(bytes[index]) + " ", highlighted: isHighlighted(index))
            } else {
                line += attributed(String(repeating: " ", count: 9))
            }
        }
        line += attributed(" ")
        for col in 0 ..< 8 where start + col < bytes.count {
            line += attributed(
                String(asciiChar(bytes[start + col])), color: .secondary, highlighted: isHighlighted(start + col)
            )
        }
        return line
    }

    private func hexRow(start: Int) -> AttributedString {
        var line = attributed(String(format: "%04X   ", start), color: .secondary)
        for col in 0 ..< 16 {
            let index = start + col
            if index < bytes.count {
                line += attributed(String(format: "%02X ", bytes[index]), highlighted: isHighlighted(index))
            } else {
                line += attributed("   ")
            }
            if col == 7 {
                line += attributed(" ")
            }
        }
        line += attributed("  ")
        for col in 0 ..< 16 {
            let index = start + col
            if index < bytes.count {
                line += attributed(
                    String(asciiChar(bytes[index])), color: .secondary, highlighted: isHighlighted(index)
                )
            } else {
                line += attributed(" ")
            }
        }
        return line
    }

    private func attributed(_ string: String, color: Color? = nil, highlighted: Tint? = nil) -> AttributedString {
        var piece = AttributedString(string)
        if let color {
            piece.foregroundColor = color
        }
        switch highlighted {
        case .field: piece.backgroundColor = Color.accentColor.opacity(0.35)
        case .match: piece.backgroundColor = Color.yellow.opacity(0.45)
        case nil: break
        }
        return piece
    }

    private func isHighlighted(_ index: Int) -> Tint? {
        if let highlight, highlight.contains(index) {
            return .field
        }
        if matches.contains(where: { $0.contains(index) }) {
            return .match
        }
        return nil
    }

    private func byte(atX x: CGFloat, rowStart: Int) -> Int? {
        guard x >= 0,
              let column = Self.column(atCharacter: Int(x / Self.characterWidth(zoom: zoom)), style: style) else
        {
            return nil
        }
        let index = rowStart + column
        return index < bytes.count ? index : nil
    }

    private func asciiChar(_ byte: UInt8) -> Character {
        byte >= 0x20 && byte < 0x7F ? Character(UnicodeScalar(byte)) : "."
    }
}
