import SwiftUI

// MARK: - AllFramesRelatedFrameGlyph

/// A compact marker for a row's position inside the selected frame's session.
struct AllFramesRelatedFrameGlyph: View {
    let ordinal: UInt64
    let first: UInt64
    let last: UInt64

    var body: some View {
        let (symbol, label): (String, String) = if ordinal == first {
            ("arrow.down.to.line", String(localized: "First frame of the selected frame's session"))
        } else if ordinal == last {
            ("arrow.up.to.line", String(localized: "Last frame of the selected frame's session"))
        } else {
            ("link", String(localized: "Same session as the selected frame"))
        }
        Image(systemName: symbol)
            .font(.system(size: Theme.Icon.small))
            .foregroundStyle(.secondary)
            .help(label)
            .accessibilityLabel(label)
    }
}
