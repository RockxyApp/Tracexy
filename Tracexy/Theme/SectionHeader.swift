import SwiftUI

// MARK: - SectionHeader

/// The small uppercase label that titles a block inside a panel — `WHERE THE
/// TIME WENT`, `RELATED ACTIONS`, `FLAGGED HERE`.
///
/// A component rather than a font token because a section header is four
/// decisions, not one: size, weight, letter-spacing and colour. Spelling those
/// out at every call site is how they drifted apart — the same header rendered
/// at three sizes in three panels, and uppercase in some and title case in
/// others. Tracking matters most: uppercase text at 10 pt sets too tight
/// without it and reads as a solid block.
///
/// Pass the label in its natural case; the view uppercases it, so the string in
/// source stays readable and the presentation stays in one place.
struct SectionHeader: View {
    // MARK: Lifecycle

    init(_ title: String, systemImage: String? = nil, detail: String? = nil) {
        self.title = title
        self.systemImage = systemImage
        self.detail = detail
    }

    // MARK: Internal

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingS) {
            if let systemImage {
                Image(systemName: systemImage)
                    .font(Theme.Typography.sectionHeader)
                    .foregroundStyle(.secondary)
            }
            Text(title.uppercased())
                .font(Theme.Typography.sectionHeader)
                .tracking(0.5)
                .foregroundStyle(.secondary)
            if let detail {
                Spacer(minLength: Theme.Metrics.spacingM)
                Text(detail)
                    .font(Theme.Typography.micro)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Private

    private let title: String
    /// Optional leading glyph — names the section's subject alongside its title.
    private let systemImage: String?
    /// Optional trailing figure — a count, a total, a span.
    private let detail: String?
}

// MARK: - StatusDot

/// The tinted dot used in legends and list rows to carry a series colour or a
/// status.
///
/// Deliberately *not* used where a symbol can say more: a verdict, a severity
/// or an evidence tier gets a real SF Symbol, because those need to survive
/// being read without colour. A dot is correct only where the colour maps to a
/// key printed next to it — a chart legend, a protocol swatch — which is the
/// one case a glyph would add nothing to.
struct StatusDot: View {
    // MARK: Lifecycle

    init(_ color: Color, size: CGFloat = 7) {
        self.color = color
        self.size = size
    }

    // MARK: Internal

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
    }

    // MARK: Private

    private let color: Color
    private let size: CGFloat
}
