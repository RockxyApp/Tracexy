import SwiftUI

// MARK: - WorkspaceFooterSurface

/// Which chrome surface a footer sits on. The bottom bars are deliberately
/// *different* materials (see `Theme.Chrome`): the sidebar footer lives inside
/// the source-list column and inherits that column's sidebar material, while the
/// workspace status bar and the right Details footer sit over opaque content and
/// use the window background so nothing bleeds up through them.
enum WorkspaceFooterSurface {
    case sidebar
    case workspace

    // MARK: Internal

    var background: Color {
        switch self {
        case .sidebar: Theme.Chrome.sidebarFooterBackground
        case .workspace: Theme.Chrome.workspaceFooterBackground
        }
    }
}

// MARK: - WorkspaceFooterBar

/// The shared footer chrome for the sidebar, the workspace/session status bar and
/// the right Details inspector.
///
/// It owns exactly four things — the shared row height, the `chrome` type role,
/// the semantic background for its surface, and the top hairline seam — so every
/// bottom bar in the window meets on one baseline, reads in one typeface, and
/// adapts to light/dark and contrast without hand-tuned colors. It carries **no**
/// product actions; each call site places its own controls inside `content` and
/// owns their horizontal layout.
struct WorkspaceFooterBar<Content: View>: View {
    // MARK: Lifecycle

    init(
        surface: WorkspaceFooterSurface = .workspace,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.surface = surface
        self.content = content
    }

    // MARK: Internal

    var body: some View {
        content()
            // `chrome` is the footer's base type role; call sites may override a
            // specific label, but everything else inherits one consistent scale.
            .font(Theme.Typography.chrome)
            // Scaled off `.callout` (the size `chrome` resolves to) so all three
            // pane footers grow in lockstep at accessibility text sizes and stay
            // on one baseline. Dynamic Type is deliberately *not* capped.
            .frame(height: footerHeight)
            .frame(maxWidth: .infinity)
            .background(surface.background)
            .overlay(alignment: .top) {
                Divider()
            }
    }

    // MARK: Private

    @ScaledMetric(relativeTo: .callout) private var footerHeight = Theme.Metrics.footerBarHeight

    private let surface: WorkspaceFooterSurface
    private let content: () -> Content
}
