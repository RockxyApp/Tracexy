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
/// It owns exactly three things — a fixed row height, the semantic background for
/// its surface, and the top hairline seam — so every bottom bar in the window
/// meets on one baseline and adapts to light/dark and contrast without hand-tuned
/// colors. It carries **no** product actions; each call site places its own
/// controls inside `content` and owns their horizontal layout.
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
            .frame(height: Theme.Metrics.footerBarHeight)
            .frame(maxWidth: .infinity)
            .background(surface.background)
            .overlay(alignment: .top) {
                Divider()
            }
    }

    // MARK: Private

    private let surface: WorkspaceFooterSurface
    private let content: () -> Content
}
