import SwiftUI

// MARK: - WorkspaceFooterSurface

/// Which workspace region owns a footer. The value stays at call sites because
/// it documents layout ownership; the native glass itself samples the region
/// behind it and therefore does not need a hand-painted region color.
enum WorkspaceFooterSurface {
    case sidebar
    case workspace
    case inspector
}

// MARK: - WorkspaceFooterBar

/// The shared footer chrome for the sidebar, the workspace/session status bar and
/// the right Details inspector.
///
/// It owns the shared row height, the `chrome` type role, and the accessibility-
/// aware glass policy so every bottom bar meets on one baseline and adapts to
/// Light, Dark, Reduce Transparency and Increase Contrast. It carries **no**
/// product actions; each call site owns its controls and horizontal layout.
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
        switch surface {
        case .workspace:
            TracexyGlassEffectGroup(spacing: Theme.Glass.functionalBarHorizontalInset) {
                footerContent
                    .tracexyGlassEffect(
                        in: RoundedRectangle(
                            cornerRadius: Theme.Glass.functionalBarCornerRadius,
                            style: .continuous
                        )
                    )
            }
            .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
            .padding(.vertical, Theme.Glass.functionalBarVerticalInset)
        case .sidebar,
             .inspector:
            // These panes are already semantic native Liquid Glass split items.
            // A second glass island would sample glass from glass and flatten the
            // system material, so their safe-area bars stay transparent.
            footerContent
        }
    }

    // MARK: Private

    @ScaledMetric(relativeTo: .callout) private var footerHeight = Theme.Metrics.footerBarHeight

    private let surface: WorkspaceFooterSurface
    private let content: () -> Content

    private var footerContent: some View {
        content()
            .font(Theme.Typography.chrome)
            .frame(height: footerHeight)
            .frame(maxWidth: .infinity)
    }
}
