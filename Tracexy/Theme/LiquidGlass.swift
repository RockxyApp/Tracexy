import AppKit
import SwiftUI

// MARK: - LiquidGlassRenderingPolicy

/// Pure rendering policy for Tracexy's functional glass surfaces.
///
/// Accessibility preferences are authoritative. Reduce Transparency and
/// Increase Contrast both select an opaque system surface; otherwise macOS 26
/// receives native Liquid Glass and older supported systems receive a managed
/// system material fallback.
enum LiquidGlassRenderingPolicy {
    enum Decision: Equatable {
        case liquidGlass
        case systemMaterial
        case opaqueColor
    }

    static func resolve(
        liquidGlassAvailable: Bool,
        reduceTransparency: Bool,
        increaseContrast: Bool
    )
        -> Decision
    {
        if reduceTransparency || increaseContrast {
            return .opaqueColor
        }
        return liquidGlassAvailable ? .liquidGlass : .systemMaterial
    }
}

// MARK: - LiquidGlassAppearanceIdentity

/// Native effects can retain their sampled tone across an in-place appearance
/// change. Re-keying the effect from every appearance input keeps Light, Dark,
/// System and accessibility transitions visually coherent without storing any
/// presentation state in product models.
struct LiquidGlassAppearanceIdentity: Hashable {
    let isDark: Bool
    let reduceTransparency: Bool
    let increaseContrast: Bool
}

// MARK: - TracexyChromeEdge

enum TracexyChromeEdge: Equatable {
    case top
    case bottom
}

// MARK: - TracexyGlassEffectGroup

/// Shares one native sampling region across nearby functional controls on
/// macOS 26 while preserving the same layout on older supported systems.
struct TracexyGlassEffectGroup<Content: View>: View {
    // MARK: Lifecycle

    init(spacing: CGFloat? = nil, @ViewBuilder content: () -> Content) {
        self.spacing = spacing
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) {
                content
            }
            .id(appearanceIdentity)
        } else {
            content
        }
        #else
        content
        #endif
    }

    // MARK: Private

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private let spacing: CGFloat?
    private let content: Content

    private var appearanceIdentity: LiquidGlassAppearanceIdentity {
        LiquidGlassAppearanceIdentity(
            isDark: colorScheme == .dark,
            reduceTransparency: reduceTransparency,
            increaseContrast: colorSchemeContrast == .increased
        )
    }
}

// MARK: - View surface helpers

extension View {
    /// Applies native Liquid Glass to a functional surface when available, with
    /// deterministic material and opaque accessibility fallbacks.
    func tracexyGlassEffect(
        tint: Color? = nil,
        interactive: Bool = false,
        in shape: some InsettableShape
    )
        -> some View
    {
        modifier(TracexyGlassEffectModifier(tint: tint, interactive: interactive, shape: shape))
    }

    /// Uses the native macOS glass button family where available and standard
    /// bordered controls elsewhere. Labels, sizing and accessibility stay owned
    /// by the original Button.
    func tracexyGlassButtonStyle(prominent: Bool = false) -> some View {
        modifier(TracexyGlassButtonStyleModifier(prominent: prominent))
    }

    /// A compact functional chrome layer for command bars, filter shelves and
    /// footer controls. Dense tables and inspectors intentionally remain opaque
    /// content surfaces instead of becoming nested glass islands.
    func tracexyFunctionalBar() -> some View {
        modifier(TracexyFunctionalBarModifier())
    }

    /// Semantic chips remain readable tint-and-stroke surfaces rather than tiny
    /// translucent samples. The selected label never becomes white-on-accent.
    func tracexyChipStyle(
        tint: Color = .accentColor,
        isActive: Bool = false,
        isHovered: Bool = false,
        isEnabled: Bool = true
    )
        -> some View
    {
        modifier(TracexyChipModifier(
            tint: tint,
            isActive: isActive,
            isHovered: isHovered,
            isEnabled: isEnabled
        ))
    }

    /// Gives information-dense cards a quiet, opaque adaptive surface. This is
    /// the deliberate counterpart to `tracexyGlassEffect`: content remains easy
    /// to scan while the surrounding chrome carries the optical material.
    func tracexyContentSurface(
        tint: Color? = nil,
        in shape: some InsettableShape
    )
        -> some View
    {
        modifier(TracexyContentSurfaceModifier(tint: tint, shape: shape))
    }

    /// Seats functional chrome in the platform safe-area layer on macOS 26 so
    /// scrollable content can continue underneath it. Older systems retain the
    /// same reading order in a zero-spacing vertical stack.
    func tracexySafeAreaBar(
        edge: TracexyChromeEdge,
        @ViewBuilder bar: () -> some View
    )
        -> some View
    {
        modifier(TracexySafeAreaBarModifier(edge: edge, bar: bar()))
    }

    /// Stronger scroll-edge separation for dense Mac content such as tables and
    /// inspectors with pinned functional chrome.
    func tracexyDenseScrollEdge() -> some View {
        modifier(TracexyScrollEdgeModifier(isDense: true))
    }

    /// Softer separation for navigation lists and settings panes.
    func tracexySoftScrollEdge() -> some View {
        modifier(TracexyScrollEdgeModifier(isDense: false))
    }

    /// Keeps fixed AppKit-backed split content reachable where the hosting split
    /// does not consume SwiftUI's propagated safe-area insets. Scroll views that
    /// already honor the inset should not use this escape hatch.
    func tracexyChromeContentClearance(
        edge: TracexyChromeEdge,
        length: CGFloat
    )
        -> some View
    {
        modifier(TracexyChromeContentClearanceModifier(edge: edge, length: length))
    }
}

// MARK: - TracexySafeAreaBarModifier

private struct TracexySafeAreaBarModifier<Bar: View>: ViewModifier {
    // MARK: Internal

    let edge: TracexyChromeEdge
    let bar: Bar

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            switch edge {
            case .top:
                content.safeAreaBar(edge: .top, spacing: 0) { bar }
            case .bottom:
                content.safeAreaBar(edge: .bottom, spacing: 0) { bar }
            }
        } else {
            legacy(content: content)
        }
        #else
        legacy(content: content)
        #endif
    }

    // MARK: Private

    private func legacy(content: Content) -> some View {
        VStack(spacing: 0) {
            if edge == .top {
                bar
            }
            content
            if edge == .bottom {
                bar
            }
        }
    }
}

// MARK: - TracexyScrollEdgeModifier

private struct TracexyScrollEdgeModifier: ViewModifier {
    let isDense: Bool

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            if isDense {
                content.scrollEdgeEffectStyle(.hard, for: .vertical)
            } else {
                content.scrollEdgeEffectStyle(.soft, for: .vertical)
            }
        } else {
            content
        }
        #else
        content
        #endif
    }
}

// MARK: - TracexyChromeContentClearanceModifier

private struct TracexyChromeContentClearanceModifier: ViewModifier {
    let edge: TracexyChromeEdge
    let length: CGFloat

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            switch edge {
            case .top:
                content.padding(.top, length)
            case .bottom:
                content.padding(.bottom, length)
            }
        } else {
            content
        }
        #else
        content
        #endif
    }
}

// MARK: - TracexyGlassEffectModifier

private struct TracexyGlassEffectModifier<S: InsettableShape>: ViewModifier {
    // MARK: Internal

    let tint: Color?
    let interactive: Bool
    let shape: S

    func body(content: Content) -> some View {
        content
            .tracexyGlassRendering(
                LiquidGlassRenderingPolicy.resolve(
                    liquidGlassAvailable: Self.isLiquidGlassAvailable,
                    reduceTransparency: reduceTransparency,
                    increaseContrast: colorSchemeContrast == .increased
                ),
                tint: tint,
                interactive: interactive,
                in: shape
            )
            .id(appearanceIdentity)
    }

    // MARK: Private

    private static var isLiquidGlassAvailable: Bool {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            return true
        }
        #endif
        return false
    }

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private var appearanceIdentity: LiquidGlassAppearanceIdentity {
        LiquidGlassAppearanceIdentity(
            isDark: colorScheme == .dark,
            reduceTransparency: reduceTransparency,
            increaseContrast: colorSchemeContrast == .increased
        )
    }
}

// MARK: - TracexyGlassButtonStyleModifier

private struct TracexyGlassButtonStyleModifier: ViewModifier {
    // MARK: Internal

    let prominent: Bool

    func body(content: Content) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            if prominent {
                content.buttonStyle(.glassProminent).id(appearanceIdentity)
            } else {
                content.buttonStyle(.glass).id(appearanceIdentity)
            }
        } else if prominent {
            content.buttonStyle(.borderedProminent)
        } else {
            content.buttonStyle(.bordered)
        }
        #else
        if prominent {
            content.buttonStyle(.borderedProminent)
        } else {
            content.buttonStyle(.bordered)
        }
        #endif
    }

    // MARK: Private

    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private var appearanceIdentity: LiquidGlassAppearanceIdentity {
        LiquidGlassAppearanceIdentity(
            isDark: colorScheme == .dark,
            reduceTransparency: reduceTransparency,
            increaseContrast: colorSchemeContrast == .increased
        )
    }
}

// MARK: - TracexyFunctionalBarModifier

private struct TracexyFunctionalBarModifier: ViewModifier {
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(
            cornerRadius: Theme.Glass.functionalBarCornerRadius,
            style: .continuous
        )

        content
            .tracexyGlassEffect(in: shape)
            .padding(.horizontal, Theme.Glass.functionalBarHorizontalInset)
            .padding(.vertical, Theme.Glass.functionalBarVerticalInset)
    }
}

// MARK: - TracexyChipModifier

private struct TracexyChipModifier: ViewModifier {
    // MARK: Internal

    let tint: Color
    let isActive: Bool
    let isHovered: Bool
    let isEnabled: Bool

    func body(content: Content) -> some View {
        content
            .foregroundStyle(isActive ? tint : Color.primary)
            .background(fillColor, in: Capsule(style: .continuous))
            .overlay {
                Capsule(style: .continuous)
                    .strokeBorder(strokeColor, lineWidth: colorSchemeContrast == .increased ? 1 : 0.75)
                    .allowsHitTesting(false)
            }
            .contentShape(Capsule(style: .continuous))
            .opacity(isEnabled ? 1 : 0.45)
    }

    // MARK: Private

    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private var fillColor: Color {
        if isActive {
            return tint.opacity(
                isHovered ? Theme.Glass.semanticHoverFillOpacity : Theme.Glass.semanticFillOpacity
            )
        }
        return Color.primary.opacity(
            isHovered ? Theme.Glass.hoverFillOpacity : Theme.Glass.neutralFillOpacity
        )
    }

    private var strokeColor: Color {
        if isActive {
            return tint.opacity(
                isHovered ? Theme.Glass.semanticHoverStrokeOpacity : Theme.Glass.semanticStrokeOpacity
            )
        }
        return Color.primary.opacity(
            colorSchemeContrast == .increased
                ? Theme.Glass.semanticStrokeOpacity
                : Theme.Glass.neutralStrokeOpacity
        )
    }
}

// MARK: - TracexyContentSurfaceModifier

private struct TracexyContentSurfaceModifier<S: InsettableShape>: ViewModifier {
    // MARK: Internal

    let tint: Color?
    let shape: S

    func body(content: Content) -> some View {
        content
            .background(Color(nsColor: .controlBackgroundColor), in: shape)
            .overlay {
                if let tint {
                    shape.fill(tint.opacity(Theme.Glass.contentTintOpacity))
                }
            }
            .overlay {
                shape.strokeBorder(
                    tint?.opacity(Theme.Glass.contentTintStrokeOpacity)
                        ?? Color.primary.opacity(Theme.Glass.contentStrokeOpacity),
                    lineWidth: colorSchemeContrast == .increased ? 1 : 0.5
                )
            }
    }

    // MARK: Private

    @Environment(\.colorSchemeContrast) private var colorSchemeContrast
}

// MARK: - Rendering treatments

private extension View {
    @ViewBuilder
    func tracexyGlassRendering(
        _ decision: LiquidGlassRenderingPolicy.Decision,
        tint: Color?,
        interactive: Bool,
        in shape: some InsettableShape
    )
        -> some View
    {
        switch decision {
        case .liquidGlass:
            #if compiler(>=6.2)
            if #available(macOS 26.0, *) {
                glassEffect(
                    Glass.regular.tint(tint).interactive(interactive),
                    in: shape
                )
            } else {
                tracexyMaterialSurface(tint: tint, in: shape)
            }
            #else
            tracexyMaterialSurface(tint: tint, in: shape)
            #endif
        case .systemMaterial:
            tracexyMaterialSurface(tint: tint, in: shape)
        case .opaqueColor:
            tracexyOpaqueSurface(tint: tint, in: shape)
        }
    }

    @ViewBuilder
    func tracexyMaterialSurface(tint: Color?, in shape: some InsettableShape) -> some View {
        if let tint {
            background(tint.opacity(Theme.Glass.fallbackTintOpacity), in: shape)
                .overlay {
                    shape.strokeBorder(
                        tint.opacity(Theme.Glass.fallbackStrokeOpacity),
                        lineWidth: 0.5
                    )
                }
        } else {
            background(.regularMaterial, in: shape)
                .overlay {
                    shape.strokeBorder(
                        Color.primary.opacity(Theme.Glass.neutralStrokeOpacity),
                        lineWidth: 0.5
                    )
                }
        }
    }

    func tracexyOpaqueSurface(tint: Color?, in shape: some InsettableShape) -> some View {
        background(Color(nsColor: .windowBackgroundColor), in: shape)
            .overlay {
                if let tint {
                    shape.fill(tint.opacity(Theme.Glass.fallbackTintOpacity))
                }
            }
            .overlay {
                shape.strokeBorder(
                    tint?.opacity(Theme.Glass.fallbackStrokeOpacity)
                        ?? Color.primary.opacity(Theme.Glass.neutralStrokeOpacity),
                    lineWidth: 0.5
                )
            }
    }
}
