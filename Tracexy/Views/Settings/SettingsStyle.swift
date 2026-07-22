import SwiftUI

// Reusable Settings building blocks that give every pane the sibling app's classic
// pro-macOS System-Preferences look: a scrolling pane of titled, rounded cards
// containing right-aligned labelled rows and indented checkboxes.

// MARK: - SettingsPane

/// Scaffolds a settings pane: a vertically scrolling stack of section titles and
/// cards with consistent padding.
struct SettingsPane<Content: View>: View {
    // MARK: Lifecycle

    init(
        metrics: SettingsDisplayMetrics = .standard,
        @ViewBuilder content: () -> Content
    ) {
        self.metrics = metrics
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                content
            }
            .padding(.horizontal, metrics.contentPadding)
            .padding(.top, 20)
            .padding(.bottom, 20)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Private

    private let metrics: SettingsDisplayMetrics
    private let content: Content
}

// MARK: - SettingsSectionTitle

/// A medium-weight section heading placed above a `SettingsCard`.
struct SettingsSectionTitle: View {
    // MARK: Lifecycle

    init(_ text: String, metrics: SettingsDisplayMetrics = .standard) {
        self.text = text
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        Text(text)
            .font(metrics.font(weight: .medium))
    }

    // MARK: Private

    private let text: String
    private let metrics: SettingsDisplayMetrics
}

// MARK: - SettingsCard

/// A rounded, subtly filled card that groups related controls.
struct SettingsCard<Content: View>: View {
    // MARK: Lifecycle

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            content
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            Color(nsColor: .controlBackgroundColor).opacity(0.82),
            in: RoundedRectangle(cornerRadius: 8)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor).opacity(0.22), lineWidth: 0.5)
        }
    }

    // MARK: Private

    private let content: Content
}

// MARK: - SettingsRow

/// A classic preferences row: a fixed-width, right-aligned label followed by its
/// control.
struct SettingsRow<Content: View>: View {
    // MARK: Lifecycle

    init(
        label: String,
        metrics: SettingsDisplayMetrics = .standard,
        @ViewBuilder content: () -> Content
    ) {
        self.label = label
        self.metrics = metrics
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Text(label)
                .font(metrics.font(weight: .medium))
                .frame(width: metrics.labelWidth, alignment: .trailing)
                .padding(.trailing, 16)
                .padding(.top, 2)
            content
        }
    }

    // MARK: Private

    private let label: String
    private let metrics: SettingsDisplayMetrics
    private let content: Content
}

// MARK: - SettingsCheckbox

/// A checkbox toggle indented to the control column, with an optional secondary
/// description line beneath it.
struct SettingsCheckbox: View {
    // MARK: Lifecycle

    init(
        isOn: Binding<Bool>,
        title: String,
        description: String? = nil,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        _isOn = isOn
        self.title = title
        self.description = description
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Color.clear.frame(width: metrics.rowLeading)
            VStack(alignment: .leading, spacing: 4) {
                Toggle(title, isOn: $isOn)
                    .toggleStyle(.checkbox)
                if let description {
                    Text(description)
                        .font(metrics.secondaryFont())
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: Private

    @Binding private var isOn: Bool

    private let title: String
    private let description: String?
    private let metrics: SettingsDisplayMetrics
}

// MARK: - SettingsThemeCard

/// A horizontal row of clickable theme preview cards (System / Light / Dark)
/// bound to the persisted appearance preference.
struct SettingsThemeCard: View {
    // MARK: Lifecycle

    init(selection: Binding<String>, metrics: SettingsDisplayMetrics = .standard) {
        _selection = selection
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        HStack(alignment: .top, spacing: 36) {
            ForEach(AppAppearance.allCases) { appearance in
                themeOption(appearance)
            }
            Spacer(minLength: 0)
        }
    }

    // MARK: Private

    @Binding private var selection: String

    private let metrics: SettingsDisplayMetrics

    private func themeOption(_ appearance: AppAppearance) -> some View {
        let isSelected = selection == appearance.rawValue
        return Button {
            selection = appearance.rawValue
        } label: {
            VStack(spacing: 8) {
                ThemePreviewCard(appearance: appearance)
                    .frame(width: 78, height: 54)

                HStack(spacing: 6) {
                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .font(metrics.font(weight: .semibold))
                            .foregroundStyle(Color(nsColor: .systemGreen))
                    }
                    Text(appearance.title)
                        .font(metrics.font())
                        .foregroundStyle(.primary)
                }
                .frame(minWidth: 82)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(appearance.title)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }
}

// MARK: - ThemePreviewCard

/// A miniature window preview used inside `SettingsThemeCard`. Draws traffic-light
/// dots, a diagonal light/dark split for System, and a sample session line for the
/// Light/Dark options.
private struct ThemePreviewCard: View {
    // MARK: Internal

    let appearance: AppAppearance

    var body: some View {
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 6)
                .fill(background)

            if appearance == .system {
                GeometryReader { proxy in
                    Path { path in
                        path.move(to: CGPoint(x: 0, y: proxy.size.height))
                        path.addLine(to: CGPoint(x: proxy.size.width, y: 0))
                        path.addLine(to: CGPoint(x: proxy.size.width, y: proxy.size.height))
                        path.closeSubpath()
                    }
                    .fill(Color(nsColor: .windowBackgroundColor))
                }
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            HStack(spacing: 4) {
                Circle().fill(Color(nsColor: .systemRed))
                Circle().fill(Color(nsColor: .systemYellow))
                Circle().fill(Color(nsColor: .systemGreen))
            }
            .frame(width: 34, height: 6)
            .padding(7)

            if appearance != .system {
                VStack(alignment: .leading, spacing: 2) {
                    Text("GET /v1/traffic")
                        .foregroundStyle(.green)
                    Text("200 · 34 ms")
                        .foregroundStyle(.blue)
                    Text("TLS 1.3 · h2")
                        .foregroundStyle(.purple)
                }
                // Off-scale on purpose: this is illustration inside a ~1:6
                // thumbnail of the app, not UI text. It is never read — it
                // stands in for "lines of traffic" at thumbnail scale — so the
                // Typography scale doesn't apply.
                .font(.system(size: 4.5, design: .monospaced))
                .padding(.top, 22)
                .padding(.leading, 11)
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 0.5)
        }
    }

    // MARK: Private

    private var background: Color {
        switch appearance {
        case .system,
             .light:
            Color(nsColor: .textBackgroundColor)
        case .dark:
            Color(nsColor: .windowBackgroundColor)
        }
    }
}
