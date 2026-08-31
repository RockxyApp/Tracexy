import SwiftUI

// Reusable Settings building blocks that give every pane a classic
// macOS System-Preferences look: a scrolling pane of titled, rounded cards
// containing aligned labelled rows and compact checkbox groups.

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
        let pane = ScrollView {
            VStack(alignment: .leading, spacing: metrics.sectionSpacing) {
                content
            }
            .padding(.horizontal, metrics.contentPadding)
            .padding(.top, 20)
            .padding(.bottom, 20)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)

        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            pane.scrollEdgeEffectStyle(.soft, for: .vertical)
        } else {
            pane
        }
        #else
        pane
        #endif
    }

    // MARK: Private

    private let metrics: SettingsDisplayMetrics
    private let content: Content
}

// MARK: - SettingsSection

/// Keeps a section title and its card together while preserving the larger gap
/// between neighboring sections.
struct SettingsSection<Content: View>: View {
    // MARK: Lifecycle

    init(
        _ title: String,
        metrics: SettingsDisplayMetrics = .standard,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.metrics = metrics
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.sectionTitleSpacing) {
            SettingsSectionTitle(title, metrics: metrics)
            SettingsCard(metrics: metrics) {
                content
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: Private

    private let title: String
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

    init(
        metrics: SettingsDisplayMetrics = .standard,
        @ViewBuilder content: () -> Content
    ) {
        self.metrics = metrics
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        VStack(alignment: .leading, spacing: metrics.cardSpacing) {
            content
        }
        .padding(.horizontal, metrics.cardHorizontalPadding)
        .padding(.vertical, metrics.cardVerticalPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tracexyContentSurface(
            in: RoundedRectangle(
                cornerRadius: metrics.cardCornerRadius,
                style: .continuous
            )
        )
    }

    // MARK: Private

    private let metrics: SettingsDisplayMetrics
    private let content: Content
}

// MARK: - SettingsDivider

/// A quiet separator between peer controls inside one settings card.
struct SettingsDivider: View {
    var body: some View {
        Divider()
            .overlay(Color(nsColor: .separatorColor).opacity(0.18))
    }
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

// MARK: - SettingsIndented

/// Places arbitrary content in the control column, aligned with the controls of
/// the `SettingsRow`s around it. Use it for action rows, notes, and messages
/// that belong to the row above but carry no label of their own.
struct SettingsIndented<Content: View>: View {
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
        HStack(alignment: .top, spacing: 0) {
            Color.clear.frame(width: metrics.rowLeading)
            content
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: Private

    private let metrics: SettingsDisplayMetrics
    private let content: Content
}

// MARK: - SettingsFootnote

/// The secondary explanatory line that follows a control. Wrapped in a type so
/// every pane gets the same size, color, and wrapping behavior instead of each
/// one re-deriving it.
struct SettingsFootnote: View {
    // MARK: Lifecycle

    init(
        _ text: String,
        maxWidth: CGFloat = 460,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        self.text = text
        self.maxWidth = maxWidth
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        Text(text)
            .font(metrics.secondaryFont())
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: metrics.fieldWidth(maxWidth), alignment: .leading)
    }

    // MARK: Private

    private let text: String
    private let maxWidth: CGFloat
    private let metrics: SettingsDisplayMetrics
}

// MARK: - SettingsStatusBanner

/// A tinted status strip: symbol, a title and detail line, and an optional
/// trailing control.
///
/// This is the "what is the state of this thing right now" element — one per
/// pane, at the top, doing the job a row of grey label/value pairs does badly.
/// The tint carries the state, so the pane does not have to spell it out twice.
struct SettingsStatusBanner<Accessory: View>: View {
    // MARK: Lifecycle

    /// `titleIdentifier` lands on the title text itself rather than the banner,
    /// so UI tests keep matching a `staticText` whose value is the status line.
    /// Marking the whole banner as one accessibility element would hide it.
    init(
        symbol: String,
        tint: Color,
        title: String,
        detail: String? = nil,
        isBusy: Bool = false,
        titleIdentifier: String? = nil,
        metrics: SettingsDisplayMetrics = .standard,
        @ViewBuilder accessory: () -> Accessory
    ) {
        self.symbol = symbol
        self.tint = tint
        self.title = title
        self.detail = detail
        self.isBusy = isBusy
        self.titleIdentifier = titleIdentifier
        self.metrics = metrics
        self.accessory = accessory()
    }

    // MARK: Internal

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            leadingIndicator
                .frame(width: 34, height: 34)
                .background(Color.secondary.opacity(0.10), in: Circle())

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(metrics.font(weight: .semibold))
                    .accessibilityIdentifier(titleIdentifier ?? "")
                if let detail {
                    Text(detail)
                        .font(metrics.secondaryFont())
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 12)

            accessory
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .frame(minHeight: 76)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tracexyContentSurface(
            tint: tint,
            in: RoundedRectangle(
                cornerRadius: metrics.cardCornerRadius,
                style: .continuous
            )
        )
    }

    // MARK: Private

    private let symbol: String
    private let tint: Color
    private let title: String
    private let detail: String?
    private let isBusy: Bool
    private let titleIdentifier: String?
    private let metrics: SettingsDisplayMetrics
    private let accessory: Accessory

    @ViewBuilder private var leadingIndicator: some View {
        if isBusy {
            ProgressView()
                .controlSize(.small)
        } else {
            Image(systemName: symbol)
                .font(.system(size: Theme.Icon.large))
                .foregroundStyle(tint)
        }
    }
}

extension SettingsStatusBanner where Accessory == EmptyView {
    init(
        symbol: String,
        tint: Color,
        title: String,
        detail: String? = nil,
        isBusy: Bool = false,
        titleIdentifier: String? = nil,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        self.init(
            symbol: symbol,
            tint: tint,
            title: title,
            detail: detail,
            isBusy: isBusy,
            titleIdentifier: titleIdentifier,
            metrics: metrics
        ) { EmptyView() }
    }
}

// MARK: - SettingsBadge

/// A small capsule fact — the two or three things worth reading before the
/// detail grid. Tinted `.secondary` by default so a row of them stays quiet;
/// pass a tint only when one badge genuinely outranks the others.
struct SettingsBadge: View {
    // MARK: Lifecycle

    init(
        _ text: String,
        systemImage: String? = nil,
        tint: Color = .secondary,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        self.text = text
        systemName = systemImage
        self.tint = tint
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        HStack(spacing: 4) {
            if let systemName {
                Image(systemName: systemName)
                    .font(metrics.metadataFont(weight: .semibold))
            }
            Text(text)
                .font(metrics.metadataFont(weight: .medium))
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .tracexyChipStyle(tint: tint, isActive: true)
    }

    // MARK: Private

    private let text: String
    private let systemName: String?
    private let tint: Color
    private let metrics: SettingsDisplayMetrics
}

// MARK: - SettingsDetailGrid

/// Baseline-aligned label/value pairs inside a card.
///
/// A `Grid` rather than stacked `HStack`s so the value column lines up no matter
/// how long any single label is, and so a value that wraps does not drag its
/// label out of alignment with the rows around it.
struct SettingsDetailGrid<Content: View>: View {
    // MARK: Lifecycle

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    // MARK: Internal

    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 8) {
            content
        }
    }

    // MARK: Private

    private let content: Content
}

// MARK: - SettingsDetailRow

/// One `SettingsDetailGrid` pair. The value defaults to selectable body text;
/// pass `monospaced` for keys and identifiers, where character shape matters
/// more than reading speed.
struct SettingsDetailRow: View {
    // MARK: Lifecycle

    init(
        _ label: String,
        value: String,
        monospaced: Bool = false,
        tint: Color? = nil,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        self.label = label
        self.value = value
        self.monospaced = monospaced
        self.tint = tint
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        GridRow {
            Text(label)
                .font(metrics.secondaryFont())
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
                .frame(width: metrics.detailLabelWidth, alignment: .trailing)

            Text(value)
                .font(monospaced ? metrics.monospacedFont() : metrics.font())
                .foregroundStyle(tint ?? .primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .gridColumnAlignment(.leading)
        }
    }

    // MARK: Private

    private let label: String
    private let value: String
    private let monospaced: Bool
    private let tint: Color?
    private let metrics: SettingsDisplayMetrics
}

// MARK: - SettingsMessageTone

enum SettingsMessageTone {
    case info
    case success
    case warning
    case failure

    // MARK: Internal

    var symbol: String {
        switch self {
        case .info: "info.circle.fill"
        case .success: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .failure: "xmark.octagon.fill"
        }
    }

    var tint: Color {
        switch self {
        case .info: .blue
        case .success: .green
        case .warning: .orange
        case .failure: .red
        }
    }
}

// MARK: - SettingsInlineMessage

/// The result of the action the user just took, shown where they took it.
///
/// Deliberately not an alert and not a floating card: the message belongs to the
/// control that produced it, and a card that appears and disappears between two
/// other cards makes the whole pane jump.
struct SettingsInlineMessage: View {
    // MARK: Lifecycle

    init(
        _ text: String,
        tone: SettingsMessageTone,
        metrics: SettingsDisplayMetrics = .standard
    ) {
        self.text = text
        self.tone = tone
        self.metrics = metrics
    }

    // MARK: Internal

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Image(systemName: tone.symbol)
                .font(metrics.secondaryFont())
                .foregroundStyle(tone.tint)
            Text(text)
                .font(metrics.secondaryFont())
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: metrics.fieldWidth(460), alignment: .leading)
        .background(tone.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: Private

    private let text: String
    private let tone: SettingsMessageTone
    private let metrics: SettingsDisplayMetrics
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
        VStack(alignment: .leading, spacing: 4) {
            Toggle(title, isOn: $isOn)
                .toggleStyle(.checkbox)
            if let description {
                Text(description)
                    .font(metrics.secondaryFont())
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 20)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
        HStack(alignment: .center, spacing: 16) {
            Text(String(localized: "Appearance"))
                .font(metrics.font(weight: .medium))
                .frame(width: metrics.labelWidth, alignment: .leading)

            HStack(spacing: 8) {
                ForEach(AppAppearance.allCases) { appearance in
                    themeOption(appearance)
                }
            }
            .frame(maxWidth: .infinity)
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
            VStack(spacing: 2) {
                Label(appearance.title, systemImage: appearance.systemImage)
                    .font(metrics.font(weight: .medium))
                Text(appearance.detail)
                    .font(metrics.metadataFont())
                    .foregroundStyle(.secondary)
            }
            .foregroundStyle(.primary)
            .frame(maxWidth: .infinity, minHeight: 62)
            .tracexyGlassEffect(
                // A full accent tint made accent-colored labels disappear into
                // the glass in Light appearance. A restrained native tint keeps
                // selection visible without sacrificing text contrast.
                tint: isSelected ? Color.accentColor.opacity(0.18) : nil,
                interactive: true,
                in: RoundedRectangle(cornerRadius: 7, style: .continuous)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
        .accessibilityLabel(appearance.title)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }
}
