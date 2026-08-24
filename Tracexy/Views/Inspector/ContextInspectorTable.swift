import SwiftUI

// MARK: - ContextTableField

/// One label/value pair in the vertical Details inspector. Technical values use
/// the monospaced inspector face by default; prose opts into proportional text.
struct ContextTableField {
    let label: String
    let value: String
    var monospaced = true
    var color: Color = .primary
}

// MARK: - ContextInspectorTable

/// Rounded diagnostics table shared by every Details group. Its title sits on a
/// control background while the divided rows use the native text background,
/// matching the key/value language of the bottom evidence inspector.
struct ContextInspectorTable<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            ContextInspectorTableHeader(title: title)
            Divider()
            content()
        }
        .contextInspectorTableChrome()
    }
}

// MARK: - ContextInspectorFieldTable

struct ContextInspectorFieldTable: View {
    let title: String
    let fields: [ContextTableField]

    var body: some View {
        ContextInspectorTable(title: title) {
            ForEach(Array(fields.enumerated()), id: \.offset) { index, field in
                if index > 0 {
                    Divider()
                }
                ContextInspectorFieldRow(field: field)
            }
        }
    }
}

// MARK: - ContextInspectorFieldRow

struct ContextInspectorFieldRow: View {
    let field: ContextTableField

    var body: some View {
        HStack(spacing: 0) {
            Text(field.label)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .frame(width: Theme.Metrics.contextTableLabelWidth, alignment: .topLeading)
                .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
                .padding(.vertical, Theme.Metrics.contextTableRowVerticalPadding)
            Divider()
            Text(field.value)
                .font(field.monospaced ? Theme.Typography.monoSmall : Theme.Typography.caption)
                .foregroundStyle(field.color)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .lineLimit(3)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
                .padding(.vertical, Theme.Metrics.contextTableRowVerticalPadding)
        }
    }
}

// MARK: - ContextInspectorInsightRow

/// Semantic icon/title mapped to a supporting explanation on the value side.
struct ContextInspectorInsightRow: View {
    let systemImage: String
    let title: String
    let detail: String
    let color: Color

    var body: some View {
        HStack(spacing: 0) {
            HStack(alignment: .top, spacing: 6) {
                Image(systemName: systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(color)
                    .frame(width: 16)
                Text(title)
                    .font(Theme.Typography.captionMedium)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: Theme.Metrics.contextTableInsightLabelWidth, alignment: .topLeading)
            .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
            .padding(.vertical, Theme.Metrics.contextTableRowVerticalPadding)
            Divider()
            Text(detail)
                .font(Theme.Typography.micro)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
                .padding(.vertical, Theme.Metrics.contextTableRowVerticalPadding)
        }
    }
}

// MARK: - ContextInspectorFullRow

/// Full-width row for charts, actions, explanations, and other content that does
/// not represent a simple label/value mapping.
struct ContextInspectorFullRow<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
            .padding(.vertical, Theme.Metrics.contextTableRowVerticalPadding)
    }
}

// MARK: - ContextInspectorTableHeader

private struct ContextInspectorTableHeader: View {
    let title: String

    var body: some View {
        Text(title)
            .font(Theme.Typography.bodyEmphasis)
            .foregroundStyle(.primary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Theme.Metrics.contextTableColumnPadding)
            .padding(.vertical, Theme.Metrics.contextTableHeaderVerticalPadding)
    }
}

// MARK: - ContextInspectorTableChrome

private struct ContextInspectorTableChrome: ViewModifier {
    func body(content: Content) -> some View {
        content
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .tracexyContentSurface(
                in: RoundedRectangle(
                    cornerRadius: Theme.Metrics.contextTableCornerRadius,
                    style: .continuous
                )
            )
            .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.contextTableCornerRadius))
    }
}

private extension View {
    func contextInspectorTableChrome() -> some View {
        modifier(ContextInspectorTableChrome())
    }
}
