import SwiftUI

// MARK: - CaptureFilterImportSheet

/// Transfers one named capture expression out of an explicitly chosen
/// capture-filter list into this Project's custom capture filter.
///
/// Reading, previewing and cancelling change nothing: only Use Filter writes the
/// BPF expression and switches the mode to Custom, and neither path starts a
/// capture. Display filters, coloring rules and profiles are not converted —
/// this sheet moves a capture expression and says so.
struct CaptureFilterImportSheet: View {
    // MARK: Lifecycle

    init(bpf: Binding<String>, filterMode: Binding<String>) {
        _bpf = bpf
        _filterMode = filterMode
    }

    // MARK: Internal

    @Binding var bpf: String
    @Binding var filterMode: String

    var body: some View {
        VStack(spacing: 0) {
            header

            Divider()

            content
                .padding(18)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider()

            footer
        }
        .frame(width: 560, height: 500)
        // A late chooser or worker return must not land in a Project the sheet
        // no longer belongs to: the Settings root remounts on Project identity,
        // which disappears this sheet.
        .onDisappear { model.deactivate() }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var model = CaptureFilterImportModel()

    private var selectedExpression: String? {
        model.selectedFilter?.expression
    }

    private var header: some View {
        HStack(spacing: Theme.Metrics.spacingL) {
            Image(systemName: "line.3.horizontal.decrease.circle.fill")
                .font(.system(size: Theme.Icon.xlarge))
                .foregroundStyle(Color.accentColor)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text("Import Capture Filter")
                    .font(Theme.Typography.surfaceTitle)
                Text(
                    "Reuse a named BPF capture expression from a capture-filter list. Display filters and coloring rules are not converted."
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(18)
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            chooserRow
            listArea
            expressionPreview
        }
    }

    private var chooserRow: some View {
        HStack(spacing: Theme.Metrics.spacingL) {
            Button("Choose File…") { model.chooseFile() }
                .disabled(model.isLoading)
                .accessibilityLabel("Choose capture-filter list")
            Text(model.sourceName ?? String(localized: "No file chosen"))
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .accessibilityLabel("Chosen file")
                .accessibilityValue(model.sourceName ?? String(localized: "None"))
            Spacer(minLength: 0)
            if model.isLoading {
                Button("Stop") { model.cancelRead() }
            }
        }
    }

    @ViewBuilder private var listArea: some View {
        switch model.phase {
        case .idle:
            placeholder(
                title: String(localized: "No Filter List Chosen"),
                symbol: "doc.text.magnifyingglass",
                detail: String(
                    localized: "Choose a capture-filter list, such as “cfilters”. Tracexy reads it and shows the named expressions it contains."
                )
            )
        case .loading:
            VStack(spacing: Theme.Metrics.spacingM) {
                ProgressView().controlSize(.small)
                Text("Reading capture filters…")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case let .failed(message):
            failure(message)
        case .loaded:
            if model.filters.isEmpty {
                placeholder(
                    title: String(localized: "No Named Filters"),
                    symbol: "line.3.horizontal.decrease.circle",
                    detail: String(localized: "This file contains no named capture filters.")
                )
            } else {
                filterList
            }
        }
    }

    private var filterList: some View {
        List(model.filters, selection: $model.selectedFilterID) { filter in
            VStack(alignment: .leading, spacing: 1) {
                Text(filter.name)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(filter.expression)
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .frame(minHeight: Theme.Metrics.rowHeight)
            .accessibilityElement(children: .combine)
            .accessibilityLabel(filter.name)
            .accessibilityValue(filter.expression)
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
        .scrollContentBackground(.hidden)
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
        .overlay {
            RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
        .accessibilityLabel("Named capture filters")
    }

    private var expressionPreview: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text("Capture expression")
                .font(Theme.Typography.bodyMedium)
            ScrollView {
                Text(selectedExpression ?? String(localized: "Select a filter to see its full expression."))
                    .font(Theme.Typography.monoSmall)
                    .foregroundStyle(selectedExpression == nil ? Color.secondary : Color.primary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Theme.Metrics.spacingM)
                    .accessibilityLabel("Selected capture expression")
                    .accessibilityValue(selectedExpression ?? String(localized: "None"))
            }
            .frame(height: 66)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
        }
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingL) {
            Text(
                "Applies to this Project’s next capture. BPF syntax is checked when capture starts."
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: Theme.Metrics.spacingM)
            Button("Cancel", role: .cancel) { close() }
                .keyboardShortcut(.cancelAction)
            Button("Use Filter") { apply() }
                .keyboardShortcut(.defaultAction)
                .tracexyGlassButtonStyle(prominent: true)
                .disabled(!model.canApply)
        }
        .padding(.horizontal, 18)
        .frame(height: 66)
    }

    private func placeholder(title: String, symbol: String, detail: String) -> some View {
        ContentUnavailableView(title, systemImage: symbol, description: Text(detail))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func failure(_ message: String) -> some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: Theme.Icon.hero))
                .foregroundStyle(.orange)
            Text(message)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Import failed")
        .accessibilityValue(message)
    }

    /// The only path that writes a preference, and only for an expression the
    /// model still considers applicable.
    private func apply() {
        guard let expression = model.applicableExpression() else {
            return
        }
        bpf = expression
        filterMode = CaptureFilterMode.custom.rawValue
        close()
    }

    private func close() {
        model.deactivate()
        dismiss()
    }
}

#Preview {
    CaptureFilterImportSheet(bpf: .constant(""), filterMode: .constant(CaptureFilterMode.all.rawValue))
}
