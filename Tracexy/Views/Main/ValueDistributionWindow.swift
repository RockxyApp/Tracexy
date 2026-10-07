import AppKit
import SwiftUI

// MARK: - ValueDistributionWindow

/// Statistics ▸ Value Distribution: every value one decode-tree field took across
/// the frames in view, with its occurrences, share and the normalized Shannon
/// entropy of the whole, as Wireshark's Distribution window. A high entropy means
/// values are evenly spread; a low one, that a few dominate.
struct ValueDistributionWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        @Bindable var controller = controller
        content
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Toggle("Limit to Sessions in View", isOn: $controller.limitToSessionsInView)
                        .toggleStyle(.checkbox)
                        .help("Count only the frames of the sessions the main window shows")
                }
                ToolbarItem(placement: .primaryAction) {
                    fieldMenu
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .tracexySafeAreaBar(edge: .bottom) { footer }
            .frame(minWidth: 520, minHeight: 320)
            .task(id: RunKey(field: controller.field, limited: controller.limitToSessionsInView)) {
                controller.run(from: coordinator)
            }
            .onDisappear { controller.cancel() }
    }

    /// Each field of `layers`, once, in decode-tree order.
    static func fields(in layers: [DecodedLayer]) -> [FieldKey] {
        var seen = Set<FieldKey>()
        var keys: [FieldKey] = []
        func walk(_ layers: [DecodedLayer]) {
            for layer in layers {
                for field in layer.fields {
                    let key = FieldKey(proto: layer.proto, name: field.name)
                    if seen.insert(key).inserted {
                        keys.append(key)
                    }
                }
                walk(layer.children)
            }
        }
        walk(layers)
        return keys
    }

    // MARK: Private

    private struct RunKey: Hashable {
        let field: FieldKey?
        let limited: Bool
    }

    @State private var selection: FieldValueDistribution.Row.ID?
    @State private var notice: String?

    private var controller: FieldValueDistributionController {
        FieldValueDistributionController.shared
    }

    /// The counts, then the entropy — Wireshark's hint line.
    private var summary: String {
        guard let result = controller.result else {
            return ""
        }
        let counts = String(localized: """
        \(result.rows.count.formatted()) values in \(result.occurrences.formatted()) occurrences
        """)
        guard let entropy = result.entropy else {
            return counts
        }
        let value = entropy.formatted(.number.precision(.fractionLength(3)))
        return String(localized: "\(counts), entropy \(value)")
    }

    @ViewBuilder private var content: some View {
        if controller.field == nil {
            ContentUnavailableView(
                "Choose a Field",
                systemImage: "chart.bar.doc.horizontal",
                description: Text(
                    "Right-click a field in Layers and choose Show Value Distribution, or pick one from the Field menu."
                )
            )
        } else if controller.isLoading {
            ProgressView("Counting values…")
                .controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = controller.error {
            ContentUnavailableView(
                "Values Unavailable",
                systemImage: "chart.bar.doc.horizontal",
                description: Text(error)
            )
        } else if let result = controller.result, !result.rows.isEmpty {
            table(result)
        } else if let field = controller.field {
            ContentUnavailableView(
                "No Values",
                systemImage: "chart.bar.doc.horizontal",
                description: Text("No frame in view carries \(field.title).")
            )
        }
    }

    private var fieldMenu: some View {
        let offered = Self.fields(in: coordinator.selectedSession?.decodedLayers ?? [])
        return Menu {
            if offered.isEmpty {
                Text("Select a session to choose among its fields")
            }
            ForEach(offered, id: \.self) { key in
                Button(key.title) { controller.field = key }
            }
        } label: {
            Label(controller.field?.title ?? String(localized: "Field"), systemImage: "list.bullet.rectangle")
                .labelStyle(.titleAndIcon)
        }
        .help("The field whose values are counted; the menu lists the selected session's fields")
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary)
                .lineLimit(1)
                .truncationMode(.tail)
                .help("Entropy near 1 means the values are evenly spread; near 0, that one value dominates.")
            Spacer()
            Button("Copy as CSV") {
                if let result = controller.result {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(result.csv(), forType: .string)
                }
            }
            .disabled(controller.result?.rows.isEmpty ?? true)
            Button("Save as CSV…") {
                if let result = controller.result {
                    notice = StatisticsExport.saveText(result.csv(), suggestedName: "Value Distribution.csv")
                }
            }
            .disabled(controller.result?.rows.isEmpty ?? true)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private func table(_ result: FieldValueDistribution) -> some View {
        Table(result.rows, selection: $selection) {
            TableColumn("Value") { row in
                Text(row.value).font(Theme.Typography.mono).lineLimit(1).truncationMode(.middle).help(row.value)
            }
            .width(min: 180, ideal: 320)
            TableColumn("Occurrences") { row in
                Text(row.count.formatted()).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 70, ideal: 90)
            TableColumn("Percent") { row in
                Text(row.percent.formatted(.number.precision(.fractionLength(2))) + "%")
                    .monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
            }
            .width(min: 60, ideal: 80)
        }
        .contextMenu(forSelectionType: FieldValueDistribution.Row.ID.self) { ids in
            if let value = ids.first {
                Button("Copy Value", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                }
            }
        }
    }
}
