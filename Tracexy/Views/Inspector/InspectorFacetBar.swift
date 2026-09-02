import SwiftUI

/// The bottom inspector's responsive facet strip. Context belongs to the
/// identity bar above; this component owns only named facets and an optional
/// active-facet accessory. The selected facet always remains directly visible.
struct InspectorFacetBar<Accessory: View>: View {
    // MARK: Internal

    @Bindable var workspace: WorkspaceState

    let visibleTabs: [InspectorTab]
    let activeTab: InspectorTab
    @ViewBuilder let accessory: () -> Accessory

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            ViewThatFits(in: .horizontal) {
                tabTier(limit: visibleTabs.count)
                tabTier(limit: 5)
                tabTier(limit: 3)
                tabTier(limit: 1)
            }
            .layoutPriority(1)

            if activeTab == .layers {
                accessory()
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingM)
        .padding(.vertical, 6)
    }

    // MARK: Private

    private func tabTier(limit: Int) -> some View {
        let directlyVisible = directlyVisibleTabs(limit: limit)
        let overflow = visibleTabs.filter { !directlyVisible.contains($0) }
        return HStack(spacing: 2) {
            ForEach(directlyVisible) { tab in
                tabButton(tab)
            }
            if !overflow.isEmpty {
                Menu {
                    ForEach(overflow) { tab in
                        Button {
                            workspace.inspectorTab = tab
                        } label: {
                            Label(tab.title, systemImage: tab == activeTab ? "checkmark" : tab.systemImage)
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.system(size: Theme.Icon.medium))
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("More inspector facets")
                .accessibilityLabel("More inspector facets")
            }
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    private func tabButton(_ tab: InspectorTab) -> some View {
        Button {
            workspace.inspectorTab = tab
        } label: {
            Text(tab.title)
                .font(tab == activeTab ? Theme.Typography.bodyEmphasis : Theme.Typography.body)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 9)
                .padding(.vertical, 4)
                .tracexyChipStyle(tint: .accentColor, isActive: tab == activeTab)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(tab == activeTab ? .isSelected : [])
        .help(tab.title)
    }

    private func directlyVisibleTabs(limit: Int) -> [InspectorTab] {
        guard !visibleTabs.isEmpty else {
            return []
        }
        let capacity = max(1, min(limit, visibleTabs.count))
        var selected = Array(visibleTabs.prefix(capacity))
        if !selected.contains(activeTab) {
            selected[selected.index(before: selected.endIndex)] = activeTab
        }
        let selectedSet = Set(selected)
        return visibleTabs.filter { selectedSet.contains($0) }
    }
}
