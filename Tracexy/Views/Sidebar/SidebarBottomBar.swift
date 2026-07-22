import AppKit
import SwiftUI

// Bottom toolbar for the sidebar: a compact filter pill plus an "add" menu.
// Mirrors the sibling app's `SidebarBottomBar` (Finder/Proxyman-style), self-contained
// with Tracexy `Theme` tokens instead of the sibling app's `appUIDisplayMetrics`.

// MARK: - SidebarBottomBar

struct SidebarBottomBar<AddMenu: View>: View {
    @Binding var filterText: String

    /// Menu items shown under the "+" button (e.g. Save Current / Import…).
    @ViewBuilder var addMenu: () -> AddMenu

    var body: some View {
        HStack(spacing: 6) {
            Menu {
                addMenu()
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: Theme.Icon.medium))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Add to Favorites")

            HStack(spacing: 4) {
                Image(systemName: "line.3.horizontal.decrease.circle")
                    .font(.system(size: Theme.Icon.medium))
                    .foregroundStyle(.secondary)
                TextField("Filter (\u{2318}\u{21E7}F)", text: $filterText)
                    .textFieldStyle(.plain)
                    .font(Theme.Typography.body)
                if !filterText.isEmpty {
                    Button { filterText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: Theme.Icon.small))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(Color(nsColor: .quaternaryLabelColor).opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }
}
