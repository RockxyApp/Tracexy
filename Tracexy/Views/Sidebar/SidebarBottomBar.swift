import AppKit
import SwiftUI

// Compact native toolbar pinned to the bottom of the sidebar: local navigator
// search paired with a captures menu, styled entirely with Tracexy `Theme` tokens.

// MARK: - SidebarBottomBar

struct SidebarBottomBar<AddMenu: View>: View {
    @Binding var searchText: String

    /// Menu items shown under the "+" button (Save Current / Import…).
    @ViewBuilder var addMenu: () -> AddMenu

    var body: some View {
        // The shared footer primitive owns the row height, the sidebar material
        // and the top seam, so this bar aligns with the workspace and inspector
        // footers. It contributes only local sidebar search + the captures menu.
        WorkspaceFooterBar(surface: .sidebar) {
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
                .help("Save or import a capture")
                .accessibilityLabel("Save or import a capture")

                HStack(spacing: 4) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: Theme.Icon.medium))
                        .foregroundStyle(.secondary)
                    TextField("Search sidebar", text: $searchText)
                        .textFieldStyle(.plain)
                        .font(Theme.Typography.body)
                        .accessibilityLabel("Search sidebar")
                    if !searchText.isEmpty {
                        Button { searchText = "" } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: Theme.Icon.small))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Clear sidebar search")
                    }
                }
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(Color(nsColor: .quaternaryLabelColor).opacity(0.5))
                .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
            }
            .padding(.horizontal, 8)
        }
    }
}
