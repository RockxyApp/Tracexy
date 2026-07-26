import AppKit
import SwiftUI

// Compact native toolbar pinned to the bottom of the sidebar: a session-filter
// pill paired with a captures menu, styled entirely with Tracexy `Theme` tokens.

// MARK: - SidebarBottomBar

struct SidebarBottomBar<AddMenu: View>: View {
    @Binding var filterText: String

    /// Menu items shown under the "+" button (Save Current / Import…).
    @ViewBuilder var addMenu: () -> AddMenu

    var body: some View {
        // The shared footer primitive owns the row height, the sidebar material
        // and the top seam, so this bar aligns with the workspace and inspector
        // footers. It contributes only the session filter + captures menu.
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
                    Image(systemName: "line.3.horizontal.decrease.circle")
                        .font(.system(size: Theme.Icon.medium))
                        .foregroundStyle(.secondary)
                    TextField("Filter (\u{2318}\u{21E7}F)", text: $filterText)
                        .textFieldStyle(.plain)
                        .font(Theme.Typography.body)
                        .accessibilityLabel("Filter sessions")
                    if !filterText.isEmpty {
                        Button { filterText = "" } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: Theme.Icon.small))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Clear session filter")
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
