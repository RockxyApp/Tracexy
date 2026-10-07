import AppKit
import SwiftUI

// MARK: - FilterButtonBar

/// The row of filter buttons under the toolbar, over the session content: one
/// accessory-bar button per filter button, a pull-down per `Group//`, the
/// expansion of the expression in use when it used macros, and a button that adds
/// the current expression.
struct FilterButtonBar: View {
    // MARK: Internal

    static let height: CGFloat = 30

    let controller: ExpressionLibraryController

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(controller.barItems) { item in
                        itemView(item)
                    }
                }
                .padding(.horizontal, 2)
            }
            .scrollBounceBehavior(.basedOnSize, axes: .horizontal)

            if let expansion = controller.acceptedExpansion() {
                expansionView(expansion)
            }

            Button {
                controller.beginAddingButton()
            } label: {
                Image(systemName: "plus")
            }
            .buttonStyle(.accessoryBar)
            .help(Text("Add the current expression as a filter button"))
            .accessibilityLabel(Text("Add Filter Button"))
            .accessibilityIdentifier("filterButtons.add")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingM)
        .frame(height: Self.height)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text("Filter Buttons"))
        .accessibilityIdentifier("filterButtons.bar")
    }

    // MARK: Private

    @ViewBuilder
    private func itemView(_ item: FilterButtonItem) -> some View {
        switch item {
        case let .button(button, title):
            Button {
                controller.apply(button)
            } label: {
                Text(verbatim: title)
            }
            .buttonStyle(.accessoryBar)
            .help(button.helpText)
            .accessibilityHint(Text(verbatim: button.expression))
            .accessibilityIdentifier("filterButton.\(button.id.uuidString)")
            .contextMenu {
                buttonContextMenu(button)
            }
        case let .group(name, items):
            Menu {
                FilterButtonMenuContent(items: items, controller: controller)
            } label: {
                // One text run, so the pull-down arrow follows the name.
                Text(verbatim: name + " ") + Text(Image(systemName: "chevron.down"))
                    .font(Theme.Typography.microEmphasis)
            }
            .menuStyle(.button)
            .menuIndicator(.hidden)
            .buttonStyle(.accessoryBar)
            .fixedSize()
            .accessibilityLabel(Text(verbatim: name))
            .accessibilityIdentifier("filterButtonGroup.\(name)")
        }
    }

    @ViewBuilder
    private func buttonContextMenu(_ button: FilterButton) -> some View {
        Button {
            controller.beginEditing(button)
        } label: {
            Text("Edit…")
        }
        Button {
            controller.move(button, by: -1)
        } label: {
            Text("Move Left")
        }
        .disabled(!controller.canMove(button, by: -1))
        Button {
            controller.move(button, by: 1)
        } label: {
            Text("Move Right")
        }
        .disabled(!controller.canMove(button, by: 1))
        Divider()
        Button {
            controller.sheet = .manageButtons
        } label: {
            Text("Edit Filter Buttons…")
        }
        Divider()
        Button(role: .destructive) {
            controller.delete(button)
        } label: {
            Text("Delete")
        }
    }

    private func expansionView(_ expansion: (typed: String, expanded: String)) -> some View {
        Text("Expanded: \(Text(verbatim: expansion.expanded))")
            .font(Theme.Typography.monoSmall)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: 420, alignment: .trailing)
            .help(expansion.expanded)
            .contextMenu {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(expansion.expanded, forType: .string)
                } label: {
                    Text("Copy Expanded Expression")
                }
            }
            .accessibilityIdentifier("filterButtons.expansion")
    }
}

// MARK: - FilterButtonMenuContent

/// Filter buttons as menu items, nested by group. Used by the bar's pull-downs and
/// by the menu bar, so every button is also reachable from the keyboard.
struct FilterButtonMenuContent: View {
    let items: [FilterButtonItem]
    let controller: ExpressionLibraryController

    var body: some View {
        ForEach(items) { item in
            switch item {
            case let .button(button, title):
                Button {
                    controller.apply(button)
                } label: {
                    Text(verbatim: title)
                }
                .help(button.helpText)
            case let .group(name, children):
                Menu {
                    FilterButtonMenuContent(items: children, controller: controller)
                } label: {
                    Text(verbatim: name)
                }
            }
        }
    }
}

// MARK: - FilterButtonBarInstaller

/// Puts the filter-button bar under the toolbar, below the workspace tabs when
/// they show; see ``WorkspaceTopBarHostView``.
struct FilterButtonBarInstaller: NSViewRepresentable {
    let controller: ExpressionLibraryController
    let isVisible: Bool

    static func dismantleNSView(_ view: WorkspaceTopBarHostView, coordinator _: ()) {
        view.uninstall()
    }

    func makeNSView(context _: Context) -> WorkspaceTopBarHostView {
        WorkspaceTopBarHostView(height: FilterButtonBar.height, placement: .last) { [controller] in
            NSHostingView(rootView: FilterButtonBar(controller: controller))
        }
    }

    func updateNSView(_ view: WorkspaceTopBarHostView, context _: Context) {
        view.isBarVisible = isVisible
        view.installIfNeeded()
    }
}
