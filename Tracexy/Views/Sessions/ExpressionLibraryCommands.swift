import SwiftUI

// MARK: - ExpressionLibraryWindowSupport

/// Everything the filter-button library adds to the workspace window: macro
/// expansion on the Session Expression path, the filter-button bar under the
/// toolbar, and the library's sheets.
struct ExpressionLibraryWindowSupport: ViewModifier {
    let coordinator: MainContentCoordinator

    func body(content: Content) -> some View {
        @Bindable var controller = coordinator.filterLibrary
        let isBarVisible = coordinator.hasHydratedProjects
            && !coordinator.projectTransitionStatus.isPending
            && (!controller.buttons.isEmpty || controller.acceptedExpansion() != nil)
        content
            .background {
                FilterButtonBarInstaller(controller: controller, isVisible: isBarVisible)
                    .frame(width: 0, height: 0)
                    .accessibilityHidden(true)
            }
            .sheet(item: $controller.sheet) { sheet in
                ExpressionLibrarySheetView(sheet: sheet, controller: controller)
            }
            .onAppear {
                controller.attach(to: coordinator)
            }
            .onChange(of: coordinator.projectStore.activeProjectID) {
                controller.syncProject()
            }
            .onChange(of: coordinator.hasHydratedProjects) {
                controller.syncProject()
            }
            .onChange(of: coordinator.projectTransitionStatus.isPending) {
                controller.syncProject()
            }
    }
}

extension View {
    /// The filter-button library's window support; see ``ExpressionLibraryWindowSupport``.
    func expressionLibrarySupport(coordinator: MainContentCoordinator) -> some View {
        modifier(ExpressionLibraryWindowSupport(coordinator: coordinator))
    }
}

// MARK: - ExpressionLibraryMenuExtensions

/// Items another part of the app adds to the end of View ▸ Expression Library,
/// after a divider. `nil` adds nothing.
@MainActor
enum ExpressionLibraryMenuExtensions {
    static var installed: (@MainActor () -> AnyView)?
}

// MARK: - ExpressionLibraryCommands

/// View ▸ Expression Library: every filter button (so each is on the keyboard and
/// the menu bar, not only in the bar), adding and editing buttons, and macros.
struct ExpressionLibraryCommands: Commands {
    let controller: ExpressionLibraryController

    var body: some Commands {
        CommandGroup(after: .sidebar) {
            Menu("Expression Library") {
                if !controller.buttons.isEmpty {
                    FilterButtonMenuContent(items: controller.barItems, controller: controller)
                    Divider()
                }
                Button("Add Filter Button…") {
                    controller.beginAddingButton()
                }
                .disabled(!controller.canAddButton)
                Button("Edit Filter Buttons…") {
                    controller.sheet = .manageButtons
                }
                Button("Macros…") {
                    controller.sheet = .macros
                }
                if let extensions = ExpressionLibraryMenuExtensions.installed {
                    Divider()
                    extensions()
                }
            }
            Divider()
        }
    }
}
