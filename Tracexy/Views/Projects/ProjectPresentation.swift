import AppKit
import SwiftUI

// MARK: - ProjectToolbarSelectorMetrics

enum ProjectToolbarSelectorMetrics {
    static let minimumWidth: CGFloat = 104
    static let maximumWidth: CGFloat = 240
    static let nonTextWidth: CGFloat = 64

    static func preferredWidth(
        for projectName: String,
        font: NSFont = .systemFont(ofSize: NSFont.systemFontSize)
    )
        -> CGFloat
    {
        let textWidth = ceil((projectName as NSString).size(withAttributes: [.font: font]).width)
        return min(maximumWidth, max(minimumWidth, textWidth + nonTextWidth))
    }
}

// MARK: - ProjectToolbarSelectorView

struct ProjectToolbarSelectorView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Menu {
            ForEach(coordinator.projectStore.projects) { project in
                Button {
                    coordinator.switchToProject(id: project.id)
                } label: {
                    if project.id == coordinator.projectStore.activeProjectID {
                        Label(project.name, systemImage: "checkmark")
                    } else {
                        Text(project.name)
                    }
                }
                .disabled(!coordinator.projectStore.isMutable)
            }

            Divider()

            Button("New Project…") {
                coordinator.presentNewProjectEditor()
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
            .disabled(!coordinator.projectStore.canCreateProject)

            Button("Rename Project…") {
                coordinator.presentRenameProjectEditor(id: coordinator.projectStore.activeProjectID)
            }
            .disabled(!coordinator.projectStore.isMutable)

            Button("Manage Projects…") {
                coordinator.isProjectManagerPresented = true
            }

            if case .failed = coordinator.projectStore.loadState {
                Divider()
                Button("Repair Projects…") {
                    coordinator.isProjectRecoveryPresented = true
                }
            }
        } label: {
            HStack(spacing: Theme.Metrics.controlSpacing) {
                Image(systemName: projectStatusSymbol)
                    .foregroundStyle(projectStatusColor)
                Text(coordinator.projectStore.activeProject.name)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .layoutPriority(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .contentShape(.rect)
        }
        .menuIndicator(.visible)
        .menuStyle(.borderlessButton)
        .frame(width: preferredWidth, alignment: .leading)
        .fixedSize(horizontal: true, vertical: false)
        .help("Active Project: \(coordinator.projectStore.activeProject.name)")
        .accessibilityLabel("Active Project")
        .accessibilityValue(coordinator.projectStore.activeProject.name)
    }

    // MARK: Private

    private var preferredWidth: CGFloat {
        ProjectToolbarSelectorMetrics.preferredWidth(for: coordinator.projectStore.activeProject.name)
    }

    private var projectStatusSymbol: String {
        switch coordinator.projectStore.loadState {
        case .failed: "folder.badge.questionmark"
        case .loading: "folder"
        case .idle,
             .ready: "folder.fill"
        }
    }

    private var projectStatusColor: Color {
        if case .failed = coordinator.projectStore.loadState {
            return .orange
        }
        return .accentColor
    }
}

// MARK: - ProjectNameEditorSheet

struct ProjectNameEditorSheet: View {
    // MARK: Lifecycle

    init(context: ProjectNameEditorContext, coordinator: MainContentCoordinator) {
        self.context = context
        self.coordinator = coordinator
        _name = State(initialValue: context.initialName)
    }

    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    let context: ProjectNameEditorContext

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: Theme.Metrics.spacingL) {
                Image(systemName: "folder.fill")
                    .font(.system(size: Theme.Icon.xlarge))
                    .foregroundStyle(Color.accentColor)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(context.title)
                        .font(Theme.Typography.surfaceTitle)
                    Text("Projects keep workspace filters and layout together.")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(18)

            Divider()

            VStack(alignment: .leading, spacing: Theme.Metrics.controlSpacing) {
                Text("Project Name")
                    .font(Theme.Typography.bodyMedium)
                TextField("For example: Authentication Review", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: name) { _, _ in operationErrorMessage = nil }
                Text(editorMessage)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(hasEditorError ? Color.orange : Color.secondary)
            }
            .padding(18)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(context.actionTitle) { submit() }
                    .keyboardShortcut(.defaultAction)
                    .tracexyGlassButtonStyle(prominent: true)
                    .disabled(validationMessage != nil)
            }
            .padding(.horizontal, 18)
            .frame(height: 52)
        }
        .frame(width: 460)
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var operationErrorMessage: String?

    private var normalizedName: String? {
        try? ProjectNameNormalization.normalize(name)
    }

    private var validationMessage: String? {
        guard let normalizedName else {
            return "Enter a name without control or invisible formatting characters."
        }
        let key = ProjectNameNormalization.uniquenessKey(normalizedName)
        let excludedID: UUID? = switch context.mode {
        case .create: nil
        case let .rename(id): id
        }
        if coordinator.projectStore.projects.contains(where: {
            $0.id != excludedID && ProjectNameNormalization.uniquenessKey($0.name) == key
        }) {
            return "A Project with this name already exists."
        }
        return nil
    }

    private var editorMessage: String {
        validationMessage ?? operationErrorMessage
            ?? "1–\(ProjectLimits.maximumNameLength) characters. Names must be unique."
    }

    private var hasEditorError: Bool {
        validationMessage != nil || operationErrorMessage != nil
    }

    private func submit() {
        guard let normalizedName else {
            return
        }
        let succeeded: Bool = switch context.mode {
        case .create: coordinator.createProject(named: normalizedName) != nil
        case let .rename(id): coordinator.renameProject(id: id, to: normalizedName)
        }
        guard succeeded else {
            operationErrorMessage = coordinator.projectOperationErrorMessage
                ?? "The Project could not be updated. Try again."
            return
        }
        dismiss()
    }
}

// MARK: - ProjectManagerSheet

struct ProjectManagerSheet: View {
    // MARK: Lifecycle

    init(coordinator: MainContentCoordinator) {
        self.coordinator = coordinator
        _selection = State(initialValue: coordinator.projectStore.activeProjectID)
    }

    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                projectSidebar
                    .frame(minWidth: 230, idealWidth: 250, maxWidth: 300)
                detail
                    .frame(minWidth: 430, maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            actionBar
        }
        .font(Theme.Typography.body)
        .frame(minWidth: 720, idealWidth: 780, minHeight: 500, idealHeight: 540)
        .confirmationDialog(
            "Delete Project?",
            isPresented: deleteConfirmation,
            titleVisibility: .visible,
            presenting: coordinator.projectDeletionRequest
        ) { request in
            Button("Delete \(request.projectName)", role: .destructive) {
                if coordinator.deleteProject(id: request.projectID) {
                    selection = coordinator.projectStore.activeProjectID
                }
                coordinator.projectDeletionRequest = nil
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text(
                "This removes the Project and its saved workspace configuration. "
                    + "Current capture data, saved captures, and History are not deleted."
            )
        }
        .sheet(item: $coordinator.projectNameEditorContext) { context in
            ProjectNameEditorSheet(context: context, coordinator: coordinator)
        }
        .onChange(of: coordinator.projectStore.activeProjectID) { _, activeProjectID in
            selection = activeProjectID
        }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var selection: UUID?

    private var selectedProject: Project? {
        coordinator.projectStore.projects.first { $0.id == selection }
    }

    private var canDeleteSelectedProject: Bool {
        coordinator.projectStore.isMutable
            && selectedProject != nil
            && coordinator.projectStore.projects.count > 1
    }

    private var deleteConfirmation: Binding<Bool> {
        Binding(
            get: { coordinator.projectDeletionRequest != nil },
            set: {
                if !$0 {
                    coordinator.projectDeletionRequest = nil
                }
            }
        )
    }

    private var projectSidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Projects")
                    .font(Theme.Typography.surfaceTitle)
                Text("Organize durable workspace views for different investigations.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingL)

            Divider()

            List(selection: $selection) {
                ForEach(coordinator.projectStore.projects) { project in
                    HStack(spacing: Theme.Metrics.spacingM) {
                        Image(systemName: project.id == coordinator.projectStore.activeProjectID
                            ? "folder.fill" : "folder")
                            .foregroundStyle(selection == project.id ? Color.primary : Color.secondary)
                            .frame(width: 16)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(project.name).lineLimit(1).truncationMode(.middle)
                            Text(workspaceCountText(project.workspaces.count))
                                .font(Theme.Typography.micro)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 4)
                        if project.id == coordinator.projectStore.activeProjectID {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: Theme.Icon.medium))
                                .foregroundStyle(selection == project.id ? Color.primary : Color.accentColor)
                                .help("Active Project")
                        }
                    }
                    .tag(project.id)
                    .padding(.vertical, 2)
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel(project.name)
                    .accessibilityValue(project.id == coordinator.projectStore.activeProjectID
                        ? "\(workspaceCountText(project.workspaces.count)), Active Project"
                        : workspaceCountText(project.workspaces.count))
                }
            }
            .listStyle(.sidebar)

            Divider()

            HStack(spacing: Theme.Metrics.controlSpacing) {
                addRemoveControl
                Spacer()
                Text("\(coordinator.projectStore.projects.count)/\(coordinator.projectStore.maxProjects)")
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Project capacity")
            }
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingM)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    @ViewBuilder private var detail: some View {
        if let project = selectedProject {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .center, spacing: Theme.Metrics.controlSpacing) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(project.name)
                            .font(Theme.Typography.surfaceTitle)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text(project.id == coordinator.projectStore.activeProjectID
                            ? "Active Project" : "Local Project")
                            .font(Theme.Typography.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if project.id != coordinator.projectStore.activeProjectID {
                        Button("Open Project") {
                            if coordinator.switchToProject(id: project.id) {
                                selection = project.id
                            }
                        }
                        .disabled(!coordinator.projectStore.isMutable)
                    }
                    Button("Rename…") {
                        coordinator.presentRenameProjectEditor(id: project.id)
                    }
                    .disabled(!coordinator.projectStore.isMutable)
                }
                .padding(Theme.Metrics.spacingL)

                Divider()

                VStack(alignment: .leading, spacing: Theme.Metrics.controlSpacing) {
                    HStack {
                        Text("Workspaces").font(Theme.Typography.bodyMedium)
                        Spacer()
                        Text(workspaceCountText(project.workspaces.count))
                            .font(Theme.Typography.monoMicro)
                            .foregroundStyle(.secondary)
                    }

                    List {
                        ForEach(project.workspaces) { workspace in
                            HStack(spacing: Theme.Metrics.spacingM) {
                                Image(systemName: workspace.isClosable ? "rectangle" : "rectangle.fill")
                                    .foregroundStyle(.secondary)
                                    .frame(width: 16)
                                Text(workspace.title).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                if workspace.id == project.activeWorkspaceID {
                                    Label("Current", systemImage: "checkmark")
                                        .font(Theme.Typography.micro)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .frame(minHeight: Theme.Metrics.rowHeight)
                        }
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                    .scrollContentBackground(.hidden)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
                    .overlay {
                        RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius)
                            .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                    }
                }
                .padding(Theme.Metrics.spacingL)
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                Divider()
                Label(
                    "Projects save workspace names, filters, grouping, and layout. Capture data and History remain app-wide.",
                    systemImage: "info.circle"
                )
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Theme.Metrics.spacingL)
                .background(Color(nsColor: .controlBackgroundColor).opacity(0.5))
            }
        } else {
            ContentUnavailableView(
                "Select a Project",
                systemImage: "folder",
                description: Text("Choose a Project to view its saved workspaces.")
            )
        }
    }

    private var addRemoveControl: some View {
        HStack(spacing: 0) {
            Button {
                coordinator.presentNewProjectEditor()
            } label: {
                Image(systemName: "plus")
                    .frame(width: 22, height: 22)
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .keyboardShortcut("n", modifiers: [.command, .shift])
            .help("New Project")
            .disabled(!coordinator.projectStore.canCreateProject)

            Rectangle()
                .fill(Color(nsColor: .separatorColor).opacity(0.7))
                .frame(width: 1, height: 18)

            Button {
                if let selectedProject {
                    coordinator.requestProjectDeletion(selectedProject)
                }
            } label: {
                Image(systemName: "minus")
                    .frame(width: 22, height: 22)
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .help("Delete Project")
            .disabled(!canDeleteSelectedProject)
        }
        .padding(.horizontal, 3)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
        .overlay {
            RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private var actionBar: some View {
        HStack(spacing: Theme.Metrics.controlSpacing) {
            if let warning = coordinator.projectPersistenceWarningMessage {
                Label(warning, systemImage: "exclamationmark.triangle.fill")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
            } else {
                Text("Projects are stored locally on this Mac.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Import…") { coordinator.importProjectConfiguration() }
                .disabled(!coordinator.projectStore.canCreateProject)
            Button("Export…") {
                if let selectedProject {
                    coordinator.exportProjectConfiguration(selectedProject)
                }
            }
            .disabled(selectedProject == nil || !coordinator.projectStore.isMutable)
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .tracexyGlassButtonStyle()
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
        .frame(minHeight: 48)
    }

    private func workspaceCountText(_ count: Int) -> String {
        count == 1 ? "1 Workspace" : "\(count) Workspaces"
    }
}

// MARK: - ProjectRecoverySheet

struct ProjectRecoverySheet: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: Theme.Metrics.spacingL) {
                Image(systemName: "folder.badge.questionmark")
                    .font(.system(size: Theme.Icon.xlarge))
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Repair Projects")
                        .font(Theme.Typography.surfaceTitle)
                    Text("The Project catalog could not be loaded safely.")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(18)

            Divider()

            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                Text(
                    "Tracexy will not overwrite an unreadable catalog. Retry after fixing the file, "
                        + "or reset Projects to a new default catalog. Capture and History are unaffected."
                )
                .fixedSize(horizontal: false, vertical: true)

                Text(coordinator.projectStore.loadFailureMessage ?? "Unknown Project catalog error")
                    .font(Theme.Typography.monoSmall)
                    .textSelection(.enabled)
                    .padding(Theme.Metrics.spacingM)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: Theme.Metrics.pillCornerRadius))
            }
            .padding(18)

            Divider()

            HStack {
                Button("Reset…", role: .destructive) { showsResetConfirmation = true }
                Spacer()
                Button("Close", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Retry") { Task { await coordinator.retryProjectCatalogLoad() } }
                    .keyboardShortcut(.defaultAction)
                    .tracexyGlassButtonStyle(prominent: true)
            }
            .padding(.horizontal, 18)
            .frame(height: 52)
        }
        .frame(width: 540)
        .confirmationDialog(
            "Reset Projects?",
            isPresented: $showsResetConfirmation,
            titleVisibility: .visible
        ) {
            Button("Reset Project Catalog", role: .destructive) {
                Task { await coordinator.resetProjectCatalog() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This replaces Project names and saved workspace configuration. "
                    + "Current capture data, saved captures, and History are not deleted."
            )
        }
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var showsResetConfirmation = false
}
