import Foundation

// MARK: - ProjectNameEditorContext

struct ProjectNameEditorContext: Identifiable, Equatable {
    enum Mode: Equatable {
        case create
        case rename(UUID)
    }

    let id = UUID()
    let mode: Mode
    let initialName: String

    var title: String {
        switch mode {
        case .create: String(localized: "New Project")
        case .rename: String(localized: "Rename Project")
        }
    }

    var actionTitle: String {
        switch mode {
        case .create: String(localized: "Create")
        case .rename: String(localized: "Rename")
        }
    }
}

// MARK: - ProjectDeletionRequest

struct ProjectDeletionRequest: Identifiable, Equatable {
    let projectID: UUID
    let projectName: String

    var id: UUID {
        projectID
    }
}
