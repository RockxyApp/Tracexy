import AppKit
import Foundation
import UniformTypeIdentifiers

// MARK: - Configuration-only Project transfer

extension MainContentCoordinator {
    @discardableResult
    func exportProjectConfiguration(_ project: Project) -> Bool {
        guard projectStore.isMutable,
              projectStore.projects.contains(where: { $0.id == project.id }) else
        {
            lastProjectOperationError = .storeNotReady
            return false
        }
        if project.id == projectStore.activeProjectID, !flushProjectWorkspaceSnapshot() {
            return false
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [Self.projectDocumentType]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "\(safeProjectFileStem(project.name)).\(PortableProjectCodec.fileExtension)"
        panel.message = String(
            localized: "Exports workspace names, filters, grouping, and layout only. Captured traffic and History are excluded."
        ) + " " + String(
            localized: "Filter text may be sensitive; review it before sharing."
        )
        guard panel.runModal() == .OK, let url = panel.url else {
            return false
        }

        do {
            guard let currentProject = projectStore.projects.first(where: { $0.id == project.id }) else {
                lastProjectOperationError = .projectNotFound
                return false
            }
            try PortableProjectDocumentIO.write(currentProject, to: url)
            lastProjectOperationError = nil
            projectTransferErrorMessage = nil
            return true
        } catch {
            projectTransferErrorMessage = projectTransferFailureMessage(for: error)
            return false
        }
    }

    @discardableResult
    func importProjectConfiguration() -> Bool {
        guard projectStore.canCreateProject else {
            lastProjectOperationError = projectStore.isMutable
                ? .capacityReached(limit: projectStore.maxProjects)
                : .storeNotReady
            return false
        }

        let panel = NSOpenPanel()
        panel.allowedContentTypes = [Self.projectDocumentType, .json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = String(localized: "Choose a configuration-only .tracexyproject file")
        guard panel.runModal() == .OK, let url = panel.url else {
            return false
        }

        do {
            let importedConfiguration = try PortableProjectDocumentIO.read(from: url)
            guard confirmProjectImport(importedConfiguration, fileName: url.lastPathComponent) else {
                return false
            }
            guard flushProjectWorkspaceSnapshot() else {
                return false
            }
            let importedProject = try projectStore.importProject(importedConfiguration)
            activateCurrentProjectWorkspaces()
            lastProjectOperationError = nil
            projectTransferErrorMessage = nil
            return importedProject.id == projectStore.activeProjectID
        } catch let error as ProjectMutationError {
            lastProjectOperationError = error
            return false
        } catch {
            projectTransferErrorMessage = projectTransferFailureMessage(for: error)
            return false
        }
    }

    // MARK: Private

    private static var projectDocumentType: UTType {
        UTType(
            exportedAs: TracexyIdentity.current.projectUTTypeIdentifier,
            conformingTo: .json
        )
    }

    private func confirmProjectImport(_ project: Project, fileName: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = String(localized: "Import \(project.name) as a New Project?")
        alert.informativeText = String(
            localized: "\(fileName) contains \(project.workspaces.count) workspace(s), user-authored filter text, and layout preferences. It contains no captured traffic, payloads, local file paths, findings, or History. Existing Projects will not be replaced."
        )
        alert.alertStyle = .informational
        alert.addButton(withTitle: String(localized: "Import"))
        alert.addButton(withTitle: String(localized: "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func safeProjectFileStem(_ name: String) -> String {
        let invalid = CharacterSet(charactersIn: "/:")
        let components = name.components(separatedBy: invalid).filter { !$0.isEmpty }
        let stem = components.joined(separator: "-").trimmingCharacters(in: .whitespacesAndNewlines)
        return stem.isEmpty ? "Tracexy-Project" : stem
    }

    private func projectTransferFailureMessage(for error: Error) -> String {
        switch error {
        case PortableProjectCodecError.documentTooLarge:
            "The Project file is too large for a configuration-only document."
        case PortableProjectCodecError.unsupportedSchema:
            "This Project file uses a newer or unsupported format."
        case PortableProjectCodecError.documentIsSymbolicLink,
             PortableProjectCodecError.directoryIsSymbolicLink:
            "Tracexy will not import from or export through a symbolic link."
        case PortableProjectCodecError.documentIsNotRegularFile,
             PortableProjectCodecError.directoryIsNotDirectory:
            "Choose a regular Project file in a normal folder."
        default:
            "The Project configuration could not be processed safely. Verify the file and try again."
        }
    }
}
