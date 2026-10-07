import Foundation
import Observation

// MARK: - ExpressionLibrarySheet

/// The one sheet the library can show over the workspace window at a time.
enum ExpressionLibrarySheet: Identifiable {
    /// Add (no `id`) or edit one filter button.
    case buttonEditor(FilterButton, isNew: Bool)
    case manageButtons
    case macros

    // MARK: Internal

    var id: String {
        switch self {
        case let .buttonEditor(button, _): "editor.\(button.id)"
        case .manageButtons: "buttons"
        case .macros: "macros"
        }
    }
}

// MARK: - ExpressionMacroBuiltInSource

/// Offers the current built-in macros, or `nil` when there are none to offer now
/// (nothing loaded).
@MainActor
protocol ExpressionMacroBuiltInSource: AnyObject {
    func expressionBuiltIns() -> (any ExpressionMacroBuiltIns)?
}

// MARK: - ExpressionLibraryController

/// The active Project's filter buttons and macros, the macro expansion the Session
/// Expression path runs before parsing, and the library's sheets.
///
/// Everything is keyed to the active Project: the lists are reloaded from that
/// Project's preferences suite whenever the Project changes, and any open sheet is
/// dismissed so nothing edited for one Project can be saved into another. How many
/// buttons and macros may be *added* is the coordinator's policy; lists that already
/// hold more (imported, say) are kept intact and stay editable.
@MainActor
@Observable
final class ExpressionLibraryController: SessionExpressionPreprocessor {
    // MARK: Internal

    private(set) var buttons: [FilterButton] = []
    private(set) var macros: [ExpressionMacro] = []
    var sheet: ExpressionLibrarySheet?

    /// Supplies macros the app defines itself. They expand in every Session
    /// Expression whenever the source offers them.
    @ObservationIgnored weak var builtInSource: (any ExpressionMacroBuiltInSource)? {
        didSet { attachment &+= 1 }
    }

    var barItems: [FilterButtonItem] {
        FilterButtonItem.build(buttons)
    }

    /// Buttons that may be added now: the policy's number, never above the
    /// storage ceiling.
    var buttonLimit: Int {
        _ = attachment
        return min(max(0, coordinator?.policy.maxFilterButtons ?? 0), FilterButton.maximumButtons)
    }

    /// Macros that may be added now, on the same terms as ``buttonLimit``.
    var macroLimit: Int {
        _ = attachment
        return min(max(0, coordinator?.policy.maxExpressionMacros ?? 0), ExpressionMacroValidation.maximumMacros)
    }

    var canAddButton: Bool {
        buttons.count < buttonLimit
    }

    var canAddMacro: Bool {
        macros.count < macroLimit
    }

    /// The coordinator the library serves, for extensions that act on the same
    /// Project (for example moving the library between Macs).
    var attachedCoordinator: MainContentCoordinator? {
        _ = attachment
        return coordinator
    }

    /// Limits govern growth only. A list that edits, reorders or removes entries is
    /// always admitted, even above the limit; one that adds an entry is admitted
    /// only while it stays within the limit, so removing one and adding another
    /// never grows a list that is already over it.
    nonisolated static func admits(_ updated: [UUID], replacing current: [UUID], limit: Int) -> Bool {
        let known = Set(current)
        return updated.allSatisfy(known.contains) || updated.count <= limit
    }

    func admits(buttons updated: [FilterButton]) -> Bool {
        Self.admits(updated.map(\.id), replacing: buttons.map(\.id), limit: buttonLimit)
    }

    func admits(macros updated: [ExpressionMacro]) -> Bool {
        Self.admits(updated.map(\.id), replacing: macros.map(\.id), limit: macroLimit)
    }

    /// Connects the library to the coordinator: installs macro expansion on its
    /// expression library and loads the active Project's lists.
    func attach(to coordinator: MainContentCoordinator) {
        self.coordinator = coordinator
        attachment &+= 1
        coordinator.expressionLibrary.preprocessor = self
        syncProject()
    }

    /// Reloads the lists when the active Project is not the one they came from.
    func syncProject() {
        guard let coordinator else {
            return
        }
        let projectID = coordinator.projectStore.activeProjectID
        let defaults = coordinator.activeProjectDefaults
        guard projectID != boundProjectID || defaults !== boundDefaults else {
            return
        }
        boundProjectID = projectID
        boundDefaults = defaults
        buttons = ExpressionLibraryStore.loadButtons(from: defaults)
        macros = ExpressionLibraryStore.loadMacros(from: defaults)
        sheet = nil
    }

    /// Re-reads the active Project's lists from its preferences suite, for a caller
    /// that changed them outside this controller.
    func reload() {
        boundProjectID = nil
        boundDefaults = nil
        syncProject()
    }

    // MARK: Preprocessing

    func preprocess(_ expression: String) -> Result<String, InvestigationQueryDraftError> {
        syncProject()
        return ExpressionLibraryPreprocessing.preprocess(
            expression,
            macros: macros,
            builtIns: builtInSource?.expressionBuiltIns()
        )
    }

    /// What `expression` expands to, when it uses macros and they expand.
    func expandedText(_ expression: String) -> String? {
        ExpressionLibraryPreprocessing.expandedText(
            expression,
            macros: macros,
            builtIns: builtInSource?.expressionBuiltIns()
        )
    }

    /// A problem with `expression` as a Session Expression here, or `nil`.
    func expressionProblem(_ expression: String, macros candidate: [ExpressionMacro]? = nil) -> String? {
        if let problem = ExpressionLibraryLimits.expressionProblem(expression) {
            return ExpressionLibraryLimits.message(for: problem)
        }
        let macros = candidate ?? macros
        let builtIns = builtInSource?.expressionBuiltIns()
        if ExpressionMacroExpander.mayUseMacros(expression) {
            do {
                _ = try ExpressionMacroExpander(macros: macros, builtIns: builtIns).expand(expression)
            } catch let error as ExpressionMacroError {
                return error.message
            } catch {
                return nil
            }
        }
        switch ExpressionLibraryPreprocessing.preprocess(expression, macros: macros, builtIns: builtIns) {
        case let .failure(error):
            return error.reason.displayMessage
        case let .success(text):
            do {
                _ = try InvestigationQueryDraftCompiler().compile(
                    InvestigationQueryDraft(mode: .expression, expression: text)
                )
                return nil
            } catch let error as InvestigationQueryDraftError {
                return error.reason.displayMessage
            } catch {
                return nil
            }
        }
    }

    // MARK: Applying

    /// Applies `button` exactly as typing its expression and choosing Apply would.
    /// A rejected expression opens the Session Expression editor on its error.
    func apply(_ button: FilterButton) {
        guard let coordinator else {
            return
        }
        let workspace = coordinator.activeWorkspace
        if workspace.sidebarSelection == .history {
            // History is not the capture; show the sessions the button narrows.
            workspace.sidebarSelection = .sessions
        }
        coordinator.applySessionExpression(button.expression, in: workspace)
        applyTask?.cancel()
        applyTask = Task { [weak coordinator, workspace] in
            await coordinator?.waitForInvestigationQuery(in: workspace)
            guard !Task.isCancelled, workspace.investigationQueryError != nil,
                  workspace.investigationDraft.expression == button.expression else
            {
                return
            }
            if [.overview, .flow, .history].contains(workspace.sidebarSelection) {
                workspace.sidebarSelection = .sessions
            }
            workspace.isInvestigationEditorPresented = true
        }
    }

    /// The expression the workspace is using or editing, for a new button.
    func currentExpression() -> String {
        guard let workspace = coordinator?.activeWorkspace else {
            return ""
        }
        if let accepted = workspace.acceptedInvestigationDraft, accepted.mode == .expression {
            return accepted.expression
        }
        return workspace.investigationDraft.expression.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The accepted expression's expansion, when it used macros.
    func acceptedExpansion() -> (typed: String, expanded: String)? {
        _ = attachment
        guard let accepted = coordinator?.activeWorkspace.acceptedInvestigationDraft,
              accepted.mode == .expression,
              let expanded = expandedText(accepted.expression) else
        {
            return nil
        }
        return (accepted.expression, expanded)
    }

    // MARK: Editing buttons

    func beginAddingButton() {
        syncProject()
        sheet = .buttonEditor(FilterButton(label: "", expression: currentExpression()), isNew: true)
    }

    func beginEditing(_ button: FilterButton) {
        sheet = .buttonEditor(button, isNew: false)
    }

    /// Adds or replaces `button`. Returns `false` when no more may be added.
    @discardableResult
    func commit(_ button: FilterButton) -> Bool {
        var updated = buttons
        if let index = updated.firstIndex(where: { $0.id == button.id }) {
            updated[index] = button
        } else {
            guard canAddButton else {
                return false
            }
            updated.append(button)
        }
        setButtons(updated)
        return true
    }

    func delete(_ button: FilterButton) {
        setButtons(buttons.filter { $0.id != button.id })
    }

    func move(_ button: FilterButton, by offset: Int) {
        guard let index = buttons.firstIndex(where: { $0.id == button.id }) else {
            return
        }
        let target = index + offset
        guard buttons.indices.contains(target) else {
            return
        }
        var updated = buttons
        updated.swapAt(index, target)
        setButtons(updated)
    }

    func canMove(_ button: FilterButton, by offset: Int) -> Bool {
        guard let index = buttons.firstIndex(where: { $0.id == button.id }) else {
            return false
        }
        return buttons.indices.contains(index + offset)
    }

    func setButtons(_ updated: [FilterButton]) {
        buttons = Array(updated.prefix(FilterButton.maximumButtons))
        if let boundDefaults {
            ExpressionLibraryStore.save(buttons, to: boundDefaults)
        }
    }

    func setMacros(_ updated: [ExpressionMacro]) {
        macros = Array(updated.prefix(ExpressionMacroValidation.maximumMacros))
        if let boundDefaults {
            ExpressionLibraryStore.save(macros, to: boundDefaults)
        }
    }

    // MARK: Private

    @ObservationIgnored private weak var coordinator: MainContentCoordinator?
    /// Observed stand-in for the unobserved coordinator reference: views and menu
    /// commands that read a limit before ``attach(to:)`` render again once it is
    /// connected (the policy itself is observed through the coordinator).
    private var attachment = 0
    @ObservationIgnored private var boundProjectID: UUID?
    @ObservationIgnored private weak var boundDefaults: UserDefaults?
    @ObservationIgnored private var applyTask: Task<Void, Never>?
}

// MARK: - InvestigationQueryDraftError.Reason + displayMessage

extension InvestigationQueryDraftError.Reason {
    /// The same wording the Session Expression editor shows.
    var displayMessage: String {
        switch self {
        case let .expression(error): error.message
        case let .core(error): error.message
        default: String(localized: "This isn’t a valid Session Expression.")
        }
    }
}
