import Foundation
import Testing
@testable import Tracexy

@Suite("Workspace presentation contract")
struct WorkspacePresentationContractTests {
    // MARK: Internal

    @Test("Project changes remount native layout and scoped editors without remounting launch setup")
    func projectPresentationIdentity() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let manager = try readProjectFile("Tracexy/Views/Projects/ProjectPresentation.swift")
        #expect(root.contains("return ZStack {"))
        #expect(root.contains(".id(activeProjectID)"))
        #expect(root.contains("isSidebarPresented: sidebarVisibility"))
        #expect(root.contains("coordinator.startGeneration == launchGeneration"))
        #expect(app.contains(".defaultAppStorage(coordinator.activeProjectDefaults)"))
        #expect(app.components(separatedBy: ".id(coordinator.projectStore.activeProjectID)").count == 5)
        #expect(root.contains("ProjectTransitionPresentation("))
        #expect(manager.contains("ProjectTransitionPresentation("))
        #expect(manager.contains("unsaved in-memory sessions and evidence"))
    }

    @Test("Synthetic Project composition isolates storage roots and application settings")
    func demoProjectCompositionIsIsolated() throws {
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let settings = try readProjectFile("Tracexy/Views/Settings/SettingsView.swift")
        #expect(app.contains("applicationSupportRoot: demoRoot.appendingPathComponent"))
        #expect(app.contains("cacheRoot: demoRoot.appendingPathComponent"))
        #expect(app.contains("applicationDefaults: Self.applicationDefaults"))
        #expect(settings.contains("GeneralSettingsView(applicationDefaults: applicationDefaults)"))
        #expect(settings.contains("applicationDefaults: applicationDefaults,"))
    }

    @Test("Monitor navigation is exactly Overview, Sessions, Flow Map, History, in that order")
    func monitorOrder() {
        #expect(SidebarSection.monitor.items == [.overview, .sessions, .flow, .history])
    }

    @Test("Toolbar update badge keeps the approved capsule geometry")
    func updateBadgeMetrics() {
        #expect(Theme.Metrics.toolbarControlHeight == 32)
        #expect(Theme.Metrics.updateBadgeHeight == 24)
        #expect(Theme.Metrics.updateBadgeHorizontalPadding == 9)
        #expect(Theme.Metrics.updateBadgeStrokeWidth == 0.75)
    }

    @Test("Overview stays inside the workspace when the native sidebar is open")
    func overviewUsesTheWorkspaceViewport() throws {
        let source = try readProjectFile("Tracexy/Views/Overview/OverviewView.swift")

        #expect(source.contains("GeometryReader { proxy in"))
        #expect(source.contains("proxy.size.width >= Self.wideDashboardMinimumWidth"))
        #expect(source.contains("proxy.size.width - Theme.Metrics.spacingL * 2"))
    }

    @Test("Overview summarizes findings and leaves evidence to Sessions")
    func overviewDoesNotDuplicateTheFindingList() throws {
        let source = try readProjectFile("Tracexy/Views/Overview/OverviewView.swift")

        #expect(source.contains("findingSummaryBar"))
        #expect(source.contains("Review \\(all.count.formatted()) in Sessions"))
        #expect(!source.contains("findingPreviewLimit"))
        #expect(!source.contains("findingRow("))
        #expect(!source.contains("Open evidence"))
    }

    @Test("Details uses stacked inspector tables instead of List sections")
    func detailsUsesInspectorTables() throws {
        let details = try readProjectFile("Tracexy/Views/Inspector/ContextDockView.swift")
        let table = try readProjectFile("Tracexy/Views/Inspector/ContextInspectorTable.swift")

        #expect(details.contains("ScrollView {"))
        #expect(details.contains("ContextInspectorTable(title: \"Assessment\")"))
        #expect(details.contains("ContextInspectorFieldTable("))
        #expect(!details.contains("List {"))
        #expect(!details.contains(".listStyle"))

        #expect(table.contains(".tracexyContentSurface("))
        #expect(!table.contains("Color(nsColor: .textBackgroundColor)"))
        #expect(table.contains("struct ContextInspectorFieldRow"))
        #expect(table.contains("struct ContextInspectorInsightRow"))
        #expect(table.contains("struct ContextInspectorFullRow"))
    }

    @Test("Connection and TLS navigation keeps literal evidence below and compact context at right")
    func evidenceNavigationKeepsInspectorOwnership() throws {
        let inspector = try readProjectFile("Tracexy/Views/Inspector/InspectorView.swift")
        let timeline = try readProjectFile("Tracexy/Views/Inspector/SessionEvidenceTimelineView.swift")
        let details = try readProjectFile("Tracexy/Views/Inspector/ContextDockView.swift")
        let summary = try readProjectFile("Tracexy/Views/Inspector/SessionEvidenceContextSummaryView.swift")

        #expect(inspector.contains("case .evidence: sessionEvidence(session)"))
        #expect(inspector.contains("Cited frame"))
        #expect(inspector.contains("coordinator.cancelCitedFrame()"))
        #expect(timeline.contains("Capture-level:"))
        #expect(timeline.contains("No replacement frame was loaded"))
        #expect(details.contains("SessionEvidenceContextSummaryView"))
        #expect(summary.contains("Button(\"Open Evidence\")"))
        #expect(!summary.contains("SessionEvidenceItem.timeline"))
    }

    @Test("Layers keeps decode filtering compact when a cited-frame scope is visible")
    func citedLayersKeepVerticalViewport() throws {
        let inspector = try readProjectFile("Tracexy/Views/Inspector/InspectorView.swift")
        let facets = try readProjectFile("Tracexy/Views/Inspector/InspectorFacetBar.swift")

        #expect(inspector.contains("private var layerFilterControl: some View"))
        #expect(facets.contains("if activeTab == .layers"))
        #expect(inspector.contains(".frame(minWidth: 180, idealWidth: 240, maxWidth: 280)"))
        #expect(inspector.contains(".accessibilityLabel(\"Filter decoded fields\")"))
        #expect(inspector.contains("InspectorFacetBar("))
        #expect(facets.contains("private func tabTier("))
        #expect(facets.contains("private func directlyVisibleTabs("))
        #expect(facets.contains("ViewThatFits(in: .horizontal)"))
        #expect(facets.contains(".fixedSize(horizontal: true, vertical: false)"))
        #expect(facets.contains(".frame(maxWidth: .infinity, alignment: .leading)"))
        #expect(facets.contains("Spacer(minLength: Theme.Metrics.spacingM)"))
        #expect(inspector.contains("private func activityScopeBadge("))
        #expect(!inspector.contains("ScrollView(.horizontal, showsIndicators: false)"))
        #expect(!inspector.contains("scopeLabel("))
        #expect(!facets.contains("private func tabButtons("))
        #expect(inspector.contains("private func inspectorChrome("))
        #expect(inspector.contains("the decode and hex panes begin strictly below it"))
        #expect(inspector.contains(".background(Color(nsColor: .windowBackgroundColor))"))
        #expect(!inspector.contains(".tracexySafeAreaBar(edge: .top)"))
        #expect(!inspector.contains("fieldFilterRow"))
        #expect(!inspector.contains("supportsFieldFilter"))
    }

    @Test("Shared workspace chrome adopts the Liquid Glass policy without replacing native data controls")
    func workspaceUsesSharedGlassPolicy() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let commandBar = try readProjectFile("Tracexy/Views/Sessions/SessionCommandBar.swift")
        let filters = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")
        let structuredFilters = try readProjectFile("Tracexy/Views/Sessions/StructuredFilterBar.swift")
        let sessions = try readProjectFile("Tracexy/Views/Sessions/SessionCenterView.swift")
        let footer = try readProjectFile("Tracexy/Views/Common/WorkspaceFooterBar.swift")

        #expect(root.contains("commandDescriptors: sessionCommandDescriptors(workspace)"))
        #expect(root.contains("onCommandAction: { performSessionCommand($0, workspace) }"))
        #expect(!commandBar.contains("TracexyGlassEffectGroup"))
        #expect(!commandBar.contains(".tracexyGlassEffect"))
        #expect(commandBar.contains(".tracexyGlassButtonStyle()"))
        #expect(commandBar.contains(".font(.system(size: Theme.Icon.medium, weight: .medium))"))
        #expect(commandBar.contains("Theme.Metrics.sessionShelfControlLength"))
        #expect(!commandBar.contains(".tracexyFunctionalBar()"))
        #expect(filters.contains("TracexyGlassEffectGroup"))
        #expect(filters.contains(".tracexyGlassEffect(in: shape)"))
        #expect(filters.contains("SessionCommandBar("))
        #expect(filters.contains("private func commandAndSearchRow("))
        #expect(filters.contains("Theme.Glass.sessionShelfCornerRadius"))
        #expect(filters.contains("Theme.Glass.sessionShelfSectionSpacing"))
        #expect(filters.contains("Theme.Glass.sessionShelfOuterPadding"))
        #expect(filters.contains(".tracexyGlassButtonStyle()"))
        #expect(filters.contains("StructuredFilterBar(coordinator: coordinator)"))
        #expect(filters.contains(".transition(.move(edge: .top).combined(with: .opacity))"))
        #expect(!filters.contains(".tracexyFunctionalBar()"))
        #expect(structuredFilters.contains("ViewThatFits(in: .horizontal)"))
        #expect(structuredFilters.contains(".tracexyGlassButtonStyle()"))
        #expect(structuredFilters.contains(".disabled(workspace.filterRules.count <= 1)"))
        #expect(structuredFilters.contains("workspace.filterRules.count >= maxRules"))
        #expect(structuredFilters.contains("Text(\"Presets\")"))
        #expect(!structuredFilters.contains("Label(\"Presets\", systemImage: \"chevron.down\")"))
        #expect(!structuredFilters.contains(".tracexyContentSurface("))
        #expect(!sessions.contains("StructuredFilterBar(coordinator: coordinator)"))
        #expect(footer.contains(".tracexyGlassEffect("))
        #expect(sessions.contains("Table("))
        #expect(!sessions.contains("LazyVGrid"))
    }

    @Test("Glass bars never contain a second glass button layer")
    func glassHierarchyHasOneFunctionalLayer() throws {
        for (path, source) in try productionViewSources()
            where source.contains(".tracexyFunctionalBar()")
        {
            #expect(
                !source.contains(".tracexyGlassButtonStyle("),
                "\(path) must choose one glass parent or glass controls, never both"
            )
        }
    }

    @Test("Production views use the shared typography scale for visible text")
    func productionTextUsesSharedTypography() throws {
        for (path, source) in try productionViewSources() {
            for (offset, line) in source.split(separator: "\n", omittingEmptySubsequences: false).enumerated()
                where line.contains(".font(")
            {
                let isSharedTextRole = line.contains("Theme.Typography")
                    || line.contains("metrics.")
                let isSharedIconRole = line.contains(".font(.system(size: Theme.Icon")
                let isAppIconMonogram = path.hasSuffix("Sidebar/AppIconView.swift")
                    && line.contains(".font(.system(size: max(")
                #expect(
                    isSharedTextRole || isSharedIconRole || isAppIconMonogram,
                    "\(path):\(offset + 1) bypasses the shared type or icon scale"
                )
            }
        }
    }

    @Test("Every workspace edge uses semantic safe-area chrome")
    func workspaceEdgesUseSafeAreaChrome() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let details = try readProjectFile("Tracexy/Views/Inspector/ContextDockView.swift")
        let evidence = try readProjectFile("Tracexy/Views/Inspector/InspectorView.swift")
        let sessions = try readProjectFile("Tracexy/Views/Sessions/SessionCenterView.swift")

        #expect(!root.contains(".tracexySafeAreaBar(edge: .top)"))
        #expect(root.contains(".tracexySafeAreaBar(edge: .bottom)"))
        #expect(sidebar.contains(".tracexySafeAreaBar(edge: .top)"))
        #expect(sidebar.contains(".tracexySafeAreaBar(edge: .bottom)"))
        #expect(details.contains(".tracexySafeAreaBar(edge: .top)"))
        #expect(details.contains(".tracexySafeAreaBar(edge: .bottom)"))
        #expect(evidence.contains("private func inspectorChrome("))
        #expect(!evidence.contains(".tracexySafeAreaBar(edge: .top)"))
        #expect(sessions.contains(".tracexySafeAreaBar(edge: .top)"))
    }

    @Test("Navigation and Settings retain native split semantics")
    func navigationUsesNativeSplitSemantics() throws {
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let settings = try readProjectFile("Tracexy/Views/Settings/SettingsView.swift")

        #expect(app.contains(".windowToolbarStyle(.unified)"))
        #expect(app.contains(".windowStyle(.hiddenTitleBar)"))
        #expect(sidebar.contains(".listStyle(.sidebar)"))
        #expect(sidebar.contains("WorkspaceModeSegmentedControl("))
        #expect(settings.contains("NavigationSplitView"))
        #expect(settings.contains(".listStyle(.sidebar)"))
        #expect(!settings.contains("TabView(selection:"))
    }

    @Test("Main toolbar separates Project context from capture controls")
    func mainToolbarOwnsWorkspaceContext() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let chrome = try readProjectFile("Tracexy/Views/Common/NativeWorkspaceWindowChrome.swift")

        #expect(!root.contains(".navigationTitle("))
        #expect(!root.contains(".navigationSubtitle("))
        #expect(chrome.contains("window.title = TracexyIdentity.current.displayName"))
        #expect(chrome.contains("window.titleVisibility = .hidden"))
        #expect(chrome.contains(
            "Self.sidebarTrackingSeparatorIdentifier,\n            Self.projectSelectorIdentifier,\n            .flexibleSpace"
        ))
        #expect(chrome.contains(
            "Self.interfacePickerIdentifier,\n            Self.captureSeparatorIdentifier,\n            Self.captureActionIdentifier,\n            .space"
        ))
    }

    @Test("Capture status uses the native toolbar as its only visible surface")
    func captureStatusUsesSingleNativeSurface() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")

        #expect(root.contains("struct CaptureStatusView: View"))
        #expect(root.contains("showsReadiness.toggle()"))
        #expect(root.contains(".contentShape(Capsule(style: .continuous))"))
        #expect(root.contains(".popover(isPresented: $showsReadiness"))
        #expect(root.contains(".help(statusHelp)"))
        #expect(root.contains(".accessibilityLabel(\"Capture Readiness\")"))
        #expect(root.contains(".accessibilityValue(statusText)"))
        #expect(!root.contains(".tracexyGlassEffect(interactive: true, in: Capsule(style: .continuous))"))
    }

    @Test("Session search keeps the native control rhythm with Tracexy field semantics")
    func sessionSearchUsesResponsiveNativeControls() throws {
        let source = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")

        #expect(source.contains("ViewThatFits(in: .horizontal)"))
        #expect(source.contains("private func commandAndSearchRow("))
        #expect(source.contains("SessionCommandBar("))
        #expect(source.contains("Theme.Glass.sessionShelfCornerRadius"))
        #expect(source.contains("Theme.Glass.sessionShelfOuterPadding"))
        #expect(source.contains("pickerWidth: 130, showsAddFieldTitle: true"))
        #expect(source.contains("pickerWidth: 100, showsAddFieldTitle: false"))
        #expect(source.contains(".frame(minWidth: 220, maxWidth: .infinity)"))
        #expect(source.contains("Label(\"Add Field\", systemImage: \"plus\")"))
        #expect(source.contains(".accessibilityLabel(\"Search field\")"))
        #expect(source.contains(".accessibilityLabel(\"Add field\")"))
        #expect(source.contains("categoryTier(workspace, visibleProtocolCount:"))
        #expect(source.contains(".frame(maxWidth: .infinity, alignment: .leading)"))
        #expect(source.contains("Spacer(minLength: Theme.Metrics.spacingM)"))
        #expect(source.contains("\"ellipsis.circle.fill\""))
        #expect(source.contains(".accessibilityLabel(\"More session filters\")"))
        #expect(!source.contains("ScrollView(.horizontal, showsIndicators: false)"))
    }

    @Test("The evidence inspector exposes selected identity, segmented footer and an auxiliary window")
    func evidenceInspectorUsesApprovedRegionsWithoutInventingURLs() throws {
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let inspector = try readProjectFile("Tracexy/Views/Inspector/InspectorView.swift")

        #expect(inspector.contains("private func sessionIdentityBar("))
        #expect(inspector.contains("private func activityScopeBadge("))
        #expect(inspector.contains("Label(\"Whole action\", systemImage: \"rectangle.3.group\")"))
        #expect(inspector.contains("session.sourceEndpoint) → \\(session.destinationEndpoint"))
        #expect(inspector.contains("private func inspectorFooter("))
        #expect(inspector.contains(".frame(maxWidth: .infinity, alignment: .leading)"))
        #expect(inspector.contains("WorkspaceFooterBar(surface: .workspace)"))
        #expect(inspector.contains("macwindow.on.rectangle"))
        #expect(inspector.contains("TracexyApp.sessionInspectorWindowID"))
        #expect(!inspector.contains("https://\\(session.host)"))
        #expect(app.contains("static let sessionInspectorWindowID = \"session-inspector\""))
        #expect(app.contains("Window(\"Session Inspector\""))
        #expect(app.contains("InspectorView(coordinator: coordinator, allowsDetaching: false)"))
        #expect(app.contains("restorationBehavior(.disabled)"))
    }

    @Test("Workspace footer centers only the selected-session summary")
    func sessionFooterUsesIndependentCenterAndTrailingRegions() throws {
        let footer = try readProjectFile("Tracexy/Views/Sessions/SessionStatusBar.swift")

        #expect(footer.contains("CenteredStatusFooterLayout(spacing:"))
        #expect(footer.contains("at: CGPoint(x: bounds.midX, y: bounds.midY)"))
        #expect(footer.contains("at: CGPoint(x: bounds.maxX, y: bounds.midY)"))
        #expect(!footer.contains("Spacer(minLength: 24)"))
    }

    @Test("Command-F focuses the existing Sessions search without adding a new search surface")
    func sessionSearchUsesNativeFindCommand() throws {
        let app = try readProjectFile("Tracexy/TracexyApp.swift")
        let filterBar = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")

        #expect(app.contains("coordinator.beginSessionSearch()"))
        #expect(app.contains(".keyboardShortcut(\"f\", modifiers: .command)"))
        #expect(filterBar.contains("@FocusState private var isSearchFieldFocused"))
        #expect(filterBar.contains(".task(id: workspace.searchFocusRequest)"))
        #expect(filterBar.contains(".focused($isSearchFieldFocused)"))
        #expect(!filterBar.contains(".searchable"))
    }

    @Test("Findings is a toolbar-only quick filter over the scalable session workflow")
    func findingsUsesSessionQuickFilter() throws {
        let root = try readProjectFile("Tracexy/Views/Main/RootView.swift")
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let sidebarItems = try readProjectFile("Tracexy/Models/UI/SidebarItem.swift")
        let filters = try readProjectFile("Tracexy/Views/Sessions/SessionFilterBar.swift")

        #expect(!root.contains("SecurityFindingsView(coordinator:"))
        #expect(!sidebar.contains("securityQuickFilterRow"))
        #expect(!sidebarItems.contains("case security"))
        #expect(!sidebarItems.contains(".security]"))
        #expect(filters.contains("systemImage: category == .security ? \"list.bullet.clipboard\" : nil"))
    }

    @Test("Investigation uses native typed controls and never moves into the telemetry footer")
    func investigationOwnsTypedSessionChrome() throws {
        let query = try readProjectFile("Tracexy/Views/Sessions/InvestigationQueryView.swift")
        let commands = try readProjectFile("Tracexy/Views/Sessions/SessionCommandBar.swift")
        let footer = try readProjectFile("Tracexy/Views/Sessions/SessionStatusBar.swift")

        #expect(commands.contains("case investigate"))
        #expect(query.contains("Picker(\"Field\""))
        #expect(query.contains(".accessibilityLabel(\"Investigation field\")"))
        #expect(query.contains("DatePicker(\"From\""))
        #expect(query.contains("A missing retained finding is never treated as proof"))
        #expect(query.contains(".accessibilityLabel(\"Investigation query editor\")"))
        #expect(!footer.contains("Investigate"))
        #expect(!footer.contains("Investigation"))
    }

    @Test("Planned MCP and AI settings never imply a service is active")
    func plannedMCPSettingsAreTruthful() throws {
        let source = try readProjectFile("Tracexy/Views/Settings/MCPSettingsView.swift")

        #expect(source.contains("No server is running"))
        #expect(source.contains("Tracexy does not open a port or expose capture data"))
        #expect(source.contains("No provider receives sessions or evidence"))
        #expect(!source.contains("@AppStorage"))
        #expect(!source.contains("Enable in-app MCP server"))
        #expect(!source.contains("Expose sessions to AI clients"))
    }

    @Test("Saved captures expose native context actions and recoverable removal")
    func savedCaptureRemovalUsesTrash() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let persistence = try readProjectFile(
            "Tracexy/ViewModels/MainContentCoordinator+CapturePersistence.swift"
        )

        #expect(sidebar.contains("Button(\"Open\", systemImage: \"eye\")"))
        #expect(sidebar.contains("Button(\"Reveal in Finder\", systemImage: \"folder\")"))
        #expect(sidebar.contains("Button(\"Copy Path\", systemImage: \"doc.on.doc\")"))
        #expect(sidebar.contains("Button(\"Move to Trash…\", systemImage: \"trash\", role: .destructive)"))
        #expect(sidebar.contains(".confirmationDialog("))
        #expect(persistence.contains("FileManager.default.trashItem(at: capture.url"))
        #expect(!persistence.contains("removeItem(at: capture.url)"))
    }

    @Test("Sources category rows expose full-width context actions")
    func sourceCategoryRowsHaveContextMenus() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")
        let visibility = try readProjectFile(
            "Tracexy/ViewModels/MainContentCoordinator+SourceVisibility.swift"
        )

        #expect(sidebar.contains("sourceCategoryLabel("))
        #expect(sidebar.contains("copyLabel: \"Copy App Names\""))
        #expect(sidebar.contains("copyLabel: \"Copy Domains\""))
        #expect(sidebar.contains("copyLabel: \"Copy IP Addresses\""))
        #expect(sidebar.contains("Button(\"Show All Sessions\", systemImage: \"rectangle.stack\")"))
        #expect(sidebar.contains("Button(\"Remove from Sources\", systemImage: \"trash\", role: .destructive)"))
        #expect(sidebar.contains("restoreLabel: \"Restore Hidden Apps\""))
        #expect(sidebar.contains("restoreLabel: \"Restore Hidden Domains\""))
        #expect(sidebar.contains("restoreLabel: \"Restore Hidden IP Addresses\""))
        #expect(sidebar.contains(".frame(maxWidth: .infinity, alignment: .leading)"))
        #expect(visibility.contains("ProjectScopedSettingsKeys.hiddenSourceApps"))
        #expect(visibility.contains("ProjectScopedSettingsKeys.hiddenSourceDomains"))
        #expect(visibility.contains("ProjectScopedSettingsKeys.hiddenSourceIPs"))
        #expect(visibility.contains("defaults: activeProjectDefaults"))
        #expect(visibility.contains("persistHiddenSources()"))
        #expect(!visibility.contains("sessions.removeAll"))
    }

    @Test("Capture data auto-expands Protocols, Apps, and Domains without following filters")
    func captureDataAutoExpandsSidebarGroups() throws {
        let sidebar = try readProjectFile("Tracexy/Views/Sidebar/SidebarView.swift")

        #expect(sidebar.contains(".onChange(of: coordinator.sessions.isEmpty, initial: true)"))
        #expect(sidebar.contains("protocolsExpanded = true"))
        #expect(sidebar.contains("appsExpanded = true"))
        #expect(sidebar.contains("domainsExpanded = true"))
        #expect(!sidebar.contains("ipsExpanded = true"))
        #expect(!sidebar.contains(".onChange(of: coordinator.visibleSessions.count"))
    }

    @Test("AI Assistant uses a truthful conversation shell")
    func assistantUsesConversationShell() throws {
        let source = try readProjectFile("Tracexy/Views/Inspector/AIAssistantDockView.swift")

        #expect(source.contains("conversationHeader"))
        #expect(source.contains("attachedContextHeader"))
        #expect(source.contains("conversationTranscript"))
        #expect(source.contains("promptComposer"))
        #expect(source.contains("New Conversation"))
        #expect(source.contains("Select a session to add context"))
        #expect(source.contains("Ask Tracexy AI Assistant…"))
        #expect(source.contains("Label(\"Not connected\", systemImage: \"cpu\")"))
        #expect(source.contains("Label(\"Read-only\", systemImage: \"lock.shield\")"))
        #expect(!source.contains("sampleMessages"))
        #expect(!source.contains("streamingText"))
    }

    // MARK: Private

    private enum ResolveError: Error {
        case rootNotFound
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        let root = try resolveProjectRoot()
        return try String(contentsOf: root.appendingPathComponent(relativePath), encoding: .utf8)
    }

    private func productionViewSources() throws -> [(path: String, source: String)] {
        let root = try resolveProjectRoot()
        let views = root.appendingPathComponent("Tracexy/Views", isDirectory: true)
        let enumerator = try #require(FileManager.default.enumerator(
            at: views,
            includingPropertiesForKeys: nil
        ))
        return try enumerator.compactMap { item in
            guard let url = item as? URL, url.pathExtension == "swift" else {
                return nil
            }
            let relativePath = url.path.replacingOccurrences(
                of: root.path + "/Tracexy/Views/",
                with: ""
            )
            return try (
                path: relativePath,
                source: String(contentsOf: url, encoding: .utf8)
            )
        }
    }

    private func resolveProjectRoot() throws -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        guard url.lastPathComponent == "TracexyTests" else {
            throw ResolveError.rootNotFound
        }
        url.deleteLastPathComponent()
        return url
    }
}
