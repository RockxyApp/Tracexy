import Foundation
import Testing
@testable import Tracexy

// MARK: - TabPolicy

private struct TabPolicy: AppPolicy {
    var maxWorkspaceTabs = 3
}

// MARK: - WorkspaceTabTests

/// Workspace tabs: opening one is growth under the tab limit, closing, renaming
/// and switching never are, and every change reaches the Project catalog.
@Suite("Workspace tabs")
@MainActor
struct WorkspaceTabTests {
    @Test("New Tab opens and activates numbered tabs up to the limit, then explains the limit")
    func newTabStopsAtLimit() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-limit")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy())
        await coordinator.hydrateProjectsOnLaunch()

        coordinator.newWorkspaceTab()
        coordinator.newWorkspaceTab()
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 2", "Workspace 3"])
        #expect(coordinator.activeWorkspace.title == "Workspace 3")
        #expect(coordinator.policyNotice == nil)

        coordinator.newWorkspaceTab()
        #expect(coordinator.workspaces.workspaces.count == 3)
        #expect(coordinator.policyNotice == AppPolicyViolation.workspaceTabLimitReached(limit: 3).errorDescription)
    }

    @Test("Closing a middle tab never repeats a name; the first tab cannot be closed")
    func closingKeepsNamesUnique() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-close")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy(maxWorkspaceTabs: 5))
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.newWorkspaceTab()
        coordinator.newWorkspaceTab()
        let middle = coordinator.workspaces.workspaces[1].id
        coordinator.closeWorkspaceTab(middle)
        coordinator.newWorkspaceTab()
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 3", "Workspace 4"])

        let live = coordinator.workspaces.workspaces[0].id
        coordinator.closeWorkspaceTab(live)
        #expect(coordinator.workspaces.workspaces.count == 3)

        coordinator.closeOtherWorkspaceTabs(keeping: coordinator.workspaces.workspaces[2].id)
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 4"])
        #expect(coordinator.activeWorkspace.title == "Workspace 4")
    }

    @Test("Show Next and Previous Tab wrap around")
    func adjacentTabsWrap() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-cycle")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy())
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.newWorkspaceTab()
        coordinator.newWorkspaceTab()
        coordinator.showAdjacentWorkspaceTab(1)
        #expect(coordinator.activeWorkspace.title == "Live")
        coordinator.showAdjacentWorkspaceTab(-1)
        #expect(coordinator.activeWorkspace.title == "Workspace 3")
        coordinator.showAdjacentWorkspaceTab(-1)
        #expect(coordinator.activeWorkspace.title == "Workspace 2")
    }

    @Test("Renaming trims, drops control characters, bounds the length and refuses an empty name")
    func renameNormalizes() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-rename")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy())
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.newWorkspaceTab()
        let id = coordinator.activeWorkspace.id

        #expect(coordinator.renameWorkspaceTab(id, to: "  DNS\u{0007} only \n"))
        #expect(coordinator.activeWorkspace.title == "DNS only")
        #expect(!coordinator.renameWorkspaceTab(id, to: "   "))
        #expect(coordinator.activeWorkspace.title == "DNS only")
        #expect(coordinator.renameWorkspaceTab(id, to: String(repeating: "x", count: 200)))
        #expect(coordinator.activeWorkspace.title.count == ProjectLimits.maximumNameLength)
    }

    @Test("Tabs, their names and the active tab come back after a relaunch")
    func tabsSurviveRelaunch() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-relaunch", persistsCatalog: true)
        defer { environment.tearDown() }
        let first = environment.makeCoordinator(policy: TabPolicy())
        await first.hydrateProjectsOnLaunch()
        first.newWorkspaceTab()
        first.renameWorkspaceTab(first.activeWorkspace.id, to: "TLS")
        first.newWorkspaceTab()
        first.selectWorkspaceTab(first.workspaces.workspaces[1].id)
        await first.projectStore.waitForPendingPersistence()

        let second = environment.makeCoordinator(policy: TabPolicy())
        await second.hydrateProjectsOnLaunch()
        #expect(second.workspaces.workspaces.map(\.title) == ["Live", "TLS", "Workspace 3"])
        #expect(second.activeWorkspace.title == "TLS")
    }

    @Test("A lowered limit keeps every open tab; closing still works and New Tab explains")
    func loweredLimitKeepsTabs() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-lowered")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy(maxWorkspaceTabs: 5))
        await coordinator.hydrateProjectsOnLaunch()
        for _ in 0 ..< 4 {
            coordinator.newWorkspaceTab()
        }
        coordinator.applyPolicy(TabPolicy(maxWorkspaceTabs: 2))
        #expect(coordinator.workspaces.workspaces.count == 5)
        coordinator.closeWorkspaceTab(coordinator.activeWorkspace.id)
        #expect(coordinator.workspaces.workspaces.count == 4)
        coordinator.newWorkspaceTab()
        #expect(coordinator.workspaces.workspaces.count == 4)
        #expect(coordinator.policyNotice != nil)
    }

    @Test("Close Other Tabs asks first only when the closed tabs could not all be added back")
    func closeOthersWarnsAboveLimit() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-close-others")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy(maxWorkspaceTabs: 5))
        await coordinator.hydrateProjectsOnLaunch()
        for _ in 0 ..< 3 {
            coordinator.newWorkspaceTab()
        }
        let kept = coordinator.activeWorkspace.id
        #expect(coordinator.closeOtherWorkspaceTabsWarning(keeping: kept) == nil)

        coordinator.applyPolicy(TabPolicy(maxWorkspaceTabs: 2))
        #expect(coordinator.closeOtherWorkspaceTabsWarning(keeping: kept) != nil)
        coordinator.closeOtherWorkspaceTabs(keeping: kept)
        #expect(coordinator.workspaces.workspaces.map(\.id).contains(kept))
        #expect(coordinator.workspaces.workspaces.count == 2)
    }

    @Test("Typed filter text and rule values stay within what a Project can store")
    func typedFiltersStayStorable() {
        let workspace = WorkspaceState(title: "Live", isClosable: false)
        workspace.filterText = String(repeating: "x", count: ProjectLimits.maximumStringLength + 90)
        #expect(workspace.filterText.count == ProjectLimits.maximumStringLength)
        var rule = SessionFilterRule()
        rule.value = String(repeating: "y", count: ProjectLimits.maximumStringLength * 2)
        #expect(rule.value.count == ProjectLimits.maximumStringLength)
        #expect(SessionFilterRule(value: String(repeating: "z", count: 900)).value.count
            == ProjectLimits.maximumStringLength)
        // A drill-in scope taken from traffic that is too long to store is not saved.
        workspace.hostFilter = String(repeating: "h", count: 700)
        workspace.processFilter = "curl"
        let snapshot = ProjectWorkspaceSnapshot(capturing: workspace)
        #expect(snapshot.hostFilter == nil)
        #expect(snapshot.processFilter == "curl")
    }

    @Test("Tabs share the strip evenly and scroll only below the minimum width")
    func tabBarWidths() {
        let two = WorkspaceTabStripLayout.tabWidth(stripWidth: 1_000, count: 2)
        #expect(two.width == 500 && !two.overflows)
        #expect(WorkspaceTabStripLayout.tabWidth(stripWidth: 1_000, count: 5).width == 200)
        #expect(WorkspaceTabStripLayout.tabWidth(stripWidth: 1_000, count: 8).overflows)
        let many = WorkspaceTabStripLayout.tabWidth(stripWidth: 1_000, count: 32)
        #expect(many.width == WorkspaceTabStripLayout.minimumTabWidth && many.overflows)
        #expect(!WorkspaceTabStripLayout.tabWidth(stripWidth: 1_000, count: 0).overflows)
        #expect(!WorkspaceTabStripLayout.tabWidth(stripWidth: 0, count: 3).overflows)
    }

    @Test("An overflowing strip scrolls just far enough to show the active tab")
    func stripRevealsActiveTab() {
        // 32 tabs of 100 in a 1,000 wide strip: 3,200 of content, 2,200 of travel.
        #expect(WorkspaceTabStripLayout
            .offset(revealing: 0, tabWidth: 100, stripWidth: 1_000, count: 32, from: 500) == 0)
        #expect(WorkspaceTabStripLayout
            .offset(revealing: 12, tabWidth: 100, stripWidth: 1_000, count: 32, from: 0) == 324)
        #expect(WorkspaceTabStripLayout
            .offset(revealing: 5, tabWidth: 100, stripWidth: 1_000, count: 32, from: 300) == 300)
        #expect(WorkspaceTabStripLayout
            .offset(revealing: 31, tabWidth: 100, stripWidth: 1_000, count: 32, from: 0) == 2_200)
        #expect(WorkspaceTabStripLayout
            .offset(revealing: -1, tabWidth: 100, stripWidth: 1_000, count: 32, from: 9_000) == 2_200)
        #expect(WorkspaceTabStripLayout.insertionIndex(forContentX: 140, tabWidth: 100, count: 4) == 1)
        #expect(WorkspaceTabStripLayout.insertionIndex(forContentX: 160, tabWidth: 100, count: 4) == 2)
        #expect(WorkspaceTabStripLayout.insertionIndex(forContentX: 9_000, tabWidth: 100, count: 4) == 4)
    }

    @Test("Dragging reorders tabs, keeps Live first and is saved to the Project")
    func dragReorders() async {
        let environment = ProjectIsolationEnvironment(name: "workspace-tabs-move")
        defer { environment.tearDown() }
        let coordinator = environment.makeCoordinator(policy: TabPolicy(maxWorkspaceTabs: 5))
        await coordinator.hydrateProjectsOnLaunch()
        coordinator.newWorkspaceTab()
        coordinator.newWorkspaceTab()
        coordinator.newWorkspaceTab()
        let tabs = coordinator.workspaces.workspaces
        coordinator.moveWorkspaceTab(tabs[3].id, toInsertionIndex: 1)
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 4", "Workspace 2", "Workspace 3"])
        coordinator.moveWorkspaceTab(tabs[1].id, toInsertionIndex: 0)
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 2", "Workspace 4", "Workspace 3"])
        coordinator.moveWorkspaceTab(tabs[0].id, toInsertionIndex: 4)
        #expect(coordinator.workspaces.workspaces.first?.title == "Live")
        coordinator.moveWorkspaceTab(tabs[1].id, toInsertionIndex: 4)
        #expect(coordinator.workspaces.workspaces.map(\.title) == ["Live", "Workspace 4", "Workspace 3", "Workspace 2"])
        let saved = coordinator.workspaces.captureProjectWorkspaces().map(\.title)
        #expect(saved == ["Live", "Workspace 4", "Workspace 3", "Workspace 2"])
    }
}
