import Foundation

// MARK: - Navigation, pins, Focus Sets, and Noise Control

/// All of these are Project-owned: pins, Focus Sets and muted noise persist into
/// the *active Project's* preferences suite, never the shared domain, so one
/// investigation's saved filters can never leak into another's.
@MainActor
extension MainContentCoordinator {
    // MARK: Search

    /// ⌘F: bring the user to the session search box and put the cursor in it.
    ///
    /// Routes to the Sessions surface if they are elsewhere, reveals the filter
    /// bar, and switches the search on — the three states the box needs to be
    /// usable — then bumps a focus token the existing field observes. It does
    /// *not* touch the query text or any active filter (host/process/IP drill-down,
    /// category chips, advanced rules), so an in-progress investigation is
    /// preserved; ⌘F only reveals and focuses the box that is already there.
    func beginSessionSearch() {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.isFilterBarVisible = true
        ws.isSearchEnabled = true
        ws.searchFocusRequest = UUID()
    }

    // MARK: Sidebar selection

    /// Selects a top-level sidebar item, clearing any host/process/IP drill-down.
    func selectSidebarItem(_ item: SidebarItem) {
        let ws = activeWorkspace
        ws.sidebarSelection = item
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = nil
    }

    /// Drills into a single host/domain (from the sidebar "Domains"/"Pinned" groups).
    func selectHost(_ host: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.processFilter = nil
        ws.ipFilter = nil
        ws.hostFilter = host
    }

    /// Drills into a single process (from the sidebar "Apps" group).
    func selectProcess(_ process: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.ipFilter = nil
        ws.processFilter = process
    }

    /// Drills into a single IP address (a sub-IP under a domain).
    func selectIP(_ ip: String) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = ip
    }

    // MARK: Pinned hosts (Favorites)

    func isHostPinned(_ host: String) -> Bool {
        pinnedHosts.contains(host)
    }

    /// Pins or unpins a host and persists the new set into this Project's suite.
    func togglePinHost(_ host: String) {
        guard !host.isEmpty, host != "—" else {
            return
        }
        if let index = pinnedHosts.firstIndex(of: host) {
            pinnedHosts.remove(at: index)
        } else {
            do {
                try focusGate.validatePinningHost(host, into: pinnedHosts)
            } catch {
                policyNotice = error.localizedDescription
                return
            }
            pinnedHosts.append(host)
        }
        policyNotice = nil
        activeProjectDefaults.set(pinnedHosts, forKey: ProjectScopedSettingsKeys.pinnedHosts)
    }

    // MARK: Focus Sets

    /// Inserts or updates a focus set (used by the editor sheet), then persists.
    /// A save that would exceed the focus-set cap leaves the stored sets
    /// untouched and reports why through ``policyNotice``.
    func saveFocusSet(_ set: FocusSet) {
        var normalizedSet = set
        normalizedSet.rules = SessionFilterRule.normalized(
            set.rules,
            limit: policy.maxSessionFilterRules
        )
        do {
            try focusGate.validateSavingFocusSet(normalizedSet, into: focusSets)
        } catch {
            policyNotice = error.localizedDescription
            return
        }
        if let index = focusSets.firstIndex(where: { $0.id == normalizedSet.id }) {
            focusSets[index] = normalizedSet
        } else {
            focusSets.append(normalizedSet)
        }
        policyNotice = nil
        persistFocusSets()
    }

    /// Loads a focus set's rules into the active workspace's advanced filter.
    func applyFocusSet(_ set: FocusSet) {
        let ws = activeWorkspace
        ws.sidebarSelection = .sessions
        ws.hostFilter = nil
        ws.processFilter = nil
        ws.ipFilter = nil
        // A saved set may hold more rows than this build allows (it was saved on
        // a different build, or the cap changed). Clamp to capacity, and never
        // leave the builder with zero rows.
        ws.filterRules = SessionFilterRule.normalized(set.rules, limit: policy.maxSessionFilterRules)
        ws.isFilterBarVisible = true
        ws.isAdvancedFilterVisible = true
    }

    func deleteFocusSet(_ set: FocusSet) {
        focusSets.removeAll { $0.id == set.id }
        persistFocusSets()
    }

    /// A blank draft seeded from the active workspace's current active rules, so
    /// "Add" captures whatever the user is already filtering by.
    func draftFocusSet() -> FocusSet {
        let active = activeWorkspace.activeFilterRules
        return FocusSet(
            name: "",
            rules: active.isEmpty ? [SessionFilterRule()] : active
        )
    }

    // MARK: Noise Control

    func isHostMuted(_ host: String) -> Bool {
        mutedHosts.contains(host)
    }

    func isProtocolMuted(_ proto: ProtocolKind) -> Bool {
        mutedProtocols.contains(proto)
    }

    func toggleMuteHost(_ host: String) {
        if mutedHosts.contains(host) {
            mutedHosts.remove(host)
        } else {
            mutedHosts.insert(host)
        }
        persistMutedNoise()
    }

    func toggleMuteProtocol(_ proto: ProtocolKind) {
        if mutedProtocols.contains(proto) {
            mutedProtocols.remove(proto)
        } else {
            mutedProtocols.insert(proto)
        }
        persistMutedNoise()
    }

    func clearNoiseControl() {
        mutedHosts = []
        mutedProtocols = []
        persistMutedNoise()
    }

    // MARK: Private

    private func persistFocusSets() {
        guard let data = try? JSONEncoder().encode(focusSets) else {
            return
        }
        activeProjectDefaults.set(data, forKey: ProjectScopedSettingsKeys.focusSets)
    }

    private func persistMutedNoise() {
        activeProjectDefaults.set(Array(mutedHosts), forKey: ProjectScopedSettingsKeys.mutedHosts)
        activeProjectDefaults.set(
            mutedProtocols.map(\.rawValue),
            forKey: ProjectScopedSettingsKeys.mutedProtocols
        )
    }
}
