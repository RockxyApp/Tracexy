import Foundation

// MARK: - Source visibility

@MainActor
extension MainContentCoordinator {
    func isSourceAppHidden(_ app: String) -> Bool {
        hiddenSourceApps.contains(app)
    }

    func isSourceDomainHidden(_ domain: String) -> Bool {
        hiddenSourceDomains.contains(domain)
    }

    func isSourceIPHidden(_ ip: String) -> Bool {
        hiddenSourceIPs.contains(ip)
    }

    func isSourceHostHidden(_ host: String) -> Bool {
        Self.isDomainName(host) ? isSourceDomainHidden(host) : isSourceIPHidden(host)
    }

    func hideSourceApp(_ app: String) {
        guard !app.isEmpty else {
            return
        }
        hiddenSourceApps.insert(app)
        if activeWorkspace.processFilter == app {
            selectSidebarItem(.sessions)
        }
        persistHiddenSources()
    }

    func hideSourceDomain(_ domain: String) {
        guard !domain.isEmpty else {
            return
        }
        hiddenSourceDomains.insert(domain)
        if activeWorkspace.hostFilter == domain {
            selectSidebarItem(.sessions)
        }
        persistHiddenSources()
    }

    func hideSourceIP(_ ip: String) {
        guard !ip.isEmpty else {
            return
        }
        hiddenSourceIPs.insert(ip)
        if activeWorkspace.ipFilter == ip || activeWorkspace.hostFilter == ip {
            selectSidebarItem(.sessions)
        }
        persistHiddenSources()
    }

    func hideSourceHost(_ host: String) {
        if Self.isDomainName(host) {
            hideSourceDomain(host)
        } else {
            hideSourceIP(host)
        }
    }

    func restoreHiddenSourceApps() {
        hiddenSourceApps.removeAll()
        persistHiddenSources()
    }

    func restoreHiddenSourceDomains() {
        hiddenSourceDomains.removeAll()
        persistHiddenSources()
    }

    func restoreHiddenSourceIPs() {
        hiddenSourceIPs.removeAll()
        persistHiddenSources()
    }

    private func persistHiddenSources() {
        SourceVisibilityPreferences.persist(
            apps: hiddenSourceApps,
            domains: hiddenSourceDomains,
            ips: hiddenSourceIPs,
            defaults: activeProjectDefaults
        )
    }
}

// MARK: - SourceVisibilityPreferences

/// Hidden-source presentation state. `defaults` is always the *active Project's*
/// suite, so hiding a row in one Project never removes it from another.
enum SourceVisibilityPreferences {
    // MARK: Internal

    static func loadApps(defaults: UserDefaults) -> Set<String> {
        load(key: ProjectScopedSettingsKeys.hiddenSourceApps, defaults: defaults)
    }

    static func loadDomains(defaults: UserDefaults) -> Set<String> {
        load(key: ProjectScopedSettingsKeys.hiddenSourceDomains, defaults: defaults)
    }

    static func loadIPs(defaults: UserDefaults) -> Set<String> {
        load(key: ProjectScopedSettingsKeys.hiddenSourceIPs, defaults: defaults)
    }

    static func persist(
        apps: Set<String>,
        domains: Set<String>,
        ips: Set<String>,
        defaults: UserDefaults
    ) {
        defaults.set(apps.sorted(), forKey: ProjectScopedSettingsKeys.hiddenSourceApps)
        defaults.set(domains.sorted(), forKey: ProjectScopedSettingsKeys.hiddenSourceDomains)
        defaults.set(ips.sorted(), forKey: ProjectScopedSettingsKeys.hiddenSourceIPs)
    }

    // MARK: Private

    private static func load(key: String, defaults: UserDefaults) -> Set<String> {
        Set(defaults.stringArray(forKey: key) ?? [])
    }
}
