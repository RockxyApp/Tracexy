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
            ips: hiddenSourceIPs
        )
    }
}

// MARK: - SourceVisibilityPreferences

enum SourceVisibilityPreferences {
    // MARK: Internal

    static func loadApps() -> Set<String> {
        load(key: appsKey)
    }

    static func loadDomains() -> Set<String> {
        load(key: domainsKey)
    }

    static func loadIPs() -> Set<String> {
        load(key: ipsKey)
    }

    static func persist(apps: Set<String>, domains: Set<String>, ips: Set<String>) {
        UserDefaults.standard.set(apps.sorted(), forKey: appsKey)
        UserDefaults.standard.set(domains.sorted(), forKey: domainsKey)
        UserDefaults.standard.set(ips.sorted(), forKey: ipsKey)
    }

    // MARK: Private

    private static let appsKey = TracexyIdentity.current.defaultsKey("sources.hiddenApps")
    private static let domainsKey = TracexyIdentity.current.defaultsKey("sources.hiddenDomains")
    private static let ipsKey = TracexyIdentity.current.defaultsKey("sources.hiddenIPs")

    private static func load(key: String) -> Set<String> {
        Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
    }
}
