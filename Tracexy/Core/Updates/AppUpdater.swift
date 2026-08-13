import AppKit
import Combine
import Foundation
import os
import Sparkle

// MARK: - AppcastVersionParser

/// Reads the ordered release versions from Sparkle's public appcast. The parser
/// accepts the two layouts Sparkle commonly emits: version metadata on the item
/// itself or on its enclosure.
private final class AppcastVersionParser: NSObject, XMLParserDelegate {
    // MARK: Internal

    static func versions(from data: Data) -> [String]? {
        let delegate = AppcastVersionParser()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        guard parser.parse() else {
            return nil
        }
        return delegate.versions
    }

    func parser(
        _ parser: XMLParser,
        didStartElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?,
        attributes attributeDict: [String: String] = [:]
    ) {
        switch elementName {
        case "item":
            isParsingItem = true
            currentItemVersion = versionString(in: attributeDict)
        case "enclosure":
            guard let version = versionString(in: attributeDict) else {
                return
            }
            if isParsingItem {
                currentItemVersion = currentItemVersion ?? version
            } else {
                versions.append(version)
            }
        default:
            break
        }
    }

    func parser(
        _ parser: XMLParser,
        didEndElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?
    ) {
        guard elementName == "item" else {
            return
        }
        if let currentItemVersion {
            versions.append(currentItemVersion)
        }
        currentItemVersion = nil
        isParsingItem = false
    }

    // MARK: Private

    private var versions: [String] = []
    private var currentItemVersion: String?
    private var isParsingItem = false

    private func versionString(in attributes: [String: String]) -> String? {
        let version = attributes["sparkle:shortVersionString"]
            ?? attributes["shortVersionString"]
            ?? attributes["http://www.andymatuschak.org/xml-namespaces/sparkle:shortVersionString"]
        guard let version, !version.isEmpty else {
            return nil
        }
        return version
    }
}

// MARK: - UpdateCheckIntervalOption

enum UpdateCheckIntervalOption: Double, CaseIterable, Identifiable {
    case daily = 86_400
    case weekly = 604_800
    case monthly = 2_592_000

    // MARK: Internal

    var id: Double {
        rawValue
    }

    var title: String {
        switch self {
        case .daily: String(localized: "Daily")
        case .weekly: String(localized: "Weekly")
        case .monthly: String(localized: "Monthly")
        }
    }

    static func closest(to interval: TimeInterval) -> Self {
        allCases.min {
            abs($0.rawValue - interval) < abs($1.rawValue - interval)
        } ?? .daily
    }
}

// MARK: - AppUpdater

/// The app-lifetime owner for Sparkle. Views receive this object rather than
/// creating updater controllers or duplicating Sparkle-backed preferences.
@MainActor
final class AppUpdater: NSObject, ObservableObject, SPUUpdaterDelegate {
    // MARK: Lifecycle

    init(configuration: TracexyUpdateConfiguration) {
        self.configuration = configuration
        updaterController = nil
        cancellables = []
        super.init()

        if configuration.supportsUserInitiatedChecks,
           !configuration.supportsAutomaticChecks
        {
            Self.installManualOnlyOverrides()
        }

        guard configuration.supportsUserInitiatedChecks else {
            return
        }

        updaterController = SPUStandardUpdaterController(
            startingUpdater: false,
            updaterDelegate: self,
            userDriverDelegate: nil
        )
        bindSparkleState()
        refreshSparkleState()
    }

    // MARK: Internal

    struct UpdateStatusSummary: Equatable {
        let currentVersion: String
        let latestVersion: String
        let versionsBehind: Int?

        var title: String {
            String(localized: "Update Available")
        }

        var versionLine: String {
            "v\(currentVersion) -> v\(latestVersion)"
        }

        var countLine: String? {
            guard let versionsBehind, versionsBehind > 0 else {
                return nil
            }
            return versionsBehind == 1
                ? String(localized: "1 version behind")
                : String(localized: "\(versionsBehind) versions behind")
        }

        var badgeTitle: String {
            guard let versionsBehind, versionsBehind > 0 else {
                return title
            }
            return versionsBehind == 1
                ? String(localized: "1 New Update")
                : String(localized: "\(versionsBehind) New Updates")
        }

        func replacingVersionsBehind(_ count: Int?) -> Self {
            .init(
                currentVersion: currentVersion,
                latestVersion: latestVersion,
                versionsBehind: count
            )
        }
    }

    static let shared = AppUpdater(configuration: .current)

    static let changelogURL: URL = {
        guard let url = URL(string: "https://github.com/RockxyApp/Tracexy/releases") else {
            preconditionFailure("Invalid Tracexy changelog URL")
        }
        return url
    }()

    @Published private(set) var canCheckForUpdates = false
    @Published private(set) var automaticallyChecksForUpdates = false
    @Published private(set) var automaticallyDownloadsUpdates = false
    @Published private(set) var allowsAutomaticUpdates = false
    @Published private(set) var sendsSystemProfile = false
    @Published private(set) var lastUpdateCheckDate: Date?
    @Published private(set) var updateCheckInterval = UpdateCheckIntervalOption.daily.rawValue
    @Published private(set) var sessionInProgress = false
    @Published private(set) var updateStatusSummary: UpdateStatusSummary?

    let configuration: TracexyUpdateConfiguration

    var supportsManualChecks: Bool {
        configuration.supportsUserInitiatedChecks
    }

    var supportsAutomaticChecks: Bool {
        configuration.supportsAutomaticChecks
    }

    var canInitiateUpdateCheck: Bool {
        supportsManualChecks && (!hasStartedUpdater || canCheckForUpdates)
    }

    var currentVersionSummary: String {
        "\(configuration.appVersion) (build \(configuration.buildNumber))"
    }

    var updateAvailabilitySummary: String {
        if supportsAutomaticChecks {
            return String(localized: "Signed automatic updates are enabled for this build.")
        }
        if supportsManualChecks {
            return String(
                localized: "Manual update checks are available. Scheduled checks stay off in local development builds."
            )
        }
        return String(localized: "Software updates are not configured for this build.")
    }

    var lastCheckedDescription: String {
        lastUpdateCheckDate?.formatted(date: .abbreviated, time: .shortened)
            ?? String(localized: "Never")
    }

    static func makeUpdateStatusSummary(
        currentVersion: String,
        latestVersion: String,
        versionsBehind: Int? = nil
    )
        -> UpdateStatusSummary?
    {
        guard compareVersions(latestVersion, currentVersion) == .orderedDescending else {
            return nil
        }
        return UpdateStatusSummary(
            currentVersion: currentVersion,
            latestVersion: latestVersion,
            versionsBehind: versionsBehind ?? semanticVersionsBehind(
                currentVersion: currentVersion,
                latestVersion: latestVersion
            )
        )
    }

    static func makeUpdateStatusSummary(
        currentVersion: String,
        appcastData: Data
    )
        -> UpdateStatusSummary?
    {
        guard let latestVersion = AppcastVersionParser.versions(from: appcastData)?.first else {
            return nil
        }
        return makeUpdateStatusSummary(
            currentVersion: currentVersion,
            latestVersion: latestVersion,
            versionsBehind: versionsBehind(
                currentVersion: currentVersion,
                latestVersion: latestVersion,
                appcastData: appcastData
            )
        )
    }

    static func versionsBehind(
        currentVersion: String,
        latestVersion: String,
        appcastData: Data
    )
        -> Int?
    {
        let semanticCount = semanticVersionsBehind(
            currentVersion: currentVersion,
            latestVersion: latestVersion
        )
        guard let versions = AppcastVersionParser.versions(from: appcastData) else {
            return semanticCount
        }

        var seen: Set<String> = []
        let newerVersions = versions.filter { version in
            guard seen.insert(version).inserted else {
                return false
            }
            return compareVersions(version, currentVersion) == .orderedDescending
                && compareVersions(version, latestVersion) != .orderedDescending
        }
        let appcastCount = newerVersions.isEmpty ? nil : newerVersions.count
        if let appcastCount, appcastCount > 1 {
            return appcastCount
        }
        return [appcastCount, semanticCount].compactMap { $0 }.max()
    }

    static func compareVersions(_ lhs: String, _ rhs: String) -> ComparisonResult {
        let lhsComponents = versionComponents(lhs)
        let rhsComponents = versionComponents(rhs)
        let count = max(lhsComponents.count, rhsComponents.count)

        for index in 0 ..< count {
            let lhsValue = index < lhsComponents.count ? lhsComponents[index] : 0
            let rhsValue = index < rhsComponents.count ? rhsComponents[index] : 0
            if lhsValue < rhsValue {
                return .orderedAscending
            }
            if lhsValue > rhsValue {
                return .orderedDescending
            }
        }
        return .orderedSame
    }

    func startIfConfigured() {
        guard !TracexyIdentity.isRunningTests else {
            return
        }
        #if DEBUG
        if installUpdateBadgePreview(environment: ProcessInfo.processInfo.environment) {
            return
        }
        #endif
        if supportsAutomaticChecks {
            startUpdaterIfNeeded()
        }
        if supportsManualChecks {
            refreshUpdateStatusFromAppcast()
        }
    }

    #if DEBUG
    /// Installs an explicit local-only badge fixture for visual QA. Normal Debug
    /// launches and every Release build continue to derive update state solely
    /// from the signed appcast.
    @discardableResult
    func installUpdateBadgePreview(environment: [String: String]) -> Bool {
        guard let rawCount = environment["TRACEXY_UPDATE_BADGE_PREVIEW_COUNT"],
              let count = Int(rawCount),
              count > 0 else
        {
            return false
        }

        let current = Self.semanticVersionComponents(configuration.appVersion)
        let latestVersion = "\(current.major).\(current.minor).\(current.patch + count)"
        recordUpdateFound(latestVersion: latestVersion, fetchVersionsBehind: false)
        return true
    }
    #endif

    func checkForUpdates() {
        guard supportsManualChecks else {
            return
        }
        guard startUpdaterIfNeeded() else {
            return
        }
        updaterController?.checkForUpdates(nil)
        refreshSparkleState()
    }

    /// Reopens the standard Sparkle experience from the persistent toolbar badge.
    /// Sparkle owns whether this focuses an in-progress session or begins a fresh
    /// check; the badge itself deliberately remains until the feed reports no
    /// newer release.
    func showUpdatesFromStatusBadge() {
        checkForUpdates()
    }

    func refreshUpdateStatusFromAppcast() {
        guard let feedURL = configuration.feedURL else {
            return
        }

        updateStatusTask?.cancel()
        let currentVersion = configuration.appVersion
        updateStatusTask = Task { [weak self] in
            do {
                let (data, _) = try await URLSession.shared.data(from: feedURL)
                let summary = Self.makeUpdateStatusSummary(
                    currentVersion: currentVersion,
                    appcastData: data
                )
                guard !Task.isCancelled else {
                    return
                }
                self?.updateStatusSummary = summary
            } catch {
                Self.logger.debug("Unable to refresh update status from appcast: \(error.localizedDescription)")
            }
        }
    }

    func recordUpdateFound(_ item: SUAppcastItem) {
        recordUpdateFound(latestVersion: item.displayVersionString)
    }

    func recordUpdateFound(latestVersion: String, fetchVersionsBehind: Bool = true) {
        updateStatusTask?.cancel()
        guard let summary = Self.makeUpdateStatusSummary(
            currentVersion: configuration.appVersion,
            latestVersion: latestVersion
        ) else {
            updateStatusSummary = nil
            return
        }

        updateStatusSummary = summary
        guard fetchVersionsBehind, let feedURL = configuration.feedURL else {
            return
        }

        updateStatusTask = Task { [weak self] in
            do {
                let (data, _) = try await URLSession.shared.data(from: feedURL)
                let count = Self.versionsBehind(
                    currentVersion: summary.currentVersion,
                    latestVersion: summary.latestVersion,
                    appcastData: data
                )
                guard !Task.isCancelled,
                      self?.updateStatusSummary?.latestVersion == summary.latestVersion else
                {
                    return
                }
                self?.updateStatusSummary = summary.replacingVersionsBehind(count)
            } catch {
                Self.logger.debug("Unable to compute versions behind from appcast: \(error.localizedDescription)")
            }
        }
    }

    func clearUpdateStatusSummary() {
        updateStatusTask?.cancel()
        updateStatusTask = nil
        updateStatusSummary = nil
    }

    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        recordUpdateFound(item)
    }

    func updaterDidNotFindUpdate(_ updater: SPUUpdater) {
        clearUpdateStatusSummary()
    }

    func openChangelog() {
        NSWorkspace.shared.open(Self.changelogURL)
    }

    func setAutomaticallyChecksForUpdates(_ enabled: Bool) {
        guard supportsAutomaticChecks, let updater = updaterController?.updater else {
            return
        }
        updater.automaticallyChecksForUpdates = enabled
        refreshSparkleState()
    }

    func setAutomaticallyDownloadsUpdates(_ enabled: Bool) {
        guard supportsAutomaticChecks,
              let updater = updaterController?.updater,
              updater.allowsAutomaticUpdates else
        {
            return
        }
        updater.automaticallyDownloadsUpdates = enabled
        refreshSparkleState()
    }

    func setSendsSystemProfile(_ enabled: Bool) {
        guard supportsAutomaticChecks, let updater = updaterController?.updater else {
            return
        }
        updater.sendsSystemProfile = enabled
        refreshSparkleState()
    }

    func setUpdateCheckInterval(_ interval: TimeInterval) {
        guard supportsAutomaticChecks, let updater = updaterController?.updater else {
            return
        }
        updater.updateCheckInterval = interval
        refreshSparkleState()
    }

    // MARK: Private

    private static let logger = Logger(
        subsystem: TracexyIdentity.current.logSubsystem,
        category: "AppUpdater"
    )

    private var updaterController: SPUStandardUpdaterController?
    private var cancellables: Set<AnyCancellable>
    private var hasStartedUpdater = false
    private var updateStatusTask: Task<Void, Never>?

    private static func versionComponents(_ version: String) -> [Int] {
        version
            .trimmingCharacters(in: CharacterSet(charactersIn: "vV"))
            .split(separator: ".")
            .map { component in
                let digits = component.prefix { $0.isNumber }
                return Int(digits) ?? 0
            }
    }

    private static func semanticVersionsBehind(currentVersion: String, latestVersion: String) -> Int? {
        guard compareVersions(latestVersion, currentVersion) == .orderedDescending else {
            return nil
        }
        let current = semanticVersionComponents(currentVersion)
        let latest = semanticVersionComponents(latestVersion)
        guard current.major == latest.major else {
            return nil
        }
        if current.minor == latest.minor {
            let count = latest.patch - current.patch
            return count > 0 ? count : nil
        }
        guard current.patch == 0 else {
            return nil
        }
        let minorCount = latest.minor - current.minor
        guard minorCount > 0 else {
            return nil
        }
        return minorCount + latest.patch
    }

    private static func semanticVersionComponents(_ version: String) -> (major: Int, minor: Int, patch: Int) {
        let components = versionComponents(version)
        return (
            major: versionComponent(at: 0, in: components),
            minor: versionComponent(at: 1, in: components),
            patch: versionComponent(at: 2, in: components)
        )
    }

    private static func versionComponent(at index: Int, in components: [Int]) -> Int {
        components.indices.contains(index) ? components[index] : 0
    }

    private static func installManualOnlyOverrides(defaults: UserDefaults = .standard) {
        var argumentDomain = defaults.volatileDomain(forName: UserDefaults.argumentDomain)
        argumentDomain["SUEnableAutomaticChecks"] = false
        argumentDomain["SUAllowsAutomaticUpdates"] = false
        defaults.setVolatileDomain(argumentDomain, forName: UserDefaults.argumentDomain)
    }

    @discardableResult
    private func startUpdaterIfNeeded() -> Bool {
        guard let updater = updaterController?.updater else {
            return false
        }
        guard !hasStartedUpdater else {
            return true
        }

        do {
            try updater.start()
            hasStartedUpdater = true
            refreshSparkleState()
            Self.logger.info("Sparkle updater started.")
            return true
        } catch {
            Self.logger.error("Sparkle updater failed to start: \(error.localizedDescription)")
            let alert = NSAlert(error: error)
            alert.alertStyle = .warning
            alert.runModal()
            return false
        }
    }

    private func bindSparkleState() {
        guard let updater = updaterController?.updater else {
            return
        }

        updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.canCheckForUpdates = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.automaticallyChecksForUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.automaticallyChecksForUpdates = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.automaticallyDownloadsUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.automaticallyDownloadsUpdates = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.allowsAutomaticUpdates)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.allowsAutomaticUpdates = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.sendsSystemProfile)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.sendsSystemProfile = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.lastUpdateCheckDate)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.lastUpdateCheckDate = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.updateCheckInterval)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.updateCheckInterval = $0 }
            .store(in: &cancellables)
        updater.publisher(for: \.sessionInProgress)
            .receive(on: RunLoop.main)
            .sink { [weak self] in self?.sessionInProgress = $0 }
            .store(in: &cancellables)
    }

    private func refreshSparkleState() {
        guard let updater = updaterController?.updater else {
            return
        }
        canCheckForUpdates = updater.canCheckForUpdates
        automaticallyChecksForUpdates = updater.automaticallyChecksForUpdates
        automaticallyDownloadsUpdates = updater.automaticallyDownloadsUpdates
        allowsAutomaticUpdates = updater.allowsAutomaticUpdates
        sendsSystemProfile = updater.sendsSystemProfile
        lastUpdateCheckDate = updater.lastUpdateCheckDate
        updateCheckInterval = updater.updateCheckInterval
        sessionInProgress = updater.sessionInProgress
    }
}
