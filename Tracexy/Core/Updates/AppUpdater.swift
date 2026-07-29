import AppKit
import Combine
import Foundation
import os
import Sparkle

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

    func startIfConfigured() {
        guard supportsAutomaticChecks, !TracexyIdentity.isRunningTests else {
            return
        }
        startUpdaterIfNeeded()
    }

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
