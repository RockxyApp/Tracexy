import Foundation

/// Bundle-driven identity and namespace values shared across the app, tests, and helper.
struct TracexyIdentity {
    // MARK: Lifecycle

    init(bundle: Bundle) {
        self.init(infoDictionary: bundle.infoDictionary ?? [:])
    }

    init(infoDictionary info: [String: Any]) {
        let fallbackFamilyNamespace = Self.string(
            named: "TracexyFamilyNamespace",
            in: info,
            fallback: "com.amunx.tracexy"
        )
        let fallbackAppBundleIdentifier = Self.string(
            named: "CFBundleIdentifier",
            in: info,
            fallback: fallbackFamilyNamespace
        )

        displayName = Self.string(
            named: "CFBundleDisplayName",
            in: info,
            fallback: Self.string(named: "CFBundleName", in: info, fallback: "Tracexy")
        )
        familyNamespace = fallbackFamilyNamespace
        appBundleIdentifier = fallbackAppBundleIdentifier
        helperBundleIdentifier = Self.string(
            named: "TracexyHelperBundleIdentifier",
            in: info,
            fallback: "com.amunx.tracexy.helper"
        )
        helperMachServiceName = Self.string(
            named: "TracexyHelperMachServiceName",
            in: info,
            fallback: "com.amunx.tracexy.helper"
        )
        helperPlistName = Self.string(
            named: "TracexyHelperPlistName",
            in: info,
            fallback: "com.amunx.tracexy.helper.plist"
        )
        defaultsPrefix = Self.string(
            named: "TracexyDefaultsPrefix",
            in: info,
            fallback: fallbackAppBundleIdentifier
        )
        notificationPrefix = Self.string(
            named: "TracexyNotificationPrefix",
            in: info,
            fallback: defaultsPrefix
        )
        logSubsystem = Self.string(
            named: "TracexyLogSubsystem",
            in: info,
            fallback: appBundleIdentifier
        )
        appSupportDirectoryName = Self.string(
            named: "TracexyAppSupportDirectoryName",
            in: info,
            fallback: fallbackAppBundleIdentifier
        )
        sharedSupportDirectoryName = Self.string(
            named: "TracexySharedSupportDirectoryName",
            in: info,
            fallback: "com.amunx.tracexy"
        )
        sharedCertificateLabelPrefix = Self.string(
            named: "TracexySharedCertificateLabelPrefix",
            in: info,
            fallback: "com.amunx.tracexy.rootCA"
        )
        sharedUTTypePrefix = Self.string(
            named: "TracexySharedUTTypePrefix",
            in: info,
            fallback: "com.amunx.tracexy"
        )

        let callers = Self.string(
            named: "TracexyAllowedCallerIdentifiers",
            in: info,
            fallback: appBundleIdentifier
        )
        allowedCallerIdentifiers = callers
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
    }

    // MARK: Internal

    static let current = TracexyIdentity(bundle: .main)

    static var isRunningTests: Bool {
        let environment = ProcessInfo.processInfo.environment
        let arguments = ProcessInfo.processInfo.arguments
        return NSClassFromString("XCTestCase") != nil
            || NSClassFromString("XCTest.XCTestCase") != nil
            || NSClassFromString("Testing.Test") != nil
            || !(environment["XCTestConfigurationFilePath"] ?? "").isEmpty
            || environment.keys.contains { $0.hasPrefix("XCTest") }
            || arguments.contains { $0.contains(".xctest") || $0.contains("XCTest") }
    }

    let displayName: String
    let familyNamespace: String
    let appBundleIdentifier: String
    let helperBundleIdentifier: String
    let helperMachServiceName: String
    let helperPlistName: String
    let allowedCallerIdentifiers: [String]
    let defaultsPrefix: String
    let notificationPrefix: String
    let logSubsystem: String
    let appSupportDirectoryName: String
    let sharedSupportDirectoryName: String
    let sharedCertificateLabelPrefix: String
    let sharedUTTypePrefix: String

    var rootCACertificateLabel: String {
        sharedCertificateLabelPrefix
    }

    var rootCAKeyLabel: String {
        "\(sharedCertificateLabelPrefix).key"
    }

    var sessionUTTypeIdentifier: String {
        "\(sharedUTTypePrefix).session"
    }

    var harUTTypeIdentifier: String {
        "\(sharedUTTypePrefix).har"
    }

    func defaultsKey(_ suffix: String) -> String {
        "\(defaultsPrefix).\(suffix)"
    }

    func notificationName(_ suffix: String) -> Notification.Name {
        Notification.Name("\(notificationPrefix).\(suffix)")
    }

    func pluginStoragePrefix(pluginID: String) -> String {
        "\(defaultsPrefix).plugin.\(pluginID).storage."
    }

    func pluginRuntimePrefix(pluginID: String) -> String {
        "\(defaultsPrefix).plugin.\(pluginID)"
    }

    func pluginConfigPrefix(pluginID: String) -> String {
        "\(defaultsPrefix).plugin.\(pluginID).config."
    }

    func pluginEnabledKey(pluginID: String) -> String {
        defaultsKey("plugin.\(pluginID).enabled")
    }

    func appSupportDirectory(fileManager: FileManager = .default) -> URL {
        if Self.isRunningTests {
            return Self.temporaryDirectory(
                named: appSupportDirectoryName,
                fileManager: fileManager
            )
        }
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return appSupport.appendingPathComponent(appSupportDirectoryName, isDirectory: true)
    }

    func appSupportPath(_ relativePath: String, fileManager: FileManager = .default) -> URL {
        appSupportDirectory(fileManager: fileManager).appendingPathComponent(relativePath)
    }

    func temporaryAppSupportDirectory(fileManager: FileManager = .default) -> URL {
        Self.temporaryDirectory(
            named: appSupportDirectoryName,
            fileManager: fileManager
        )
    }

    func sharedSupportDirectory(fileManager: FileManager = .default) -> URL {
        if Self.isRunningTests {
            return Self.temporaryDirectory(
                named: sharedSupportDirectoryName,
                fileManager: fileManager
            )
        }
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return appSupport.appendingPathComponent(sharedSupportDirectoryName, isDirectory: true)
    }

    func sharedSupportPath(_ relativePath: String, fileManager: FileManager = .default) -> URL {
        sharedSupportDirectory(fileManager: fileManager).appendingPathComponent(relativePath)
    }

    // MARK: Private

    private static let testRunToken: String = {
        let environment = ProcessInfo.processInfo.environment
        if let explicit = environment["TRACEXY_TEST_RUN_TOKEN"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !explicit.isEmpty
        {
            return explicit
        }

        if let configurationPath = environment["XCTestConfigurationFilePath"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !configurationPath.isEmpty
        {
            return "xc-\(stableHash(configurationPath))"
        }

        return UUID().uuidString
    }()

    private static func string(
        named key: String,
        in info: [String: Any],
        fallback: String
    )
        -> String
    {
        let value = (info[key] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let value, !value.isEmpty {
            return value
        }
        return fallback
    }

    private static func temporaryDirectory(
        named directoryName: String,
        fileManager: FileManager
    )
        -> URL
    {
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("tracexy-tests-\(testRunToken)", isDirectory: true)
        return root.appendingPathComponent(directoryName, isDirectory: true)
    }

    private static func stableHash(_ value: String) -> String {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        return String(hash, radix: 16, uppercase: false)
    }
}
