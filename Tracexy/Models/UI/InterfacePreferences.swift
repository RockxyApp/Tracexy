import Foundation
import Observation

// MARK: - InterfaceSettings

/// This Mac's own interface choices, as Wireshark's Manage Interfaces keeps them:
/// which interfaces the capture menus list, the name each is shown by, and a note.
/// An interface belongs to the Mac, not to a Project, so these are app-wide.
nonisolated struct InterfaceSettings: Codable, Equatable, Sendable {
    static let maximumNameLength = 64
    static let maximumCommentLength = 200
    /// Interfaces remembered at most; macOS rarely has more than a few dozen.
    static let maximumEntries = 256

    var hidden: Set<String> = []
    var friendlyNames: [String: String] = [:]
    var comments: [String: String] = [:]
    /// Non-default BPF optimizer choices keyed by this Mac's interface identifier.
    /// Missing entries retain libpcap's historical optimized behavior.
    var bpfOptimization: [String: Bool] = [:]
    /// Named pipes listed as capture sources, by absolute path, in the order added.
    var pipes: [String] = []

    /// Paths a pipe may have: absolute, and short enough to be a capture interface.
    static func pipePath(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = (trimmed as NSString).expandingTildeInPath
        guard path.hasPrefix("/"), path.count <= CaptureConfiguration.maxInterfaceLength else {
            return nil
        }
        return (path as NSString).standardizingPath
    }

    /// Trimmed and bounded; blank removes the value.
    static func cleaned(_ text: String, limit: Int) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\n", with: " ")
        return trimmed.isEmpty ? nil : String(trimmed.prefix(limit))
    }
}

// MARK: - InterfaceSettings + Codable

extension InterfaceSettings {
    private enum CodingKeys: String, CodingKey {
        case hidden
        case friendlyNames
        case comments
        case bpfOptimization
        case pipes
    }

    /// Settings saved before pipes existed decode with none.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hidden = try container.decodeIfPresent(Set<String>.self, forKey: .hidden) ?? []
        friendlyNames = try container.decodeIfPresent([String: String].self, forKey: .friendlyNames) ?? [:]
        comments = try container.decodeIfPresent([String: String].self, forKey: .comments) ?? [:]
        var optimizerOverrides = try container.decodeIfPresent([String: Bool].self, forKey: .bpfOptimization) ?? [:]
        if optimizerOverrides.count > Self.maximumEntries {
            for key in optimizerOverrides.keys.sorted().dropFirst(Self.maximumEntries) {
                optimizerOverrides.removeValue(forKey: key)
            }
        }
        bpfOptimization = optimizerOverrides
        pipes = try container.decodeIfPresent([String].self, forKey: .pipes) ?? []
    }
}

// MARK: - NetworkInterfaces + InterfaceSettings

extension NetworkInterfaces {
    /// The pipes `settings` lists, each up while a named pipe exists at its path.
    static func pipes(_ settings: InterfaceSettings) -> [NetworkInterface] {
        settings.pipes.map { path in
            NetworkInterface(
                id: path, displayName: (path as NSString).lastPathComponent, category: .pipes, ipv4: nil,
                isUp: PipeCapture.problem(with: path) == nil, isLoopback: false
            )
        }
    }

    /// `interfaces` as the capture menus show them: hidden ones left out — except
    /// `keeping`, the interface in use, which is always listed — and each shown by
    /// its friendly name when it has one.
    static func applying(
        _ settings: InterfaceSettings,
        to interfaces: [NetworkInterface],
        keeping: String?
    )
        -> [NetworkInterface]
    {
        interfaces.compactMap { interface in
            guard !settings.hidden.contains(interface.id) || interface.id == keeping else {
                return nil
            }
            guard let name = settings.friendlyNames[interface.id] else {
                return interface
            }
            return NetworkInterface(
                id: interface.id, displayName: name, category: interface.category, ipv4: interface.ipv4,
                isUp: interface.isUp, isLoopback: interface.isLoopback
            )
        }
    }

    /// The groups the capture menus list under `settings`.
    static func grouped(_ settings: InterfaceSettings, keeping: String?, includingPipes: Bool = false)
        -> [InterfaceGroup]
    {
        let all = applying(settings, to: available() + (includingPipes ? pipes(settings) : []), keeping: keeping)
        return InterfaceCategory.allCases.compactMap { category in
            let items = all.filter { $0.category == category }
            return items.isEmpty ? nil : InterfaceGroup(category: category, interfaces: items)
        }
    }
}

// MARK: - InterfacePreferences

/// The app-wide store for ``InterfaceSettings``: Capture ▸ Manage Interfaces edits
/// it and every interface menu reads it.
@Observable
final class InterfacePreferences {
    // MARK: Lifecycle

    init(defaults: UserDefaults) {
        self.defaults = defaults
        if let data = defaults.data(forKey: SettingsKeys.interfaceSettings),
           let decoded = try? JSONDecoder().decode(InterfaceSettings.self, from: data)
        {
            settings = decoded
        }
    }

    // MARK: Internal

    static let shared = InterfacePreferences(defaults: TracexyIdentity.interfaceDefaults)

    private(set) var settings = InterfaceSettings()

    func setShown(_ isShown: Bool, for id: String) {
        if isShown {
            settings.hidden.remove(id)
        } else if settings.hidden.count < InterfaceSettings.maximumEntries {
            settings.hidden.insert(id)
        }
        save()
    }

    func setFriendlyName(_ text: String, for id: String) {
        update(
            \.friendlyNames,
            id: id,
            value: InterfaceSettings.cleaned(text, limit: InterfaceSettings.maximumNameLength)
        )
    }

    func setComment(_ text: String, for id: String) {
        update(
            \.comments,
            id: id,
            value: InterfaceSettings.cleaned(text, limit: InterfaceSettings.maximumCommentLength)
        )
    }

    func optimizesBPF(for id: String) -> Bool {
        settings.bpfOptimization[id] ?? true
    }

    func setBPFOptimization(_ isEnabled: Bool, for id: String) {
        guard optimizesBPF(for: id) != isEnabled else {
            return
        }
        if isEnabled {
            settings.bpfOptimization.removeValue(forKey: id)
        } else if settings.bpfOptimization.count < InterfaceSettings.maximumEntries {
            settings.bpfOptimization[id] = false
        } else {
            return
        }
        save()
    }

    /// Adds a pipe by path; returns why it was not added, if it was not.
    @discardableResult
    func addPipe(_ text: String) -> String? {
        guard let path = InterfaceSettings.pipePath(text) else {
            return String(localized: "Enter the full path of a named pipe, such as /tmp/remote.fifo.")
        }
        guard !settings.pipes.contains(path) else {
            return nil
        }
        guard settings.pipes.count < InterfaceSettings.maximumEntries else {
            return String(localized: "Remove a pipe before adding another.")
        }
        settings.pipes.append(path)
        save()
        return nil
    }

    func removePipes(_ paths: Set<String>) {
        settings.pipes.removeAll { paths.contains($0) }
        save()
    }

    func showAll() {
        settings.hidden = []
        save()
    }

    // MARK: Private

    @ObservationIgnored private let defaults: UserDefaults

    private func update(_ path: WritableKeyPath<InterfaceSettings, [String: String]>, id: String, value: String?) {
        guard settings[keyPath: path][id] != value else {
            return
        }
        if value == nil || settings[keyPath: path][id] != nil
            || settings[keyPath: path].count < InterfaceSettings.maximumEntries
        {
            settings[keyPath: path][id] = value
            save()
        }
    }

    private func save() {
        if let data = try? JSONEncoder().encode(settings) {
            defaults.set(data, forKey: SettingsKeys.interfaceSettings)
        }
    }
}
