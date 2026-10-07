import Foundation
import SwiftUI

// MARK: - PacketDetailOptions

/// How the decode tree presents a frame, per Project: View ▸ Validate Checksums.
@MainActor
@Observable
final class PacketDetailOptions {
    // MARK: Internal

    static let zoomRange = -3 ... 8

    static let maximumFrameColumns = 4

    /// Off by default, as in Wireshark: a frame sent from this Mac is often captured
    /// before the network card fills its checksums in.
    var validateChecksums = false {
        didSet {
            defaults?.set(validateChecksums, forKey: ProjectScopedSettingsKeys.validateChecksums)
        }
    }

    /// View ▸ Zoom In / Zoom Out / Actual Size: points added to packet text.
    var textZoom = 0 {
        didSet {
            defaults?.set(textZoom, forKey: ProjectScopedSettingsKeys.packetTextZoom)
        }
    }

    /// The bytes pane's "Show as": hexadecimal (16 bytes a row) or bits (8).
    var byteDumpStyle: ByteDumpStyle = .hex {
        didSet {
            defaults?.set(byteDumpStyle.rawValue, forKey: ProjectScopedSettingsKeys.byteDumpStyle)
        }
    }

    /// View ▸ Name Resolution ▸ Resolve Network Addresses: frame lists show names
    /// (see ``FrameAddressNames``). Off by default, as in Wireshark.
    var resolvesNetworkAddresses = false {
        didSet {
            defaults?.set(resolvesNetworkAddresses, forKey: ProjectScopedSettingsKeys.resolveNetworkAddresses)
        }
    }

    /// Apply as Column: decode-tree fields shown as All Frames columns, in the order
    /// applied, at most ``maximumFrameColumns``.
    var frameColumns: [FieldKey] = [] {
        didSet {
            defaults?.set(
                frameColumns.map { "\($0.proto.rawValue)\u{1F}\($0.name)" },
                forKey: ProjectScopedSettingsKeys.frameColumns
            )
        }
    }

    var canZoomIn: Bool {
        textZoom < Self.zoomRange.upperBound
    }

    var canZoomOut: Bool {
        textZoom > Self.zoomRange.lowerBound
    }

    /// Adds `key` as a column, or removes it when it is one; `false` when full.
    @discardableResult
    func toggleFrameColumn(_ key: FieldKey) -> Bool {
        if let index = frameColumns.firstIndex(of: key) {
            frameColumns.remove(at: index)
            return true
        }
        guard frameColumns.count < Self.maximumFrameColumns else {
            return false
        }
        frameColumns.append(key)
        return true
    }

    func zoom(by step: Int) {
        textZoom = min(Self.zoomRange.upperBound, max(Self.zoomRange.lowerBound, textZoom + step))
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = nil
        validateChecksums = defaults.bool(forKey: ProjectScopedSettingsKeys.validateChecksums)
        textZoom = min(Self.zoomRange.upperBound, max(
            Self.zoomRange.lowerBound, defaults.integer(forKey: ProjectScopedSettingsKeys.packetTextZoom)
        ))
        resolvesNetworkAddresses = defaults.bool(forKey: ProjectScopedSettingsKeys.resolveNetworkAddresses)
        byteDumpStyle = defaults.string(forKey: ProjectScopedSettingsKeys.byteDumpStyle)
            .flatMap(ByteDumpStyle.init(rawValue:)) ?? .hex
        frameColumns = (defaults.stringArray(forKey: ProjectScopedSettingsKeys.frameColumns) ?? [])
            .compactMap { stored in
                let parts = stored.split(separator: "\u{1F}", maxSplits: 1).map(String.init)
                guard parts.count == 2, let proto = ProtocolKind(rawValue: parts[0]) else {
                    return nil
                }
                return FieldKey(proto: proto, name: parts[1])
            }
            .prefix(Self.maximumFrameColumns).map(\.self)
        self.defaults = defaults
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?
}

// MARK: - ByteDumpStyle

/// How the bytes pane writes each byte, as Wireshark's "…as Hexadecimal / …as Bits".
nonisolated enum ByteDumpStyle: String, CaseIterable, Identifiable, Sendable {
    case hex
    case bits

    // MARK: Internal

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .hex: String(localized: "Hexadecimal")
        case .bits: String(localized: "Bits")
        }
    }

    var bytesPerRow: Int {
        self == .hex ? 16 : 8
    }
}

// MARK: - Packet text zoom in the environment

extension EnvironmentValues {
    /// View ▸ Zoom's step for packet text, for views without the coordinator.
    @Entry var packetTextZoom = 0
    /// The bytes pane's Show as choice, for views without the coordinator.
    @Entry var byteDumpStyle = ByteDumpStyle.hex
}
