import SwiftUI

// MARK: - CaptureReadinessLevel

enum CaptureReadinessLevel: Equatable {
    case ready
    case attention
    case neutral
}

// MARK: - CaptureReadinessItem

struct CaptureReadinessItem: Identifiable, Equatable {
    let label: String
    let value: String
    let systemImage: String
    let level: CaptureReadinessLevel
    var isMonospaced = false

    var id: String {
        label
    }
}

// MARK: - CaptureReadinessPresentation

/// Pure, source-backed decisions for the centered toolbar popover. Unknown and
/// stopped states stay explicit; a zero count is reported only for stages the
/// current live path actually accounts for.
struct CaptureReadinessPresentation: Equatable {
    // MARK: Lifecycle

    init(
        displayState: CaptureDisplayState,
        captureError: String?,
        interfaceID: String,
        interface: NetworkInterface?,
        configuration: CaptureConfiguration,
        retentionCapacity: Int,
        helperStatus: HelperClient.Status,
        isDirectCapture: Bool,
        captureStatistics: CaptureStatistics?,
        helperDropCount: UInt64,
        retentionEvictionCount: UInt64
    ) {
        title = displayState.title
        description = Self.description(for: displayState, error: captureError)
        systemImage = Self.systemImage(for: displayState)
        actionTitle = displayState == .capturing ? "Stop Capture" : "Start Capture"
        isActionEnabled = displayState != .starting
        items = [
            Self.interfaceItem(id: interfaceID, interface: interface),
            Self.helperItem(status: helperStatus, isDirectCapture: isDirectCapture),
            CaptureReadinessItem(
                label: "Capture filter",
                value: configuration.bpf ?? "All traffic",
                systemImage: configuration.bpf == nil ? "line.3.horizontal.decrease.circle" : "text.magnifyingglass",
                level: .neutral,
                isMonospaced: configuration.bpf != nil
            ),
            CaptureReadinessItem(
                label: "Packet snapshot",
                value: "\(configuration.snapLength.formatted()) bytes · "
                    + (configuration.promiscuous ? "promiscuous" : "standard"),
                systemImage: "shippingbox",
                level: .neutral
            ),
            CaptureReadinessItem(
                label: "Memory window",
                value: "\(retentionCapacity.formatted()) recent frames",
                systemImage: "memorychip",
                level: .neutral
            ),
            Self.kernelLossItem(displayState: displayState, statistics: captureStatistics),
            Self.helperLossItem(displayState: displayState, count: helperDropCount),
            Self.retentionItem(displayState: displayState, count: retentionEvictionCount),
        ]
    }

    // MARK: Internal

    let title: String
    let description: String
    let systemImage: String
    let actionTitle: String
    let isActionEnabled: Bool
    let items: [CaptureReadinessItem]

    // MARK: Private

    private static func description(for state: CaptureDisplayState, error: String?) -> String {
        switch state {
        case .stopped:
            "No new packets are being captured. Review the source below before starting."
        case .starting:
            "Opening and validating the selected packet source."
        case .capturing:
            "Packets are being captured locally on the selected interface."
        case .error:
            error ?? "Capture needs attention before it can continue."
        }
    }

    private static func systemImage(for state: CaptureDisplayState) -> String {
        switch state {
        case .stopped: "stop.circle"
        case .starting: "hourglass.circle"
        case .capturing: "record.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        }
    }

    private static func interfaceItem(id: String, interface: NetworkInterface?) -> CaptureReadinessItem {
        guard let interface else {
            return CaptureReadinessItem(
                label: "Interface",
                value: "\(id) · unavailable",
                systemImage: "network.slash",
                level: .attention,
                isMonospaced: true
            )
        }
        let address = interface.ipv4.map { " · \($0)" } ?? ""
        return CaptureReadinessItem(
            label: "Interface",
            value: "\(interface.menuLabel) · \(interface.isUp ? "up" : "not connected")\(address)",
            systemImage: interface.symbol,
            level: interface.isUp ? .ready : .attention,
            isMonospaced: false
        )
    }

    private static func helperItem(
        status: HelperClient.Status,
        isDirectCapture: Bool
    )
        -> CaptureReadinessItem
    {
        if isDirectCapture {
            return CaptureReadinessItem(
                label: "Capture path",
                value: "Direct development mode",
                systemImage: "wrench.and.screwdriver",
                level: .neutral
            )
        }
        let value: String
        let level: CaptureReadinessLevel
        switch status {
        case .installedCompatible:
            value = "Helper ready"
            level = .ready
        case .installedOutdated:
            value = "Ready · update available"
            level = .ready
        case .requiresApproval:
            value = "Approval needed"
            level = .attention
        case .installedIncompatible:
            value = "Incompatible · update needed"
            level = .attention
        case .unreachable:
            value = "Registered but unreachable"
            level = .attention
        case .signingMismatch:
            value = "Code-signing mismatch"
            level = .attention
        case .notInstalled:
            value = "Not installed"
            level = .attention
        case let .failed(reason):
            value = reason
            level = .attention
        }
        return CaptureReadinessItem(
            label: "Capture helper",
            value: value,
            systemImage: level == .ready ? "checkmark.shield.fill" : "exclamationmark.shield.fill",
            level: level
        )
    }

    private static func kernelLossItem(
        displayState: CaptureDisplayState,
        statistics: CaptureStatistics?
    )
        -> CaptureReadinessItem
    {
        guard let statistics else {
            return CaptureReadinessItem(
                label: "Interface drops",
                value: displayState == .capturing ? "Awaiting pcap statistics" : "Unknown while stopped",
                systemImage: "questionmark.circle",
                level: .neutral
            )
        }
        return CaptureReadinessItem(
            label: "Interface drops",
            value: "\(statistics.totalDropped.formatted()) reported",
            systemImage: statistics.totalDropped == 0 ? "checkmark.circle" : "exclamationmark.triangle.fill",
            level: statistics.isLossy ? .attention : .neutral
        )
    }

    private static func helperLossItem(
        displayState: CaptureDisplayState,
        count: UInt64
    )
        -> CaptureReadinessItem
    {
        CaptureReadinessItem(
            label: "Helper drops",
            value: displayState == .capturing ? "\(count.formatted()) reported" : "Not active",
            systemImage: count > 0 ? "exclamationmark.triangle.fill" : "shield",
            level: count > 0 ? .attention : .neutral
        )
    }

    private static func retentionItem(
        displayState: CaptureDisplayState,
        count: UInt64
    )
        -> CaptureReadinessItem
    {
        CaptureReadinessItem(
            label: "Outside memory window",
            value: displayState == .capturing ? "\(count.formatted()) frames" : "Not active",
            systemImage: "rectangle.stack.badge.minus",
            level: .neutral
        )
    }
}

// MARK: - CaptureReadinessPopover

struct CaptureReadinessPopover: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    @Binding var isPresented: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            header
            Divider()
            Grid(
                alignment: .leading,
                horizontalSpacing: Theme.Metrics.spacingL,
                verticalSpacing: Theme.Metrics.spacingM
            ) {
                ForEach(presentation.items) { item in
                    itemRow(item)
                }
            }
            Divider()
            HStack(spacing: Theme.Metrics.spacingM) {
                Button("Capture Settings…") { open(tab: .capture) }
                Button("Helper Settings…") { open(tab: .helper) }
                Spacer()
            }
            .controlSize(.small)
        }
        .padding(16)
        .frame(width: 430)
    }

    // MARK: Private

    @Environment(\.openSettings) private var openSettings

    private var presentation: CaptureReadinessPresentation {
        let interface = NetworkInterfaces.available().first { $0.id == coordinator.captureInterface }
        return CaptureReadinessPresentation(
            displayState: coordinator.captureDisplayState,
            captureError: coordinator.captureError,
            interfaceID: coordinator.captureInterface,
            interface: interface,
            configuration: coordinator.readinessCaptureConfiguration,
            retentionCapacity: coordinator.readinessRetentionCapacity,
            helperStatus: coordinator.helper.status,
            isDirectCapture: MainContentCoordinator.forceDirectCapture,
            captureStatistics: coordinator.captureStatistics,
            helperDropCount: coordinator.helperBufferDropCount,
            retentionEvictionCount: coordinator.retainedFrameEvictionCount
        )
    }

    private var headerColor: Color {
        switch coordinator.captureDisplayState {
        case .stopped: .secondary
        case .starting: .accentColor
        case .capturing: Color(nsColor: .systemGreen)
        case .error: Color(nsColor: .systemRed)
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingL) {
            Image(systemName: presentation.systemImage)
                .font(Theme.Typography.title)
                .foregroundStyle(headerColor)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                Text(presentation.title).font(Theme.Typography.surfaceTitle)
                Text(presentation.description)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: Theme.Metrics.spacingS)
            if coordinator.isStarting {
                ProgressView().controlSize(.small)
            } else {
                Button(presentation.actionTitle) {
                    coordinator.toggleCapture()
                    isPresented = false
                }
                .controlSize(.small)
                .disabled(!presentation.isActionEnabled)
            }
        }
    }

    private func itemRow(_ item: CaptureReadinessItem) -> some View {
        GridRow {
            Text(item.label)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            HStack(spacing: Theme.Metrics.spacingS) {
                Image(systemName: item.systemImage)
                    .foregroundStyle(color(for: item.level))
                    .accessibilityHidden(true)
                Text(item.value)
                    .font(item.isMonospaced ? Theme.Typography.monoSmall : Theme.Typography.bodyMedium)
                    .lineLimit(2)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(item.label): \(item.value)")
    }

    private func color(for level: CaptureReadinessLevel) -> Color {
        switch level {
        case .ready: Color(nsColor: .systemGreen)
        case .attention: Color(nsColor: .systemOrange)
        case .neutral: .secondary
        }
    }

    private func open(tab: SettingsTab) {
        UserDefaults.standard.set(tab.rawValue, forKey: SettingsKeys.selectedSettingsTab)
        isPresented = false
        openSettings()
    }
}
