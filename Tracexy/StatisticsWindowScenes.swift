import SwiftUI

// MARK: - StatisticsWindowScenes

/// The Statistics menu's windows. Each is a regular auxiliary window on the same
/// terms as every other: remounted on the Project identity, disabled while
/// Projects hydrate or a Project change is pending, never restored and never
/// opened by an external event. Kept apart from ``TracexyApp`` so the app's
/// composition file stays readable as the Statistics family grows.
struct StatisticsWindowScenes: Scene {
    // MARK: Internal

    let coordinator: MainContentCoordinator
    let colorScheme: ColorScheme?

    var body: some Scene {
        findingsScene
        conversationsScene
        endpointsScene
        protocolHierarchyScene
        packetLengthsScene
        ioGraphScene
        flowGraphScene
        valueDistributionScene
        fieldPlotScene
        httpStatisticsScene
        ipStatisticsScene
        dnsStatisticsScene
        rtpStreamsScene
        multicastStreamsScene
        voipCallsScene
        sipStatisticsScene
        serviceResponseTimeScene
    }

    // MARK: Private

    /// Statistics ▸ I/O Graph, packets and bytes per second over the open capture.
    private var ioGraphScene: some Scene {
        let base = Window("I/O Graph", id: TracexyApp.ioGraphWindowID) {
            TrafficRateGraphWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 860, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Findings (Wireshark's Expert Information), on the same terms as
    /// Resolved Addresses.
    private var findingsScene: some Scene {
        let base = Window("Findings", id: TracexyApp.findingsWindowID) {
            FindingsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 860, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Conversations, on the same terms as Resolved Addresses.
    private var conversationsScene: some Scene {
        let base = Window("Conversations", id: TracexyApp.conversationsWindowID) {
            ConversationsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 1_080, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Endpoints, on the same terms as Resolved Addresses.
    private var endpointsScene: some Scene {
        let base = Window("Endpoints", id: TracexyApp.endpointsWindowID) {
            EndpointsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 960, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Protocol Hierarchy, on the same terms as Resolved Addresses.
    private var protocolHierarchyScene: some Scene {
        let base = Window("Protocol Hierarchy", id: TracexyApp.protocolHierarchyWindowID) {
            ProtocolHierarchyWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 640, height: 440)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Packet Lengths, on the same terms as Resolved Addresses.
    private var packetLengthsScene: some Scene {
        let base = Window("Packet Lengths", id: TracexyApp.packetLengthsWindowID) {
            PacketLengthsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 700, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Flow Graph, on the same terms as All Frames.
    private var flowGraphScene: some Scene {
        let base = Window("Flow Graph", id: TracexyApp.flowGraphWindowID) {
            FlowGraphWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 1_000, height: 620)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Value Distribution, one field counted over a rescan of the capture.
    private var valueDistributionScene: some Scene {
        let base = Window("Value Distribution", id: TracexyApp.valueDistributionWindowID) {
            ValueDistributionWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 640, height: 460)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Plot, one field's numeric values over time from a rescan.
    private var fieldPlotScene: some Scene {
        let base = Window("Plot", id: TracexyApp.fieldPlotWindowID) {
            FieldPlotWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 820, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ HTTP, over the All Frames scan like Flow Graph.
    private var httpStatisticsScene: some Scene {
        let base = Window("HTTP Statistics", id: TracexyApp.httpStatisticsWindowID) {
            HTTPStatisticsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 560)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ IP Statistics, Wireshark's IPv4 and IPv6 trees over the All Frames scan.
    private var ipStatisticsScene: some Scene {
        let base = Window("IP Statistics", id: TracexyApp.ipStatisticsWindowID) {
            IPStatisticsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 520)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ DNS, over the All Frames scan like Statistics ▸ HTTP.
    private var dnsStatisticsScene: some Scene {
        let base = Window("DNS Statistics", id: TracexyApp.dnsStatisticsWindowID) {
            DNSStatisticsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 620)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ RTP Streams, over the All Frames scan.
    private var rtpStreamsScene: some Scene {
        let base = Window("RTP Streams", id: TracexyApp.rtpStreamsWindowID) {
            RTPStreamsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 980, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ UDP Multicast Streams, over the All Frames scan.
    private var multicastStreamsScene: some Scene {
        let base = Window("UDP Multicast Streams", id: TracexyApp.multicastStreamsWindowID) {
            MulticastStreamsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 1_080, height: 480)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ VoIP Calls, over the All Frames scan.
    private var voipCallsScene: some Scene {
        let base = Window("VoIP Calls", id: TracexyApp.voipCallsWindowID) {
            VoIPCallsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 800, height: 420)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ SIP, over the All Frames scan like Statistics ▸ DNS.
    private var sipStatisticsScene: some Scene {
        let base = Window("SIP Statistics", id: TracexyApp.sipStatisticsWindowID) {
            SIPStatisticsWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 720, height: 460)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }

    /// Statistics ▸ Service Response Time, Wireshark's SRT tables over the All Frames scan.
    private var serviceResponseTimeScene: some Scene {
        let base = Window("Service Response Time", id: TracexyApp.serviceResponseTimeWindowID) {
            ServiceResponseTimeWindow(coordinator: coordinator)
                .id(coordinator.projectStore.activeProjectID)
                .disabled(!coordinator.hasHydratedProjects || coordinator.projectTransitionStatus.isPending)
                .preferredColorScheme(colorScheme)
        }
        .defaultSize(width: 760, height: 420)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unifiedCompact)
        .handlesExternalEvents(matching: [])
        if #available(macOS 15.0, *) {
            return base.restorationBehavior(.disabled)
        } else {
            return base
        }
    }
}
