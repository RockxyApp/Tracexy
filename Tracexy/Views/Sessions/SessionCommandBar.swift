import SwiftUI

// MARK: - SessionCommandKind

enum SessionCommandKind: String, CaseIterable {
    case followLive
    case jumpToLatest
    case investigate
    case clearCapture
    case saveCapture
    case newFocusSet
    case noiseControl
    case restoreRemovedSessions
    case advancedFilters
}

// MARK: - SessionCommandDescriptor

/// Value-typed command presentation shared by every responsive command-strip
/// width. The footer never consumes this catalog; it is telemetry-only.
struct SessionCommandDescriptor: Identifiable, Equatable {
    enum Placement {
        case immediate
        case overflow
    }

    let id: SessionCommandKind
    let title: String
    let systemImage: String
    let help: String
    let placement: Placement
    let priority: Int
    let isEnabled: Bool
    let isActive: Bool
    let isDestructive: Bool
}

// MARK: - SessionCommandBarModel

enum SessionCommandBarModel {
    static func commands(
        isFollowingLive: Bool,
        hasVisibleSessions: Bool,
        hasCaptureData: Bool,
        canSaveCapture: Bool,
        canAddFocusSet: Bool,
        isNoiseControlActive: Bool,
        removedSessionCount: Int,
        activeFilterRuleCount: Int,
        isAdvancedFilterVisible: Bool,
        isInvestigationActive: Bool
    )
        -> [SessionCommandDescriptor]
    {
        [
            SessionCommandDescriptor(
                id: .followLive,
                title: "Follow Live",
                systemImage: "dot.radiowaves.right",
                help: isFollowingLive
                    ? "Follow Live is on for this workspace. Select, navigate, scroll, or click again to stop."
                    : "Keep the newest visible session selected as it arrives.",
                placement: .immediate,
                priority: 0,
                isEnabled: true,
                isActive: isFollowingLive,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .jumpToLatest,
                title: "Jump to Latest",
                systemImage: "arrow.down.to.line",
                help: "Select the latest visible row without changing Follow Live.",
                placement: .immediate,
                priority: 1,
                isEnabled: hasVisibleSessions,
                isActive: false,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .investigate,
                title: isInvestigationActive ? "Investigate (on)" : "Investigate",
                systemImage: "scope",
                help: "Build a capture-local query from typed session and evidence fields.",
                placement: .immediate,
                priority: 2,
                isEnabled: hasCaptureData,
                isActive: isInvestigationActive,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .clearCapture,
                title: "Clear Capture Data…",
                systemImage: "trash",
                help: "Remove decoded sessions, retained packets, capture statistics, and throughput history.",
                placement: .immediate,
                priority: 3,
                isEnabled: hasCaptureData,
                isActive: false,
                isDestructive: true
            ),
            SessionCommandDescriptor(
                id: .saveCapture,
                title: "Save Capture",
                systemImage: "square.and.arrow.down",
                help: "Save the complete current capture to a .pcapng file.",
                placement: .immediate,
                priority: 4,
                isEnabled: canSaveCapture,
                isActive: false,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .newFocusSet,
                title: "New Focus Set",
                systemImage: "scope",
                help: "Create a focus set from the current advanced filter rules.",
                placement: .immediate,
                priority: 5,
                isEnabled: canAddFocusSet,
                isActive: false,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .noiseControl,
                title: "Noise Control",
                systemImage: "speaker.slash",
                help: "Mute noisy hosts or protocols so the list stops flooding.",
                placement: .immediate,
                priority: 6,
                isEnabled: true,
                isActive: isNoiseControlActive,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .restoreRemovedSessions,
                title: "Restore Removed Sessions (\(removedSessionCount))",
                systemImage: "arrow.uturn.backward",
                help: "Restore every session removed from the current capture views.",
                placement: .overflow,
                priority: 7,
                isEnabled: removedSessionCount > 0,
                isActive: false,
                isDestructive: false
            ),
            SessionCommandDescriptor(
                id: .advancedFilters,
                title: activeFilterRuleCount > 0 ? "Advanced Filters (on)" : "Advanced Filters",
                systemImage: "line.3.horizontal.decrease.circle",
                help: "Show the advanced filter rule builder.",
                placement: .overflow,
                priority: 8,
                isEnabled: true,
                isActive: isAdvancedFilterVisible || activeFilterRuleCount > 0,
                isDestructive: false
            ),
        ]
    }
}

// MARK: - SessionCommandBar

/// Immediate investigation controls above the filter stack. Each width variant
/// reads the same ordered catalog and moves hidden commands into the same
/// structured overflow menu, preserving intent rather than degrading to
/// unlabeled icon-only state.
struct SessionCommandBar: View {
    // MARK: Internal

    let descriptors: [SessionCommandDescriptor]
    let onAction: (SessionCommandKind) -> Void

    var body: some View {
        ViewThatFits(in: .horizontal) {
            commandRow(immediateCount: 6)
            commandRow(immediateCount: 4)
            commandRow(immediateCount: 2)
            commandRow(immediateCount: 1)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingS)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) { Divider() }
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Private

    private var immediateDescriptors: [SessionCommandDescriptor] {
        descriptors.filter { $0.placement == .immediate }
    }

    private var overflowDescriptors: [SessionCommandDescriptor] {
        descriptors.filter { $0.placement == .overflow }
    }

    private func commandRow(immediateCount: Int) -> some View {
        let visible = Array(immediateDescriptors.prefix(immediateCount))
        let hidden = Array(immediateDescriptors.dropFirst(immediateCount)) + overflowDescriptors
        return HStack(spacing: Theme.Metrics.spacingM) {
            ForEach(visible) { descriptor in
                commandButton(descriptor)
            }
            Spacer(minLength: Theme.Metrics.spacingL)
            moreMenu(hidden)
        }
    }

    @ViewBuilder
    private func commandButton(_ descriptor: SessionCommandDescriptor) -> some View {
        if descriptor.id == .followLive {
            Toggle(isOn: Binding(
                get: { descriptor.isActive },
                set: { _ in onAction(descriptor.id) }
            )) {
                Label(descriptor.title, systemImage: descriptor.systemImage)
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .toggleStyle(.button)
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
            .accessibilityLabel(descriptor.title)
            .accessibilityValue(descriptor.isActive ? "On" : "Off")
        } else {
            Button {
                onAction(descriptor.id)
            } label: {
                Label(descriptor.title, systemImage: descriptor.systemImage)
                    .font(Theme.Typography.caption)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
            .accessibilityLabel(descriptor.title)
            .accessibilityValue(descriptor.isActive ? "Active" : "")
        }
    }

    private func moreMenu(_ hidden: [SessionCommandDescriptor]) -> some View {
        Menu {
            ForEach(hidden) { descriptor in
                menuItem(descriptor)
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.system(size: Theme.Icon.medium))
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("More session actions")
        .accessibilityLabel("More Session Actions")
    }

    @ViewBuilder
    private func menuItem(_ descriptor: SessionCommandDescriptor) -> some View {
        if descriptor.id == .followLive {
            Toggle(isOn: Binding(
                get: { descriptor.isActive },
                set: { _ in onAction(descriptor.id) }
            )) {
                Label(descriptor.title, systemImage: descriptor.systemImage)
            }
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
        } else {
            Button(role: descriptor.isDestructive ? .destructive : nil) {
                onAction(descriptor.id)
            } label: {
                Label(
                    descriptor.title,
                    systemImage: descriptor.isActive ? "checkmark" : descriptor.systemImage
                )
            }
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
        }
    }
}
