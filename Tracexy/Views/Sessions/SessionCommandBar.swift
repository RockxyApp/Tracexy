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
/// width. Standard macOS actions can use compact symbols while domain-specific
/// actions keep labels. The footer never consumes this catalog; it is telemetry-only.
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
                placement: .overflow,
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
                placement: .overflow,
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
                placement: .overflow,
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
                placement: .overflow,
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

/// Rockxy-inspired embedded command cluster. Its immediate vocabulary and order
/// never change with width: Follow Live, Jump Latest, a divider, Clear Capture,
/// then More. Less-frequent or domain-specific actions live in labelled sections
/// of the stable overflow menu beside the search controls.
struct SessionCommandBar: View {
    // MARK: Internal

    let descriptors: [SessionCommandDescriptor]
    let onAction: (SessionCommandKind) -> Void

    var body: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            commandButton(.followLive)
            commandButton(.jumpToLatest)
            commandDivider
            commandButton(.clearCapture)
            moreMenu
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    // MARK: Private

    private var moreMenu: some View {
        Menu {
            Section("Analysis") {
                menuItems([.investigate, .advancedFilters, .newFocusSet])
            }
            Section("Capture Data") {
                menuItems([.saveCapture])
            }
            Section("View") {
                menuItems([.noiseControl, .restoreRemovedSessions])
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.system(size: Theme.Icon.medium, weight: .medium))
                .foregroundStyle(Color(nsColor: .secondaryLabelColor))
                .frame(
                    width: Theme.Metrics.sessionShelfControlLength,
                    height: Theme.Metrics.sessionShelfControlLength
                )
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("More session actions")
        .accessibilityLabel("More Session Actions")
    }

    private var commandDivider: some View {
        Divider()
            .frame(height: 16)
            .padding(.horizontal, 4)
    }

    @ViewBuilder
    private func commandButton(_ kind: SessionCommandKind) -> some View {
        if let descriptor = descriptor(kind) {
            commandButton(descriptor)
        }
    }

    @ViewBuilder
    private func commandButton(_ descriptor: SessionCommandDescriptor) -> some View {
        if descriptor.id == .followLive {
            Toggle(isOn: Binding(
                get: { descriptor.isActive },
                set: { _ in onAction(descriptor.id) }
            )) {
                commandLabel(descriptor)
            }
            .toggleStyle(.button)
            .tracexyGlassButtonStyle()
            .controlSize(.small)
            .overlay {
                if descriptor.isActive {
                    Capsule(style: .continuous)
                        .strokeBorder(
                            Color.accentColor.opacity(Theme.Glass.activeStrokeOpacity),
                            lineWidth: 1
                        )
                        .allowsHitTesting(false)
                }
            }
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
            .accessibilityLabel(descriptor.title)
            .accessibilityValue(descriptor.isActive ? "On" : "Off")
        } else {
            Button {
                onAction(descriptor.id)
            } label: {
                commandLabel(descriptor)
            }
            .tracexyGlassButtonStyle()
            .controlSize(.small)
            .disabled(!descriptor.isEnabled)
            .help(descriptor.help)
            .accessibilityLabel(descriptor.title)
            .accessibilityValue(descriptor.isActive ? "Active" : "")
        }
    }

    private func menuItems(_ kinds: [SessionCommandKind]) -> some View {
        ForEach(kinds, id: \.self) { kind in
            if let descriptor = descriptor(kind) {
                menuItem(descriptor)
            }
        }
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

    private func commandLabel(_ descriptor: SessionCommandDescriptor) -> some View {
        Image(systemName: descriptor.systemImage)
            .font(.system(size: Theme.Icon.medium, weight: .medium))
            .frame(
                width: Theme.Metrics.sessionShelfControlLength,
                height: Theme.Metrics.sessionShelfControlLength
            )
            .symbolVariant(descriptor.isActive ? .fill : .none)
    }

    private func descriptor(_ kind: SessionCommandKind) -> SessionCommandDescriptor? {
        descriptors.first { $0.id == kind }
    }
}
