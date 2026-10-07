import AppKit
import SwiftUI

// MARK: - CaptureInterfaceToolbarHost

/// Only source-label density follows the window width. The same native menu,
/// selection, tooltip, and accessibility value survive either presentation.
final class CaptureInterfaceToolbarHost: NSHostingView<CaptureInterfaceToolbarPicker> {
    // MARK: Lifecycle

    convenience init(coordinator: MainContentCoordinator) {
        self.init(rootView: CaptureInterfaceToolbarPicker(coordinator: coordinator))
    }

    required init(rootView: CaptureInterfaceToolbarPicker) {
        super.init(rootView: rootView)
        // NSToolbar measures custom views through constraints. Keep both bounds
        // current as SwiftUI changes between icon-only and labelled content.
        sizingOptions = [.minSize, .intrinsicContentSize, .maxSize]
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: Internal

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        NotificationCenter.default.removeObserver(self, name: NSWindow.didResizeNotification, object: nil)
        guard let window else {
            return
        }
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(updateDensity),
            name: NSWindow.didResizeNotification,
            object: window
        )
        updateDensity()
    }

    // MARK: Private

    @objc
    private func updateDensity() {
        guard let window else {
            return
        }
        let isCompact = window.frame.width < Theme.Metrics.toolbarCompactWindowWidth
        guard rootView.isCompact != isCompact else {
            return
        }
        rootView.isCompact = isCompact
        invalidateIntrinsicContentSize()
    }
}

// MARK: - CaptureInterfaceToolbarPicker

struct CaptureInterfaceToolbarPicker: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var isCompact = false

    var body: some View {
        Menu {
            Picker(
                selection: Binding(
                    get: { coordinator.captureInterface },
                    set: { coordinator.captureInterface = $0 }
                )
            ) {
                ForEach(interfaceGroups) { group in
                    Section(group.category.title) {
                        ForEach(group.interfaces) { iface in
                            Text(iface.pickerLabel).tag(iface.id)
                        }
                    }
                }
            } label: {
                EmptyView()
            }
            .pickerStyle(.inline)
            Divider()
            Button("Manage Interfaces…") {
                openWindow(id: TracexyApp.manageInterfacesWindowID)
            }
        } label: {
            HStack(spacing: Theme.Metrics.controlSpacing) {
                Image(systemName: currentInterface?.symbol ?? "network")
                if !isCompact {
                    Text(currentInterface?.displayName ?? coordinator.captureInterface)
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .frame(maxWidth: Theme.Metrics.toolbarInterfaceLabelMaximumWidth)
                }
            }
        }
        .menuStyle(.button)
        .help("Capture interface: \(fullInterfaceLabel)")
        .accessibilityLabel("Capture interface")
        .accessibilityValue(fullInterfaceLabel)
        .fixedSize()
        .onAppear {
            interfaceGroups = listedGroups
            if currentInterface == nil, let first = interfaceGroups.flatMap(\.interfaces).first {
                coordinator.captureInterface = first.id
            }
        }
        .onChange(of: coordinator.interfaceListToken) {
            interfaceGroups = listedGroups
        }
        .onChange(of: InterfacePreferences.shared.settings) {
            interfaceGroups = listedGroups
        }
    }

    // MARK: Private

    @State private var interfaceGroups: [InterfaceGroup] = []
    @Environment(\.openWindow) private var openWindow

    /// The interfaces Manage Interfaces leaves listed, by their friendly names.
    private var listedGroups: [InterfaceGroup] {
        NetworkInterfaces.grouped(
            InterfacePreferences.shared.settings, keeping: coordinator.captureInterface, includingPipes: true
        )
    }

    private var currentInterface: NetworkInterface? {
        interfaceGroups.flatMap(\.interfaces).first { $0.id == coordinator.captureInterface }
    }

    private var fullInterfaceLabel: String {
        currentInterface?.menuLabel ?? coordinator.captureInterface
    }
}
