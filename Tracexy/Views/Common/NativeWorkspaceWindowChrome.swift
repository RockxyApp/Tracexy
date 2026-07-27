import AppKit
import SwiftUI

// MARK: - NativeWorkspaceToolbarConfiguration

/// The data the native window toolbar needs: the one shared coordinator whose
/// capture and inspector state its items read and drive.
struct NativeWorkspaceToolbarConfiguration {
    let coordinator: MainContentCoordinator
}

// MARK: - NativeWorkspaceWindowChrome

/// Installs the full-height unified titlebar and the native `NSToolbar` on the
/// window hosting the root workspace split.
///
/// The sidebar toggle lives here — as a real bordered toolbar item followed by an
/// `NSTrackingSeparatorToolbarItem` bound to the split's first divider — so the
/// control sits geometrically above the source list and tracks its width, exactly
/// like the Mac's own source-list windows. The SwiftUI sidebar owns no show/hide
/// chrome of its own.
enum NativeWorkspaceWindowChrome {
    @MainActor
    static func configure(
        _ window: NSWindow,
        workspaceSplitController: NativeWorkspaceSplitViewController? = nil,
        toolbarConfiguration: NativeWorkspaceToolbarConfiguration? = nil
    ) {
        window.titlebarAppearsTransparent = true
        window.styleMask.insert(.fullSizeContentView)

        if let workspaceSplitController,
           let toolbarConfiguration
        {
            workspaceSplitController.installToolbarIfNeeded(
                window: window,
                configuration: toolbarConfiguration
            )
        }

        window.titleVisibility = .hidden
    }
}

// MARK: - NativeWorkspaceToolbar

@MainActor
final class NativeWorkspaceToolbar: NSObject, NSToolbarDelegate {
    // MARK: Lifecycle

    init(
        splitViewController: NativeWorkspaceSplitViewController,
        configuration: NativeWorkspaceToolbarConfiguration
    ) {
        self.splitViewController = splitViewController
        coordinator = configuration.coordinator
        managedToolbar = NSToolbar(identifier: Self.toolbarIdentifier)
        super.init()

        managedToolbar.delegate = self
        managedToolbar.displayMode = .iconOnly
        managedToolbar.allowsUserCustomization = false
        managedToolbar.autosavesConfiguration = false
        managedToolbar.centeredItemIdentifiers = [Self.captureStatusIdentifier]
    }

    deinit {
        observationTask?.cancel()
    }

    // MARK: Internal

    static let toolbarIdentifier = NSToolbar.Identifier(
        "\(TracexyIdentity.current.logSubsystem).main.toolbar"
    )
    static let sidebarToggleIdentifier = NSToolbarItem.Identifier(
        "\(TracexyIdentity.current.logSubsystem).toolbar.toggleSidebar"
    )
    static let sidebarTrackingSeparatorIdentifier = NSToolbarItem.Identifier(
        "\(TracexyIdentity.current.logSubsystem).toolbar.sidebarTrackingSeparator"
    )
    static let interfacePickerIdentifier = NSToolbarItem.Identifier(
        "\(TracexyIdentity.current.logSubsystem).toolbar.interfacePicker"
    )
    static let captureStatusIdentifier = NSToolbarItem.Identifier(
        "\(TracexyIdentity.current.logSubsystem).toolbar.captureStatus"
    )
    static let actionsIdentifier = NSToolbarItem.Identifier(
        "\(TracexyIdentity.current.logSubsystem).toolbar.actions"
    )

    let managedToolbar: NSToolbar

    /// Keeps the Start/Stop capture item's icon, label and tooltip truthful by
    /// observing `coordinator.isCapturing`. Called once after the toolbar is
    /// installed; the weak captures mean neither the toolbar nor the coordinator is
    /// retained by the long-lived observation task.
    func startObservingState() {
        syncActionItems(isCapturing: coordinator.isCapturing)
        observationTask?.cancel()
        observationTask = Task { [weak self, weak coordinator] in
            guard let coordinator else {
                return
            }
            while !Task.isCancelled {
                await withCheckedContinuation { continuation in
                    withObservationTracking {
                        // Sync from inside the tracked read. Launch auto-start can
                        // change `isCapturing` after the initial sync but before
                        // this task gets its first actor turn; reading and
                        // rendering together prevents that state from being
                        // missed until the next capture transition.
                        let isCapturing = coordinator.isCapturing
                        self?.syncActionItems(isCapturing: isCapturing)
                    } onChange: {
                        continuation.resume()
                    }
                }
                guard !Task.isCancelled else {
                    return
                }
            }
        }
    }

    func toolbarDefaultItemIdentifiers(
        _ toolbar: NSToolbar
    )
        -> [NSToolbarItem.Identifier]
    {
        // The bordered sidebar toggle sits behind a leading flexible space with the
        // tracking separator immediately after it, so the control lands directly
        // above the source list and tracks the first divider. Capture status is
        // centred; the capture/inspector actions trail on the right.
        [
            .flexibleSpace,
            Self.sidebarToggleIdentifier,
            Self.sidebarTrackingSeparatorIdentifier,
            Self.interfacePickerIdentifier,
            .flexibleSpace,
            Self.captureStatusIdentifier,
            .flexibleSpace,
            Self.actionsIdentifier,
        ]
    }

    func toolbarAllowedItemIdentifiers(
        _ toolbar: NSToolbar
    )
        -> [NSToolbarItem.Identifier]
    {
        toolbarDefaultItemIdentifiers(toolbar)
    }

    func toolbar(
        _ toolbar: NSToolbar,
        itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier,
        willBeInsertedIntoToolbar flag: Bool
    )
        -> NSToolbarItem?
    {
        switch itemIdentifier {
        case Self.sidebarToggleIdentifier:
            makeSidebarToggleItem()
        case Self.sidebarTrackingSeparatorIdentifier:
            splitViewController.map {
                NSTrackingSeparatorToolbarItem(
                    identifier: Self.sidebarTrackingSeparatorIdentifier,
                    splitView: $0.splitView,
                    dividerIndex: 0
                )
            }
        case Self.interfacePickerIdentifier:
            hostingItem(
                identifier: itemIdentifier,
                rootView: AnyView(CaptureInterfaceToolbarPicker(coordinator: coordinator))
            )
        case Self.captureStatusIdentifier:
            hostingItem(
                identifier: itemIdentifier,
                rootView: AnyView(CaptureStatusView(coordinator: coordinator))
            )
        case Self.actionsIdentifier:
            makeActionGroup()
        default:
            nil
        }
    }

    // MARK: Private

    private weak var splitViewController: NativeWorkspaceSplitViewController?
    private let coordinator: MainContentCoordinator
    private var hostingControllers: [
        NSToolbarItem.Identifier: NSHostingController<AnyView>
    ] = [:]
    private var observationTask: Task<Void, Never>?
    private weak var captureToggleItem: NSToolbarItem?

    private func makeSidebarToggleItem() -> NSToolbarItem {
        let item = NSToolbarItem(itemIdentifier: Self.sidebarToggleIdentifier)
        let label = String(localized: "Toggle Sidebar")
        item.label = label
        item.paletteLabel = label
        item.toolTip = String(localized: "Show or hide the sidebar")
        item.target = self
        item.action = #selector(toggleSidebar(_:))
        item.image = NSImage(
            systemSymbolName: "sidebar.leading",
            accessibilityDescription: label
        )
        item.isBordered = true
        return item
    }

    /// The trailing capture/inspector cluster as a real `NSToolbarItemGroup` of
    /// three plain native icon items — Start/Stop capture, bottom inspector, and
    /// the right context inspector — matching the Mac's own toolbar styling. The
    /// items carry no custom background, tint or divider; state is reflected only
    /// through the Start/Stop icon, which `syncActionItems` keeps current.
    private func makeActionGroup() -> NSToolbarItemGroup {
        let captureItem = imageItem(
            identifier: NSToolbarItem.Identifier(
                "\(Self.actionsIdentifier.rawValue).capture"
            ),
            label: coordinator.isCapturing
                ? String(localized: "Stop")
                : String(localized: "Start"),
            systemImage: coordinator.isCapturing ? "stop.fill" : "play.fill",
            action: #selector(toggleCapture(_:))
        )
        captureItem.toolTip = coordinator.isCapturing
            ? String(localized: "Stop capture")
            : String(localized: "Start capture")
        captureToggleItem = captureItem

        let bottomInspectorItem = imageItem(
            identifier: NSToolbarItem.Identifier(
                "\(Self.actionsIdentifier.rawValue).bottomInspector"
            ),
            label: String(localized: "Bottom Inspector"),
            systemImage: "rectangle.split.1x2",
            action: #selector(toggleBottomInspector(_:))
        )
        bottomInspectorItem.toolTip = String(localized: "Show or hide the bottom inspector panel")

        let contextDockItem = imageItem(
            identifier: NSToolbarItem.Identifier(
                "\(Self.actionsIdentifier.rawValue).contextDock"
            ),
            label: String(localized: "Inspector"),
            systemImage: "sidebar.trailing",
            action: #selector(toggleContextDock(_:))
        )
        contextDockItem.toolTip = String(localized: "Show or hide the inspector (Details · AI Assistant).")

        let group = NSToolbarItemGroup(itemIdentifier: Self.actionsIdentifier)
        group.label = String(localized: "Workspace Actions")
        group.paletteLabel = group.label
        group.subitems = [
            captureItem,
            bottomInspectorItem,
            contextDockItem,
        ]
        return group
    }

    private func imageItem(
        identifier: NSToolbarItem.Identifier,
        label: String,
        systemImage: String,
        action: Selector
    )
        -> NSToolbarItem
    {
        let item = NSToolbarItem(itemIdentifier: identifier)
        item.label = label
        item.paletteLabel = label
        item.toolTip = label
        item.target = self
        item.action = action
        item.image = NSImage(
            systemSymbolName: systemImage,
            accessibilityDescription: label
        )
        return item
    }

    private func hostingItem(
        identifier: NSToolbarItem.Identifier,
        rootView: AnyView
    )
        -> NSToolbarItem
    {
        let controller = NSHostingController(rootView: rootView)
        controller.sizingOptions = [.intrinsicContentSize]
        hostingControllers[identifier] = controller

        let item = NSToolbarItem(itemIdentifier: identifier)
        item.view = controller.view
        item.visibilityPriority = .high
        return item
    }

    private func syncActionItems(isCapturing: Bool) {
        let label = isCapturing ? String(localized: "Stop") : String(localized: "Start")
        captureToggleItem?.label = label
        captureToggleItem?.paletteLabel = label
        captureToggleItem?.toolTip = isCapturing
            ? String(localized: "Stop capture")
            : String(localized: "Start capture")
        captureToggleItem?.image = NSImage(
            systemSymbolName: isCapturing ? "stop.fill" : "play.fill",
            accessibilityDescription: label
        )
    }

    @objc
    private func toggleCapture(_ sender: Any?) {
        coordinator.toggleCapture()
    }

    @objc
    private func toggleBottomInspector(_ sender: Any?) {
        coordinator.toggleInspectorBottom()
    }

    @objc
    private func toggleContextDock(_ sender: Any?) {
        coordinator.toggleContextDock()
    }

    @objc
    private func toggleSidebar(_ sender: Any?) {
        guard let splitViewController else {
            return
        }
        let isPresented = !splitViewController.isSidebarPresented
        splitViewController.setSidebarPresented(
            isPresented,
            animated: true
        )
        // A toolbar action originates outside SwiftUI. Publish the requested
        // presentation explicitly: `setSidebarPresented` updates the controller's
        // requested state before collapse KVO fires, so that KVO callback correctly
        // coalesces the matching change instead of writing the binding a second time.
        splitViewController.onSidebarVisibilityChanged?(isPresented)
    }
}

// MARK: - CaptureInterfaceToolbarPicker

/// The capture-interface dropdown, grouped by family (Wi-Fi, Ethernet, Thunderbolt,
/// …) with macOS's friendly names and a checkmark on the active one. Hosted in a
/// native toolbar item so it lives in the title area beside the sidebar toggle.
private struct CaptureInterfaceToolbarPicker: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

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
                            Text(iface.menuLabel).tag(iface.id)
                        }
                    }
                }
            } label: {
                EmptyView()
            }
            .pickerStyle(.inline)
        } label: {
            HStack(spacing: 5) {
                Image(systemName: currentInterfaceSymbol)
                Text(currentInterfaceLabel).lineLimit(1).truncationMode(.tail)
            }
            .frame(width: 188, alignment: .leading)
        }
        .menuStyle(.button)
        .help("Capture interface")
        .fixedSize()
        .onAppear {
            interfaceGroups = NetworkInterfaces.grouped()
            // Make sure a real interface is selected by default.
            if currentInterface == nil, let first = interfaceGroups.flatMap(\.interfaces).first {
                coordinator.captureInterface = first.id
            }
        }
    }

    // MARK: Private

    @State private var interfaceGroups: [InterfaceGroup] = []

    private var currentInterface: NetworkInterface? {
        interfaceGroups.flatMap(\.interfaces).first { $0.id == coordinator.captureInterface }
    }

    private var currentInterfaceSymbol: String {
        currentInterface?.symbol ?? "network"
    }

    /// Friendly label for the toolbar button, e.g. "Wi-Fi (en0)".
    private var currentInterfaceLabel: String {
        currentInterface?.menuLabel ?? coordinator.captureInterface
    }
}

// MARK: - NativeWorkspaceSplitViewController + Toolbar

extension NativeWorkspaceSplitViewController {
    func installToolbarIfNeeded(
        window: NSWindow,
        configuration: NativeWorkspaceToolbarConfiguration
    ) {
        if let nativeToolbar,
           window.toolbar === nativeToolbar.managedToolbar
        {
            return
        }

        let toolbar = NativeWorkspaceToolbar(
            splitViewController: self,
            configuration: configuration
        )
        nativeToolbar = toolbar
        window.toolbar = toolbar.managedToolbar
        toolbar.startObservingState()
    }

    private(set) var nativeToolbar: NativeWorkspaceToolbar? {
        get {
            objc_getAssociatedObject(
                self,
                &NativeWorkspaceToolbarAssociation.key
            ) as? NativeWorkspaceToolbar
        }
        set {
            objc_setAssociatedObject(
                self,
                &NativeWorkspaceToolbarAssociation.key,
                newValue,
                .OBJC_ASSOCIATION_RETAIN_NONATOMIC
            )
        }
    }
}

// MARK: - NativeWorkspaceToolbarAssociation

private enum NativeWorkspaceToolbarAssociation {
    static var key: UInt8 = 0
}
