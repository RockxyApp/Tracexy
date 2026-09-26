import AppKit
import SwiftUI

// MARK: - WorkspaceTabStripModel

/// What the tab strip shows: a value copy of the active Project's tabs, taken in
/// a SwiftUI body so every change to a tab's title, the order or the active tab
/// redraws the strip through observation, without the AppKit view observing the
/// store itself.
struct WorkspaceTabStripModel: Equatable {
    // MARK: Lifecycle

    @MainActor
    init(coordinator: MainContentCoordinator) {
        let store = coordinator.workspaces
        tabs = store.workspaces.map { Tab(id: $0.id, title: $0.title, isClosable: $0.isClosable) }
        activeID = store.activeWorkspaceID
        isEnabled = coordinator.canEditWorkspaceTabs
        isVisible = coordinator.hasHydratedProjects && tabs.count > 1
    }

    init() {}

    // MARK: Internal

    struct Tab: Equatable {
        let id: UUID
        let title: String
        let isClosable: Bool
    }

    var tabs: [Tab] = []
    var activeID: UUID?
    /// Tab commands apply now (not while Projects load or change).
    var isEnabled = false
    /// Shown once a Project has more than one tab, as Safari and Finder show theirs.
    var isVisible = false
}

// MARK: - WorkspaceTabStripActions

/// Where the strip sends what the user did; each goes to the coordinator, which
/// saves the change to the Project.
@MainActor
struct WorkspaceTabStripActions {
    // MARK: Lifecycle

    init() {}

    init(coordinator: MainContentCoordinator) {
        select = { [weak coordinator] in coordinator?.selectWorkspaceTab($0) }
        close = { [weak coordinator] in coordinator?.closeWorkspaceTab($0) }
        closeOthers = { [weak coordinator] in coordinator?.closeOtherWorkspaceTabs(keeping: $0) }
        closeOthersWarning = { [weak coordinator] in coordinator?.closeOtherWorkspaceTabsWarning(keeping: $0) }
        rename = { [weak coordinator] in coordinator?.renameWorkspaceTab($0, to: $1) ?? false }
        add = { [weak coordinator] in coordinator?.newWorkspaceTab() }
        move = { [weak coordinator] in coordinator?.moveWorkspaceTab($0, toInsertionIndex: $1) }
    }

    // MARK: Internal

    var select: (UUID) -> Void = { _ in }
    var close: (UUID) -> Void = { _ in }
    var closeOthers: (UUID) -> Void = { _ in }
    /// Set when closing the other tabs needs confirming first.
    var closeOthersWarning: (UUID) -> String? = { _ in nil }
    /// Returns `false` when the name is refused (empty after trimming).
    var rename: (UUID, String) -> Bool = { _, _ in false }
    var add: () -> Void = {}
    var move: (UUID, Int) -> Void = { _, _ in }
}

// MARK: - WorkspaceTabStripLayout

/// Tab geometry, kept apart from drawing so it can be tested. Tabs share the
/// strip's width, as Safari's do; below ``minimumTabWidth`` they keep that width
/// and the strip scrolls, with every tab also listed in the All Tabs menu.
enum WorkspaceTabStripLayout {
    static let barHeight: CGFloat = 36
    static let tabHeight: CGFloat = 28
    static let leadingInset: CGFloat = 74
    static let trailingInset: CGFloat = 12
    static let buttonSize: CGFloat = 28
    static let buttonSpacing: CGFloat = 6
    static let minimumTabWidth: CGFloat = 128
    static let closeButtonSize: CGFloat = 16
    static let dragThreshold: CGFloat = 4
    /// How far a strip edge that hides more tabs fades out.
    static let edgeFadeWidth: CGFloat = 24

    /// The width of each tab, and whether the tabs overflow the strip at it.
    static func tabWidth(stripWidth: CGFloat, count: Int) -> (width: CGFloat, overflows: Bool) {
        guard count > 0, stripWidth > 0 else {
            return (minimumTabWidth, false)
        }
        let share = (stripWidth / CGFloat(count)).rounded(.down)
        return (max(minimumTabWidth, share), share < minimumTabWidth)
    }

    /// The scroll offset that brings the tab at `index` fully into view, clear of
    /// a faded edge, moving as little as possible from `offset`.
    static func offset(
        revealing index: Int,
        tabWidth: CGFloat,
        stripWidth: CGFloat,
        count: Int,
        from offset: CGFloat
    )
        -> CGFloat
    {
        let maximum = max(0, tabWidth * CGFloat(count) - stripWidth)
        guard index >= 0, index < count else {
            return min(max(0, offset), maximum)
        }
        // A tab with more tabs beyond it stops short of the fade on that side.
        let minX = tabWidth * CGFloat(index) - (index > 0 ? edgeFadeWidth : 0)
        let maxX = tabWidth * CGFloat(index + 1) + (index < count - 1 ? edgeFadeWidth : 0)
        var next = offset
        if minX < next {
            next = minX
        } else if maxX > next + stripWidth {
            next = maxX - stripWidth
        }
        return min(max(0, next), maximum)
    }

    /// Where a dragged tab would be inserted: before the first tab whose middle is
    /// right of `x` (content coordinates), or after the last.
    static func insertionIndex(forContentX x: CGFloat, tabWidth: CGFloat, count: Int) -> Int {
        guard tabWidth > 0 else {
            return count
        }
        let index = Int(((x / tabWidth) + 0.5).rounded(.down))
        return min(max(0, index), count)
    }
}

// MARK: - WorkspaceTabsWindowSupport

/// Puts the workspace tab strip in the window's titlebar, under the toolbar and
/// across the whole window, as an `NSTitlebarAccessoryViewController`. AppKit
/// owns its layout, full-screen behaviour and the space the content gives it.
struct WorkspaceTabsWindowSupport: ViewModifier {
    let coordinator: MainContentCoordinator

    func body(content: Content) -> some View {
        let model = WorkspaceTabStripModel(coordinator: coordinator)
        content.background {
            WorkspaceTabStripInstaller(model: model, actions: WorkspaceTabStripActions(coordinator: coordinator))
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
    }
}

extension View {
    /// The workspace tab strip; see ``WorkspaceTabsWindowSupport``.
    func workspaceTabsSupport(coordinator: MainContentCoordinator) -> some View {
        modifier(WorkspaceTabsWindowSupport(coordinator: coordinator))
    }
}

// MARK: - WorkspaceTabStripInstaller

struct WorkspaceTabStripInstaller: NSViewRepresentable {
    let model: WorkspaceTabStripModel
    let actions: WorkspaceTabStripActions

    static func dismantleNSView(_ view: WorkspaceTabStripAnchorView, coordinator _: ()) {
        view.uninstall()
    }

    func makeNSView(context _: Context) -> WorkspaceTabStripAnchorView {
        WorkspaceTabStripAnchorView()
    }

    func updateNSView(_ view: WorkspaceTabStripAnchorView, context _: Context) {
        view.apply(model: model, actions: actions)
    }
}

// MARK: - WorkspaceTabStripAnchorView

/// A zero-size view that finds its window and owns the titlebar accessory
/// holding the strip for as long as it is in that window.
final class WorkspaceTabStripAnchorView: NSView {
    // MARK: Lifecycle

    init() {
        super.init(frame: .zero)
        setAccessibilityElement(false)
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    // MARK: Internal

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil {
            uninstall()
        } else {
            installIfNeeded()
        }
    }

    func apply(model: WorkspaceTabStripModel, actions: WorkspaceTabStripActions) {
        self.model = model
        self.actions = actions
        installIfNeeded()
        strip.actions = actions
        strip.model = model
        guard let accessory, accessory.isHidden == model.isVisible else {
            return
        }
        if NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            accessory.isHidden = !model.isVisible
        } else {
            accessory.animator().isHidden = !model.isVisible
        }
    }

    func uninstall() {
        strip.endEditing(commit: true)
        guard let accessory else {
            return
        }
        if let window = accessory.view.window ?? installedWindow,
           let index = window.titlebarAccessoryViewControllers.firstIndex(of: accessory)
        {
            window.removeTitlebarAccessoryViewController(at: index)
        }
        self.accessory = nil
        installedWindow = nil
    }

    // MARK: Private

    private let strip = WorkspaceTabStripView()
    private var accessory: NSTitlebarAccessoryViewController?
    private weak var installedWindow: NSWindow?
    private var model = WorkspaceTabStripModel()
    private var actions = WorkspaceTabStripActions()

    private func installIfNeeded() {
        guard let window else {
            return
        }
        if let accessory, installedWindow === window,
           window.titlebarAccessoryViewControllers.contains(accessory)
        {
            return
        }
        uninstall()
        let controller = NSTitlebarAccessoryViewController()
        controller.layoutAttribute = .bottom
        strip.frame = NSRect(x: 0, y: 0, width: window.frame.width, height: WorkspaceTabStripLayout.barHeight)
        controller.view = strip
        controller.fullScreenMinHeight = WorkspaceTabStripLayout.barHeight
        controller.isHidden = !model.isVisible
        // Above any other titlebar bar, directly under the toolbar.
        window.insertTitlebarAccessoryViewController(controller, at: 0)
        accessory = controller
        installedWindow = window
    }
}

// MARK: - WorkspaceTabStripView

/// The tab strip itself: capsule tabs in one rounded track, drawn with system
/// colours so Light, Dark, Increase Contrast and Reduce Transparency follow the
/// Mac. Click selects, double-click renames in place, drag reorders (the first
/// tab stays first), the close button shows on the active and hovered tab, and
/// the context menu renames and closes. Each tab is an accessibility radio
/// button inside a tab group, with its close button beside it.
final class WorkspaceTabStripView: NSView, NSTextFieldDelegate, NSViewToolTipOwner {
    // MARK: Lifecycle

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: WorkspaceTabStripLayout.barHeight))
        autoresizingMask = [.width]
        setAccessibilityElement(true)
        setAccessibilityRole(.tabGroup)
        setAccessibilityLabel(String(localized: "Workspace Tabs"))
        setAccessibilityIdentifier("workspaceTabs.bar")
        let center = NSWorkspace.shared.notificationCenter
        displayObserver = center.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.needsDisplay = true
            }
        }
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    deinit {
        if let displayObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(displayObserver)
        }
    }

    // MARK: Internal

    override var isFlipped: Bool {
        true
    }

    override var mouseDownCanMoveWindow: Bool {
        false
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: WorkspaceTabStripLayout.barHeight)
    }

    var actions = WorkspaceTabStripActions()

    var model = WorkspaceTabStripModel() {
        didSet {
            guard model != oldValue else {
                return
            }
            if let editingID, !model.tabs.contains(where: { $0.id == editingID }) {
                endEditing(commit: false)
            }
            let activeMoved = model.activeID != oldValue.activeID || model.tabs.count != oldValue.tabs.count
            recalculate(revealActive: activeMoved)
            needsDisplay = true
        }
    }

    override func acceptsFirstMouse(for _: NSEvent?) -> Bool {
        true
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        recalculate(revealActive: true)
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingArea {
            removeTrackingArea(trackingArea)
        }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseMoved, .mouseEnteredAndExited, .activeInKeyWindow, .inVisibleRect],
            owner: self
        )
        trackingArea = area
        addTrackingArea(area)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        drawTrack()
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect: stripRect).addClip()
        let context = NSGraphicsContext.current?.cgContext
        context?.beginTransparencyLayer(auxiliaryInfo: nil)
        for tab in model.tabs where tab.id != model.activeID {
            drawTab(tab)
        }
        if let active = model.tabs.first(where: { $0.id == model.activeID }) {
            drawTab(active)
        }
        drawDragFeedback()
        fadeScrolledEdges()
        context?.endTransparencyLayer()
        NSGraphicsContext.restoreGraphicsState()
        if overflows {
            drawButton(symbol: "chevron.down", in: allTabsFrame, isHovered: hovered == .allTabs, isEnabled: true)
        }
        drawButton(symbol: "plus", in: addFrame, isHovered: hovered == .add, isEnabled: model.isEnabled)
    }

    // MARK: Mouse

    override func mouseMoved(with event: NSEvent) {
        let next = hit(at: convert(event.locationInWindow, from: nil))
        if next != hovered {
            hovered = next
            needsDisplay = true
        }
    }

    override func mouseExited(with _: NSEvent) {
        hovered = nil
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        if let field = editField, !field.frame.contains(point) {
            guard endEditing(commit: true) else {
                return
            }
        }
        switch hit(at: point) {
        case .add:
            if model.isEnabled {
                actions.add()
            }
        case .allTabs:
            showAllTabsMenu()
        case let .close(id):
            if model.isEnabled {
                actions.close(id)
            }
        case let .tab(id):
            guard model.isEnabled else {
                return
            }
            if event.clickCount == 2 {
                beginRename(id)
                return
            }
            actions.select(id)
            pressedID = id
            pressPoint = point
        case nil:
            if event.clickCount == 2 {
                window?.performZoom(nil)
            }
        }
    }

    override func mouseDragged(with event: NSEvent) {
        guard editField == nil, let pressedID, let pressPoint,
              model.tabs.first(where: { $0.id == pressedID })?.isClosable == true else
        {
            return
        }
        let point = convert(event.locationInWindow, from: nil)
        if draggingID == nil,
           hypot(point.x - pressPoint.x, point.y - pressPoint.y) >= WorkspaceTabStripLayout.dragThreshold
        {
            draggingID = pressedID
            grabOffset = pressPoint.x - (tabFrame(at: index(of: pressedID) ?? 0).minX)
        }
        guard draggingID != nil else {
            return
        }
        dragX = point.x
        autoscrollWhileDragging(pointerX: point.x)
        needsDisplay = true
    }

    override func mouseUp(with _: NSEvent) {
        defer {
            pressedID = nil
            pressPoint = nil
            draggingID = nil
            dragX = nil
            needsDisplay = true
        }
        guard let draggingID, let insertion = dropInsertionIndex else {
            return
        }
        actions.move(draggingID, insertion)
    }

    override func scrollWheel(with event: NSEvent) {
        guard overflows else {
            super.scrollWheel(with: event)
            return
        }
        let delta = abs(event.scrollingDeltaX) > abs(event.scrollingDeltaY) ? event.scrollingDeltaX : event
            .scrollingDeltaY
        let scale: CGFloat = event.hasPreciseScrollingDeltas ? 1 : 10
        setScrollOffset(scrollOffset - delta * scale)
    }

    override func rightMouseDown(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        guard case let .tab(id)? = hit(at: point),
              let tab = model.tabs.first(where: { $0.id == id }) else
        {
            super.rightMouseDown(with: event)
            return
        }
        NSMenu.popUpContextMenu(contextMenu(for: tab), with: event, for: self)
    }

    // MARK: Accessibility

    override func accessibilityChildren() -> [Any]? {
        accessibilityElements
    }

    override func accessibilityTabs() -> [Any]? {
        accessibilityElements.filter { $0.accessibilityRole() == .radioButton }
    }

    // MARK: Rename

    func beginRename(_ id: UUID) {
        guard model.isEnabled, let index = index(of: id), endEditing(commit: true) else {
            return
        }
        actions.select(id)
        setScrollOffset(WorkspaceTabStripLayout.offset(
            revealing: index,
            tabWidth: tabWidth,
            stripWidth: stripRect.width,
            count: model.tabs.count,
            from: scrollOffset
        ))
        let field = WorkspaceTabRenameField(frame: renameFrame(for: index))
        field.stringValue = model.tabs[index].title
        field.font = Self.titleFont(active: true)
        field.alignment = .center
        field.delegate = self
        field.setAccessibilityLabel(String(localized: "Tab Name"))
        field.setAccessibilityIdentifier("workspaceTabs.rename")
        field.onCancel = { [weak self] in
            self?.endEditing(commit: false)
        }
        editingID = id
        editField = field
        addSubview(field)
        window?.makeFirstResponder(field)
        field.currentEditor()?.selectAll(nil)
        needsDisplay = true
    }

    /// Ends an in-place rename. Returns `false` (and keeps the field) when the
    /// name is refused, so an empty name never replaces the tab's title.
    @discardableResult
    func endEditing(commit: Bool) -> Bool {
        guard let editingID, let field = editField else {
            return true
        }
        if commit {
            let title = field.stringValue
            let current = model.tabs.first { $0.id == editingID }?.title
            if title != current, !actions.rename(editingID, title) {
                NSSound.beep()
                window?.makeFirstResponder(field)
                return false
            }
        }
        self.editingID = nil
        editField = nil
        field.delegate = nil
        field.removeFromSuperview()
        needsDisplay = true
        return true
    }

    func controlTextDidEndEditing(_: Notification) {
        endEditing(commit: true)
    }

    func control(_: NSControl, textView _: NSTextView, doCommandBy selector: Selector) -> Bool {
        switch selector {
        case #selector(NSResponder.insertNewline(_:)):
            endEditing(commit: true)
            return true
        case #selector(NSResponder.cancelOperation(_:)):
            endEditing(commit: false)
            return true
        default:
            return false
        }
    }

    // MARK: Tooltips

    func view(
        _: NSView,
        stringForToolTip _: NSView.ToolTipTag,
        point: NSPoint,
        userData _: UnsafeMutableRawPointer?
    )
        -> String
    {
        switch hit(at: point) {
        case .add:
            String(localized: "Open a new workspace tab")
        case .allTabs:
            String(localized: "Show all workspace tabs")
        case .close:
            String(localized: "Close this tab")
        case let .tab(id):
            model.tabs.first { $0.id == id }?.title ?? ""
        case nil:
            ""
        }
    }

    // MARK: Private

    private enum Hit: Equatable {
        case tab(UUID)
        case close(UUID)
        case add
        case allTabs
    }

    private var trackingArea: NSTrackingArea?
    private var displayObserver: NSObjectProtocol?
    private var tabWidth = WorkspaceTabStripLayout.minimumTabWidth
    private var overflows = false
    private var scrollOffset: CGFloat = 0
    private var stripRect = NSRect.zero
    private var addFrame = NSRect.zero
    private var allTabsFrame = NSRect.zero
    private var hovered: Hit?
    private var pressedID: UUID?
    private var pressPoint: NSPoint?
    private var draggingID: UUID?
    private var dragX: CGFloat?
    private var grabOffset: CGFloat = 0
    private var editingID: UUID?
    private var editField: WorkspaceTabRenameField?
    private var accessibilityElements: [WorkspaceTabAccessibilityElement] = []

    private var isDark: Bool {
        effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    }

    private var increasesContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    private var reducesTransparency: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency
    }

    /// Where the dragged tab would land, in the store's insertion terms.
    private var dropInsertionIndex: Int? {
        guard let draggingID, let dragX, let source = index(of: draggingID) else {
            return nil
        }
        let centre = dragX - grabOffset + tabWidth / 2 - stripRect.minX + scrollOffset
        let pinned = model.tabs.prefix { !$0.isClosable }.count
        let index = max(pinned, WorkspaceTabStripLayout.insertionIndex(
            forContentX: centre,
            tabWidth: tabWidth,
            count: model.tabs.count
        ))
        return index == source || index == source + 1 ? nil : index
    }

    private var hoveredTabID: UUID? {
        switch hovered {
        case let .tab(id),
             let .close(id):
            id
        default:
            nil
        }
    }

    private static func titleFont(active: Bool) -> NSFont {
        .systemFont(ofSize: NSFont.systemFontSize, weight: active ? .medium : .regular)
    }

    private func index(of id: UUID) -> Int? {
        model.tabs.firstIndex { $0.id == id }
    }

    private func tabFrame(at index: Int) -> NSRect {
        NSRect(
            x: stripRect.minX + CGFloat(index) * tabWidth - scrollOffset,
            y: (bounds.height - WorkspaceTabStripLayout.tabHeight) / 2,
            width: tabWidth,
            height: WorkspaceTabStripLayout.tabHeight
        )
    }

    private func closeFrame(in tab: NSRect) -> NSRect {
        let size = WorkspaceTabStripLayout.closeButtonSize
        return NSRect(x: tab.minX + 8, y: tab.midY - size / 2, width: size, height: size)
    }

    private func renameFrame(for index: Int) -> NSRect {
        tabFrame(at: index).insetBy(dx: 28, dy: 4)
    }

    private func recalculate(revealActive: Bool) {
        let size = WorkspaceTabStripLayout.buttonSize
        let spacing = WorkspaceTabStripLayout.buttonSpacing
        let top = (bounds.height - size) / 2
        addFrame = NSRect(
            x: bounds.maxX - WorkspaceTabStripLayout.trailingInset - size,
            y: top,
            width: size,
            height: size
        )
        let leading = WorkspaceTabStripLayout.leadingInset
        var trailing = addFrame.minX - spacing
        var layout = WorkspaceTabStripLayout.tabWidth(stripWidth: trailing - leading, count: model.tabs.count)
        if layout.overflows {
            allTabsFrame = NSRect(x: addFrame.minX - spacing - size, y: top, width: size, height: size)
            trailing = allTabsFrame.minX - spacing
            layout = WorkspaceTabStripLayout.tabWidth(stripWidth: trailing - leading, count: model.tabs.count)
        } else {
            allTabsFrame = .zero
        }
        tabWidth = layout.width
        overflows = layout.overflows
        stripRect = NSRect(x: leading, y: 0, width: max(0, trailing - leading), height: bounds.height)
        let activeIndex = model.activeID.flatMap(index(of:)) ?? -1
        scrollOffset = WorkspaceTabStripLayout.offset(
            revealing: revealActive ? activeIndex : -1,
            tabWidth: tabWidth,
            stripWidth: stripRect.width,
            count: model.tabs.count,
            from: overflows ? scrollOffset : 0
        )
        layoutEditField()
        rebuildToolTips()
        rebuildAccessibility()
    }

    private func setScrollOffset(_ offset: CGFloat) {
        let maximum = max(0, tabWidth * CGFloat(model.tabs.count) - stripRect.width)
        let clamped = min(max(0, offset), maximum)
        guard clamped != scrollOffset else {
            return
        }
        scrollOffset = clamped
        layoutEditField()
        rebuildToolTips()
        rebuildAccessibility()
        needsDisplay = true
    }

    private func layoutEditField() {
        if let editingID, let index = index(of: editingID) {
            editField?.frame = renameFrame(for: index)
        }
    }

    private func autoscrollWhileDragging(pointerX: CGFloat) {
        guard overflows else {
            return
        }
        if pointerX < stripRect.minX + 24 {
            setScrollOffset(scrollOffset - 12)
        } else if pointerX > stripRect.maxX - 24 {
            setScrollOffset(scrollOffset + 12)
        }
    }

    private func hit(at point: NSPoint) -> Hit? {
        if addFrame.contains(point) {
            return .add
        }
        if overflows, allTabsFrame.contains(point) {
            return .allTabs
        }
        guard stripRect.contains(point) else {
            return nil
        }
        for (index, tab) in model.tabs.enumerated() {
            let frame = tabFrame(at: index)
            guard frame.contains(point) else {
                continue
            }
            if tab.isClosable, editingID != tab.id,
               tab.id == model.activeID || hoveredTabID == tab.id,
               closeFrame(in: frame).insetBy(dx: -3, dy: -3).contains(point)
            {
                return .close(tab.id)
            }
            return .tab(tab.id)
        }
        return nil
    }

    // MARK: Drawing

    /// While tabs overflow, the edge that hides more tabs fades out instead of
    /// cutting a tab mid-title, as Safari's tab bar does.
    private func fadeScrolledEdges() {
        guard overflows, let context = NSGraphicsContext.current?.cgContext else {
            return
        }
        let width = WorkspaceTabStripLayout.edgeFadeWidth
        let maximum = max(0, tabWidth * CGFloat(model.tabs.count) - stripRect.width)
        let colors = [NSColor.black.cgColor, NSColor.black.withAlphaComponent(0).cgColor] as CFArray
        guard let gradient = CGGradient(colorsSpace: nil, colors: colors, locations: [0, 1]) else {
            return
        }
        context.saveGState()
        context.setBlendMode(.destinationOut)
        if scrollOffset > 0.5 {
            context.drawLinearGradient(
                gradient,
                start: CGPoint(x: stripRect.minX, y: 0),
                end: CGPoint(x: stripRect.minX + width, y: 0),
                options: []
            )
        }
        if scrollOffset < maximum - 0.5 {
            context.drawLinearGradient(
                gradient,
                start: CGPoint(x: stripRect.maxX, y: 0),
                end: CGPoint(x: stripRect.maxX - width, y: 0),
                options: []
            )
        }
        context.restoreGState()
    }

    private func drawTrack() {
        guard stripRect.width > 0 else {
            return
        }
        let track = NSRect(
            x: stripRect.minX - 4,
            y: (bounds.height - WorkspaceTabStripLayout.tabHeight) / 2 - 2,
            width: min(stripRect.width, tabWidth * CGFloat(model.tabs.count)) + 8,
            height: WorkspaceTabStripLayout.tabHeight + 4
        )
        let path = NSBezierPath(roundedRect: track, xRadius: track.height / 2, yRadius: track.height / 2)
        let fillAlpha: CGFloat = reducesTransparency ? 1 : (isDark ? 0.24 : 0.34)
        NSColor.windowBackgroundColor.withAlphaComponent(fillAlpha).setFill()
        path.fill()
        NSColor.separatorColor.withAlphaComponent(increasesContrast ? 1 : 0.35).setStroke()
        path.lineWidth = increasesContrast ? 1 : 0.6
        path.stroke()
    }

    private func drawTab(_ tab: WorkspaceTabStripModel.Tab) {
        guard let index = index(of: tab.id), tab.id != draggingID else {
            return
        }
        let frame = tabFrame(at: index)
        guard frame.intersects(stripRect) else {
            return
        }
        let isActive = tab.id == model.activeID
        let isHovered = hoveredTabID == tab.id
        drawCapsule(frame, isActive: isActive, isHovered: isHovered)
        if editingID != tab.id {
            drawTitle(tab.title, in: frame, isActive: isActive, closable: tab.isClosable)
        }
        if tab.isClosable, isActive || isHovered, editingID != tab.id, draggingID == nil {
            let close = closeFrame(in: frame)
            if hovered == .close(tab.id) {
                NSColor.labelColor.withAlphaComponent(isDark ? 0.16 : 0.08).setFill()
                NSBezierPath(ovalIn: close).fill()
            }
            drawSymbol("xmark", in: close, pointSize: 9, color: .secondaryLabelColor)
        }
        drawDivider(after: index, frame: frame)
    }

    private func drawCapsule(_ frame: NSRect, isActive: Bool, isHovered: Bool) {
        let rect = frame.insetBy(dx: 1, dy: 0)
        let path = NSBezierPath(roundedRect: rect, xRadius: rect.height / 2, yRadius: rect.height / 2)
        if isActive {
            NSGraphicsContext.saveGraphicsState()
            let shadow = NSShadow()
            shadow.shadowBlurRadius = 3
            shadow.shadowOffset = NSSize(width: 0, height: -0.5)
            shadow.shadowColor = NSColor.shadowColor.withAlphaComponent(isDark ? 0.3 : 0.1)
            shadow.set()
            NSColor.controlBackgroundColor.withAlphaComponent(reducesTransparency ? 1 : (isDark ? 0.84 : 0.96))
                .setFill()
            path.fill()
            NSGraphicsContext.restoreGraphicsState()
            (increasesContrast ? NSColor.labelColor : NSColor.separatorColor).setStroke()
            path.lineWidth = increasesContrast ? 1 : 0.7
            path.stroke()
        } else if isHovered {
            NSColor.labelColor.withAlphaComponent(isDark ? 0.08 : 0.04).setFill()
            path.fill()
        }
    }

    private func drawTitle(_ title: String, in frame: NSRect, isActive: Bool, closable: Bool) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        paragraph.lineBreakMode = .byTruncatingMiddle
        let color: NSColor = isActive || increasesContrast ? .labelColor : .secondaryLabelColor
        let text = NSAttributedString(string: title, attributes: [
            .font: Self.titleFont(active: isActive),
            .foregroundColor: color,
            .paragraphStyle: paragraph,
        ])
        // Room for the close button on both sides keeps the title centred; a
        // narrow tab gives the trailing side back before it truncates the title.
        let size = text.size()
        let leading: CGFloat = closable ? 28 : 12
        let trailing: CGFloat = size.width <= frame.width - leading * 2 ? leading : 10
        text.draw(in: NSRect(
            x: frame.minX + leading,
            y: frame.midY - size.height / 2,
            width: max(1, frame.width - leading - trailing),
            height: size.height + 1
        ))
    }

    private func drawDivider(after index: Int, frame: NSRect) {
        guard draggingID == nil, index < model.tabs.count - 1 else {
            return
        }
        let ids = [model.tabs[index].id, model.tabs[index + 1].id]
        guard !ids.contains(where: { $0 == model.activeID || $0 == hoveredTabID }) else {
            return
        }
        NSColor.separatorColor.setFill()
        NSRect(x: frame.maxX - 0.5, y: frame.minY + 7, width: 1, height: frame.height - 14).fill()
    }

    private func drawDragFeedback() {
        guard let draggingID, let dragX, let tab = model.tabs.first(where: { $0.id == draggingID }) else {
            return
        }
        if let insertion = dropInsertionIndex {
            let x = insertion < model.tabs.count ? tabFrame(at: insertion).minX : tabFrame(at: model.tabs.count - 1)
                .maxX
            NSColor.controlAccentColor.setFill()
            NSBezierPath(
                roundedRect: NSRect(x: x - 1, y: 8, width: 2, height: bounds.height - 16),
                xRadius: 1,
                yRadius: 1
            ).fill()
        }
        var ghost = tabFrame(at: 0)
        ghost.origin.x = dragX - grabOffset
        drawCapsule(ghost, isActive: true, isHovered: false)
        drawTitle(tab.title, in: ghost, isActive: true, closable: tab.isClosable)
    }

    private func drawButton(symbol: String, in frame: NSRect, isHovered: Bool, isEnabled: Bool) {
        let path = NSBezierPath(ovalIn: frame)
        let alpha: CGFloat = isEnabled ? (isHovered ? (isDark ? 0.22 : 0.12) : (isDark ? 0.14 : 0.075)) :
            (isDark ? 0.08 : 0.04)
        NSColor.labelColor.withAlphaComponent(alpha).setFill()
        path.fill()
        if increasesContrast {
            NSColor.separatorColor.setStroke()
            path.lineWidth = 1
            path.stroke()
        }
        drawSymbol(symbol, in: frame, pointSize: 12, color: isEnabled ? .secondaryLabelColor : .tertiaryLabelColor)
    }

    private func drawSymbol(_ name: String, in frame: NSRect, pointSize: CGFloat, color: NSColor) {
        let configuration = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .semibold)
            .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        guard let image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(configuration) else
        {
            return
        }
        let size = image.size
        let rect = NSRect(
            x: frame.midX - size.width / 2,
            y: frame.midY - size.height / 2,
            width: size.width,
            height: size.height
        )
        image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
    }

    // MARK: Menus

    private func contextMenu(for tab: WorkspaceTabStripModel.Tab) -> NSMenu {
        let menu = NSMenu()
        menu.addItem(menuItem(String(localized: "Rename Tab…"), enabled: model.isEnabled) { [weak self] in
            self?.beginRename(tab.id)
        })
        menu.addItem(.separator())
        menu
            .addItem(menuItem(
                String(localized: "Close Tab"),
                enabled: model.isEnabled && tab.isClosable
            ) { [weak self] in
                self?.actions.close(tab.id)
            })
        let othersClosable = model.tabs.contains { $0.id != tab.id && $0.isClosable }
        menu
            .addItem(menuItem(
                String(localized: "Close Other Tabs"),
                enabled: model.isEnabled && othersClosable
            ) { [weak self] in
                self?.closeOtherTabs(keeping: tab.id)
            })
        menu.addItem(.separator())
        menu.addItem(menuItem(String(localized: "New Tab"), enabled: model.isEnabled) { [weak self] in
            self?.actions.add()
        })
        return menu
    }

    private func closeOtherTabs(keeping id: UUID) {
        guard let warning = actions.closeOthersWarning(id), let window else {
            actions.closeOthers(id)
            return
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Close Other Tabs?")
        alert.informativeText = warning
        let confirm = alert.addButton(withTitle: String(localized: "Close Other Tabs"))
        confirm.hasDestructiveAction = true
        alert.addButton(withTitle: String(localized: "Cancel"))
        alert.beginSheetModal(for: window) { [weak self] response in
            if response == .alertFirstButtonReturn {
                self?.actions.closeOthers(id)
            }
        }
    }

    private func showAllTabsMenu() {
        let menu = NSMenu()
        for tab in model.tabs {
            let item = menuItem(tab.title, enabled: model.isEnabled) { [weak self] in
                self?.actions.select(tab.id)
            }
            item.state = tab.id == model.activeID ? .on : .off
            menu.addItem(item)
        }
        menu.popUp(positioning: nil, at: NSPoint(x: allTabsFrame.minX, y: allTabsFrame.maxY + 4), in: self)
    }

    private func menuItem(_ title: String, enabled: Bool, action: @escaping @MainActor () -> Void) -> NSMenuItem {
        let item = WorkspaceTabMenuItem(title: title, handler: action)
        item.isEnabled = enabled
        return item
    }

    // MARK: Tooltips and accessibility

    private func rebuildToolTips() {
        removeAllToolTips()
        for index in model.tabs.indices {
            let frame = tabFrame(at: index).intersection(stripRect)
            if !frame.isEmpty {
                addToolTip(frame, owner: self, userData: nil)
            }
        }
        addToolTip(addFrame, owner: self, userData: nil)
        if overflows {
            addToolTip(allTabsFrame, owner: self, userData: nil)
        }
    }

    private func rebuildAccessibility() {
        var elements: [WorkspaceTabAccessibilityElement] = []
        for (index, tab) in model.tabs.enumerated() {
            let frame = tabFrame(at: index)
            let isActive = tab.id == model.activeID
            // A tab partly scrolled out reports only the part in view, so the
            // VoiceOver cursor never outlines a part the strip does not show.
            let visible = frame.intersection(stripRect)
            let element = WorkspaceTabAccessibilityElement(
                parent: self,
                role: .radioButton,
                frame: visible.isNull ? frame : visible
            ) { [weak self] in
                self?.actions.select(tab.id)
            }
            element.setAccessibilityLabel(tab.title)
            element.setAccessibilityValue(isActive ? 1 : 0)
            element.setAccessibilitySelected(isActive)
            element.setAccessibilityIdentifier("workspaceTabs.tab")
            element.setAccessibilityHelp(isActive ? nil : String(localized: "Shows this workspace tab"))
            element.isHiddenFromAccessibility = !frame.intersects(stripRect)
            elements.append(element)
            if tab.isClosable {
                let close = WorkspaceTabAccessibilityElement(
                    parent: self,
                    role: .button,
                    frame: closeFrame(in: frame)
                ) { [weak self] in
                    self?.actions.close(tab.id)
                }
                close.setAccessibilityLabel(String(localized: "Close \(tab.title)"))
                close.setAccessibilityIdentifier("workspaceTabs.close")
                close.setAccessibilityEnabled(model.isEnabled)
                close.isHiddenFromAccessibility = element.isHiddenFromAccessibility
                    || !stripRect.contains(closeFrame(in: frame))
                elements.append(close)
            }
        }
        if overflows {
            let all = WorkspaceTabAccessibilityElement(
                parent: self,
                role: .menuButton,
                frame: allTabsFrame
            ) { [weak self] in
                self?.showAllTabsMenu()
            }
            all.setAccessibilityLabel(String(localized: "All Tabs"))
            all.setAccessibilityIdentifier("workspaceTabs.all")
            elements.append(all)
        }
        let add = WorkspaceTabAccessibilityElement(parent: self, role: .button, frame: addFrame) { [weak self] in
            self?.actions.add()
        }
        add.setAccessibilityLabel(String(localized: "New Tab"))
        add.setAccessibilityIdentifier("workspaceTabs.add")
        add.setAccessibilityEnabled(model.isEnabled)
        elements.append(add)
        accessibilityElements = elements.filter { !$0.isHiddenFromAccessibility }
        NSAccessibility.post(element: self, notification: .layoutChanged)
    }
}

// MARK: - WorkspaceTabAccessibilityElement

/// One tab, close button or strip button as VoiceOver sees it; pressing it does
/// what clicking it does.
private final class WorkspaceTabAccessibilityElement: NSAccessibilityElement {
    // MARK: Lifecycle

    init(parent: NSView, role: NSAccessibility.Role, frame: NSRect, press: @escaping @MainActor () -> Void) {
        self.press = press
        super.init()
        setAccessibilityParent(parent)
        setAccessibilityRole(role)
        setAccessibilityFrameInParentSpace(frame)
    }

    // MARK: Internal

    var isHiddenFromAccessibility = false

    override func accessibilityPerformPress() -> Bool {
        MainActor.assumeIsolated {
            press()
        }
        return true
    }

    // MARK: Private

    private let press: @MainActor () -> Void
}

// MARK: - WorkspaceTabMenuItem

/// A menu item that runs a closure, so the strip's menus need no selectors.
private final class WorkspaceTabMenuItem: NSMenuItem {
    // MARK: Lifecycle

    init(title: String, handler: @escaping @MainActor () -> Void) {
        self.handler = handler
        super.init(title: title, action: #selector(run), keyEquivalent: "")
        target = self
    }

    @available(*, unavailable)
    required init(coder _: NSCoder) {
        fatalError("not used")
    }

    // MARK: Private

    private let handler: @MainActor () -> Void

    @objc
    private func run() {
        MainActor.assumeIsolated {
            handler()
        }
    }
}

// MARK: - WorkspaceTabRenameField

/// The in-place rename field; Escape cancels.
private final class WorkspaceTabRenameField: NSTextField {
    // MARK: Lifecycle

    override init(frame: NSRect) {
        super.init(frame: frame)
        isBezeled = true
        bezelStyle = .roundedBezel
        drawsBackground = true
        lineBreakMode = .byTruncatingMiddle
        usesSingleLineMode = true
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    // MARK: Internal

    var onCancel: (() -> Void)?

    override func cancelOperation(_: Any?) {
        onCancel?()
    }
}

// MARK: - WorkspaceTabCommands

/// File ▸ New Tab and Close Tab, and Window ▸ Show Next/Previous Tab (⌃Tab,
/// ⌃⇧Tab, the standard tab-cycling keys). ⌘T already sets a time reference, as
/// Wireshark's Ctrl+T does, so New Tab takes ⌥⌘T.
struct WorkspaceTabCommands: Commands {
    let coordinator: MainContentCoordinator

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("New Tab") {
                coordinator.newWorkspaceTab()
            }
            .keyboardShortcut("t", modifiers: [.command, .option])
            .disabled(!coordinator.canEditWorkspaceTabs)
            Button("Close Tab") {
                coordinator.closeWorkspaceTab(coordinator.workspaces.activeWorkspaceID)
            }
            .disabled(!coordinator.canCloseActiveWorkspaceTab)
            Divider()
        }
        CommandGroup(before: .windowList) {
            Button("Show Next Tab") {
                coordinator.showAdjacentWorkspaceTab(1)
            }
            .keyboardShortcut(.tab, modifiers: .control)
            .disabled(!coordinator.canShowAdjacentWorkspaceTab)
            Button("Show Previous Tab") {
                coordinator.showAdjacentWorkspaceTab(-1)
            }
            .keyboardShortcut(.tab, modifiers: [.control, .shift])
            .disabled(!coordinator.canShowAdjacentWorkspaceTab)
            Divider()
        }
    }
}
