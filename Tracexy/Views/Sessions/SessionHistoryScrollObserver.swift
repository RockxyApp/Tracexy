import AppKit
import SwiftUI

/// Observes user-owned wheel/trackpad navigation inside a SwiftUI `Table`
/// without intercepting the event. Programmatic selection/reveal emits no scroll
/// event, so coordinator-driven Follow Live updates do not turn themselves off.
///
/// It also answers a reveal request: when `revealToken` changes, the selected row of
/// the table it sits behind is scrolled into view on the next run-loop turn — outside
/// SwiftUI's update, so the table is never asked to scroll from inside its own
/// delegate callbacks.
struct SessionHistoryScrollObserver: NSViewRepresentable {
    @MainActor
    final class ObserverView: NSView {
        // MARK: Lifecycle

        init(onUserScroll: @escaping () -> Void) {
            self.onUserScroll = onUserScroll
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder _: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }

        // MARK: Internal

        var onUserScroll: () -> Void
        var revealToken = 0

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            stopObserving()
            guard window != nil else {
                return
            }

            eventMonitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] event in
                self?.handle(event)
                return event
            }
        }

        func stopObserving() {
            guard let eventMonitor else {
                return
            }
            NSEvent.removeMonitor(eventMonitor)
            self.eventMonitor = nil
        }

        /// Scrolls the selected row of the sibling table into view, once, after the
        /// current update settles.
        func scheduleReveal(row: Int?) {
            // After the current update and the layout it triggers (an inspector that
            // just opened shortens the table), so the row lands in the final viewport.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
                guard let table = self?.siblingTable() else {
                    return
                }
                // SwiftUI's Table does not always mirror a programmatic selection into
                // the table's `selectedRow`, so the caller names the row it drew.
                let target = table.selectedRow >= 0 ? table.selectedRow : row ?? -1
                guard target >= 0, target < table.numberOfRows else {
                    return
                }
                Self.center(row: target, in: table)
            }
        }

        // MARK: Private

        private var eventMonitor: Any?

        /// Scrolls so the row sits mid-viewport unless it is already comfortably
        /// inside it — `scrollRowToVisible` alone can leave it under the bottom edge's
        /// overlays (a scroller, a safe-area bar).
        private static func center(row: Int, in table: NSTableView) {
            let rowRect = table.rect(ofRow: row)
            let visible = table.visibleRect
            let margin = rowRect.height * 2
            guard !visible.insetBy(dx: 0, dy: min(margin, visible.height / 4)).contains(rowRect) else {
                return
            }
            let y = max(0, rowRect.midY - visible.height / 2)
            table.scroll(NSPoint(x: visible.minX, y: y))
        }

        private static func tables(in view: NSView) -> [NSTableView] {
            if let table = view as? NSTableView {
                return [table]
            }
            return view.subviews.flatMap { tables(in: $0) }
        }

        /// The `NSTableView` this background view sits behind: the one in the window
        /// whose scroll view covers this view's centre. Walking up to the first
        /// ancestor that holds *a* table finds the sidebar's outline instead.
        private func siblingTable() -> NSTableView? {
            guard let root = window?.contentView else {
                return nil
            }
            let center = convert(NSPoint(x: bounds.midX, y: bounds.midY), to: nil)
            return Self.tables(in: root).first { table in
                let container: NSView = table.enclosingScrollView ?? table
                return container.convert(container.bounds, to: nil).contains(center)
            }
        }

        private func handle(_ event: NSEvent) {
            guard event.window === window else {
                return
            }
            let location = convert(event.locationInWindow, from: nil)
            guard bounds.contains(location) else {
                return
            }
            onUserScroll()
        }
    }

    var revealToken = 0
    /// The row the table drew for the selection, when the caller knows it.
    var revealRow: Int?
    let onUserScroll: () -> Void

    static func dismantleNSView(_ nsView: ObserverView, coordinator _: ()) {
        nsView.stopObserving()
    }

    func makeNSView(context _: Context) -> ObserverView {
        let view = ObserverView(onUserScroll: onUserScroll)
        view.revealToken = revealToken
        return view
    }

    func updateNSView(_ nsView: ObserverView, context _: Context) {
        nsView.onUserScroll = onUserScroll
        if nsView.revealToken != revealToken {
            nsView.revealToken = revealToken
            nsView.scheduleReveal(row: revealRow)
        }
    }
}
