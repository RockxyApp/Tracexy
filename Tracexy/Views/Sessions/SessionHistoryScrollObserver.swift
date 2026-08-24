import AppKit
import SwiftUI

/// Observes user-owned wheel/trackpad navigation inside a SwiftUI `Table`
/// without intercepting the event. Programmatic selection/reveal emits no scroll
/// event, so coordinator-driven Follow Live updates do not turn themselves off.
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

        // MARK: Private

        private var eventMonitor: Any?

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

    let onUserScroll: () -> Void

    static func dismantleNSView(_ nsView: ObserverView, coordinator _: ()) {
        nsView.stopObserving()
    }

    func makeNSView(context _: Context) -> ObserverView {
        ObserverView(onUserScroll: onUserScroll)
    }

    func updateNSView(_ nsView: ObserverView, context _: Context) {
        nsView.onUserScroll = onUserScroll
    }
}
