import SwiftUI

// MARK: - Inspector panel toggles

@MainActor
extension MainContentCoordinator {
    /// Bottom evidence inspector. Hiding it by hand also cancels the automatic
    /// reveal — a panel the user dismissed must not reappear on the next
    /// selection.
    func toggleInspectorBottom() {
        let ws = activeWorkspace
        let willHide = ws.inspectorLayout == .bottom
        withAnimation(.smooth(duration: 0.18)) {
            ws.inspectorLayout = willHide ? .hidden : .bottom
        }
        layoutPreferences.rememberInspectorLayout(ws.inspectorLayout)
        // Opening it by hand is the user asking for it back, so it cancels an
        // earlier dismissal. Without this the two rules fight: panels start
        // closed at launch, and a user who had once dismissed the inspector
        // could never get it to come back on its own again — they would be
        // re-opening it manually every single launch.
        ws.allowsAutomaticInspectorReveal = !willHide
        layoutPreferences.rememberAutomaticInspectorReveal(!willHide)
    }

    /// Right-hand interpretation column. Never auto-revealed: it earns its space
    /// only once the user asks for it.
    func toggleContextDock() {
        let ws = activeWorkspace
        withAnimation(.smooth(duration: 0.18)) {
            ws.isContextDockVisible.toggle()
        }
        layoutPreferences.rememberContextDockVisible(ws.isContextDockVisible)
    }
}
