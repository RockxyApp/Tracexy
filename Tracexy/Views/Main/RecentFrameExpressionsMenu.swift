import SwiftUI

// MARK: - RecentFrameExpressionsMenu

struct RecentFrameExpressionsMenu: View {
    let state: CaptureFrameListState

    var body: some View {
        Menu("Recent Frame Expressions") {
            if state.recentFrameExpressions.isEmpty {
                Text("No Recent Frame Expressions")
            }
            ForEach(state.recentFrameExpressions, id: \.self) { expression in
                Button(expression) {
                    state.updateFrameExpressionDraft(expression)
                }
                .help(expression)
            }
            if !state.recentFrameExpressions.isEmpty {
                Divider()
                Button("Clear Recent Expressions") { state.clearRecentFrameExpressions() }
            }
        }
    }
}

// MARK: - FrameExpressionSyntaxStatus

struct FrameExpressionSyntaxStatus: View {
    let isValid: Bool?

    var body: some View {
        if isValid == true {
            Label("Draft syntax valid", systemImage: "checkmark.circle")
                .font(Theme.Typography.caption)
                .foregroundStyle(.green)
                .accessibilityLabel("Frame Expression draft syntax valid")
        }
    }
}
