import SwiftUI

// MARK: - MCPSettingsView

/// Truthful placeholder for the planned MCP/AI surface. No listener, client
/// connection or provider exists yet, so this view exposes no switch that could
/// imply a service is running or capture data is being shared.
struct MCPSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("MCP Server") {
                plannedCapability(
                    title: "No server is running",
                    detail: "Tracexy does not open a port or expose capture data. A reviewed, bounded local automation boundary must land before an MCP transport can be enabled."
                )
            }

            SettingsSection("AI Insights") {
                plannedCapability(
                    title: "Not connected",
                    detail: "No provider receives sessions or evidence. Any future insight request must show the exact redacted snapshot and require explicit user review."
                )
            }
        }
    }

    // MARK: Private

    private func plannedCapability(title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
            Image(systemName: "lock.shield")
                .foregroundStyle(Color.accentColor)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                Text(title)
                    .font(Theme.Typography.bodyEmphasis)
                Text(detail)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Text("Planned")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, Theme.Metrics.spacingS)
                .padding(.vertical, Theme.Metrics.spacingS)
                .background(.quaternary, in: Capsule())
        }
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    MCPSettingsView()
}
