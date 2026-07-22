import SwiftUI

// MARK: - MCPSettingsView

/// MCP server + AI-insight preferences. These persist; the in-app MCP server and
/// AI-insight provider are on the roadmap and not yet running, so the controls
/// store intent only for now.
struct MCPSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSectionTitle("MCP Server")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $mcpEnabled,
                    title: "Enable in-app MCP server",
                    description: "Run a local MCP server so AI clients can query captured sessions."
                )
                SettingsRow(label: "Port:") {
                    TextField("7420", value: $mcpPort, format: .number.grouping(.never))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: metrics.bodyFontSize, design: .monospaced))
                        .frame(width: metrics.fieldWidth(80))
                        .frame(minHeight: metrics.controlHeight)
                        .disabled(!mcpEnabled)
                }
                SettingsCheckbox(
                    isOn: $mcpExposeSessions,
                    title: "Expose sessions to AI clients",
                    description: "Allow connected MCP clients to read conversation summaries and findings."
                )
                .disabled(!mcpEnabled)
            }

            SettingsSectionTitle("AI Insights")
            SettingsCard {
                SettingsCheckbox(
                    isOn: $aiInsights,
                    title: "Enable AI insights",
                    description: "Summarize latency, errors, and security findings for the active workspace."
                )
                SettingsRow(label: "Provider:") {
                    Picker("", selection: $aiProvider) {
                        Text("None").tag("none")
                        Text("Claude (via MCP)").tag("claude")
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                    .disabled(!aiInsights)
                }
            }
        }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.mcpEnabled) private var mcpEnabled = true
    @AppStorage(SettingsKeys.mcpPort) private var mcpPort = 7_420
    @AppStorage(SettingsKeys.mcpExposeSessions) private var mcpExposeSessions = true
    @AppStorage(SettingsKeys.aiInsights) private var aiInsights = false
    @AppStorage(SettingsKeys.aiProvider) private var aiProvider = "none"

    private let metrics = SettingsDisplayMetrics.standard
}

#Preview {
    MCPSettingsView()
}
