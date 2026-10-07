import AppKit
import SwiftUI

// MARK: - FirewallRulesWindow

/// Tools ▸ Firewall Rules: rule text that blocks or allows the selected session's
/// traffic in a chosen firewall's syntax, as Wireshark's Firewall ACL Rules does.
/// Nothing is applied; copy the text into the firewall yourself.
struct FirewallRulesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let session = coordinator.selectedSession,
               let source = session.sourceEndpointValue,
               let destination = session.destinationEndpointValue
            {
                form(FirewallRules.Request(
                    product: product, scope: scope, source: source, destination: destination,
                    transport: session.protocolStack.contains(.tcp)
                        ? "tcp" : session.protocolStack.contains(.udp) ? "udp" : nil,
                    deny: deny, inbound: inbound
                ))
            } else {
                ContentUnavailableView(
                    "No Session Selected",
                    systemImage: "shield.lefthalf.filled",
                    description: Text("Select a session with IP addresses in the main window to write a rule for it.")
                )
            }
        }
        .frame(minWidth: 520, minHeight: 300)
    }

    // MARK: Private

    @State private var product: FirewallProduct = .pf
    @State private var scope: FirewallRuleScope = .conversation
    @State private var deny = true
    @State private var inbound = true

    private func form(_ request: FirewallRules.Request) -> some View {
        let rule = FirewallRules.rule(request)
        return Form {
            Picker("Firewall", selection: $product) {
                ForEach(FirewallProduct.allCases) { Text($0.title).tag($0) }
            }
            Picker("Match", selection: $scope) {
                ForEach(FirewallRuleScope.allCases) { Text($0.title).tag($0) }
            }
            Picker("Action", selection: $deny) {
                Text("Block").tag(true)
                Text("Allow").tag(false)
            }
            .pickerStyle(.segmented)
            Picker("Direction", selection: $inbound) {
                Text("Inbound").tag(true)
                Text("Outbound").tag(false)
            }
            .pickerStyle(.segmented)
            Section {
                if let rule {
                    Text(rule)
                        .font(Theme.Typography.mono)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text("This session has no TCP or UDP port to match.")
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("\(request.source.display) → \(request.destination.display)")
            } footer: {
                HStack {
                    Spacer()
                    Button("Copy Rule") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(rule ?? "", forType: .string)
                    }
                    .disabled(rule == nil)
                }
            }
        }
        .formStyle(.grouped)
    }
}
