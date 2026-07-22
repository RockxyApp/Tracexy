import SwiftUI

// MARK: - SecurityFindingsView

/// The Security surface: Tracexy's take on Wireshark "Expert Information" — a
/// severity-ranked list of problems (Errors / Warnings / Notes), each row
/// click-to-session. This is the "what's wrong" lens, deliberately distinct from
/// the raw Sessions stream (which shows every conversation).
struct SecurityFindingsView: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        let findings = coordinator.findings
        Group {
            if findings.isEmpty {
                emptyState
            } else {
                List {
                    ForEach(Finding.Severity.allCases, id: \.self) { severity in
                        let rows = findings.filter { $0.severity == severity }
                        if !rows.isEmpty {
                            Section {
                                ForEach(rows) { finding in
                                    row(finding)
                                }
                            } header: {
                                sectionHeader(severity, count: rows.count)
                            }
                        }
                    }
                    if findings.count >= MainContentCoordinator.maxFindings {
                        Text(
                            "Showing the first \(MainContentCoordinator.maxFindings.formatted()) findings — narrow the capture with filters to see the rest."
                        )
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(.inset)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Private

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Findings", systemImage: "checkmark.seal")
        } description: {
            Text("Traffic looks healthy — no errors, warnings, or notes so far.")
        }
    }

    private func sectionHeader(_ severity: Finding.Severity, count: Int) -> some View {
        HStack(spacing: 6) {
            Image(systemName: severity.systemImage).foregroundStyle(severity.tint)
            Text(title(for: severity))
            Text(count.formatted())
                .font(Theme.Typography.monoSmall)
                .foregroundStyle(.secondary)
        }
    }

    private func row(_ finding: Finding) -> some View {
        Button {
            guard let id = finding.sessionID,
                  let session = coordinator.sessions.first(where: { $0.id == id }) else
            {
                return
            }
            coordinator.selectSidebarItem(.sessions)
            coordinator.select(session)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: finding.severity.systemImage)
                    .foregroundStyle(finding.severity.tint)
                    .frame(width: 18)
                VStack(alignment: .leading, spacing: 1) {
                    Text(finding.title).font(Theme.Typography.surfaceTitle).lineLimit(1)
                    Text(finding.subtitle).font(Theme.Typography.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: Theme.Icon.small)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func title(for severity: Finding.Severity) -> String {
        switch severity {
        case .error: String(localized: "Errors")
        case .warning: String(localized: "Warnings")
        case .note: String(localized: "Notes")
        }
    }
}
