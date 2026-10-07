import SwiftUI

// MARK: - SessionTag + color

extension SessionTag {
    var color: Color {
        switch self {
        case .red: .red
        case .orange: .orange
        case .yellow: .yellow
        case .green: .green
        case .blue: .blue
        case .purple: .purple
        case .gray: .gray
        }
    }
}

// MARK: - SessionTagMenu

/// Tag ▸ Red … Gray, Clear Tags — for the sessions a menu acts on.
struct SessionTagMenu: View {
    let coordinator: MainContentCoordinator
    let sessionIDs: [UUID]

    var body: some View {
        Menu {
            ForEach(SessionTag.allCases) { tag in
                Toggle(isOn: Binding(
                    get: { coordinator.allSessions(sessionIDs, carry: tag) },
                    set: { _ in coordinator.toggleTag(tag, on: sessionIDs) }
                )) {
                    Label {
                        Text(tag.title)
                    } icon: {
                        Image(systemName: "circle.fill").foregroundStyle(tag.color)
                    }
                }
            }
            Divider()
            Button("Clear Tags") {
                coordinator.clearTags(on: sessionIDs)
            }
            .disabled(!sessionIDs.contains { !coordinator.investigationNotes.tags(onSession: $0).isEmpty })
        } label: {
            Label("Tag", systemImage: "tag")
        }
        .disabled(coordinator.investigationNotes.scope == nil)
    }
}

// MARK: - SessionTagDots

/// The tags on one session as small colored dots, with their names for VoiceOver.
struct SessionTagDots: View {
    let tags: [SessionTag]

    var body: some View {
        if !tags.isEmpty {
            HStack(spacing: -3) {
                ForEach(tags) { tag in
                    Circle()
                        .fill(tag.color)
                        .overlay(Circle().stroke(Color(nsColor: .windowBackgroundColor), lineWidth: 1))
                        .frame(width: 8, height: 8)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Tagged " + ListFormatter.localizedString(byJoining: tags.map(\.title)))
            .help(ListFormatter.localizedString(byJoining: tags.map(\.title)))
        }
    }
}
