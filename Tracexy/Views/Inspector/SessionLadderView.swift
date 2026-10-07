import SwiftUI

// MARK: - SessionLadderView

/// The Ladder facet: the session's two endpoints as vertical lanes and one arrow per
/// retained step between them, oldest at the top. Each arrow opens its frame.
struct SessionLadderView: View {
    // MARK: Internal

    let ladder: SessionLadder
    let inspect: (SessionFrameProvenance) -> Void

    var body: some View {
        if ladder.isEmpty {
            Text("No handshake, close, TLS or datagram steps were retained for this session.")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                header
                ForEach(ladder.steps) { step in
                    row(step)
                }
                if ladder.omittedStepCount > 0 {
                    Text("\(ladder.omittedStepCount.formatted()) later steps are not drawn")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingM)
                }
            }
            .frame(maxWidth: 720, alignment: .leading)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Ladder")
        }
    }

    // MARK: Private

    private static let timeWidth: CGFloat = 72

    private var header: some View {
        HStack(spacing: 0) {
            Spacer().frame(width: Self.timeWidth)
            Text(ladder.leftEndpoint)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text(ladder.rightEndpoint)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .font(Theme.Typography.captionMedium)
        .lineLimit(1)
        .truncationMode(.middle)
        .padding(.bottom, Theme.Metrics.spacingS)
    }

    private var lanes: some View {
        HStack {
            Rectangle().fill(.quaternary).frame(width: 2)
            Spacer()
            Rectangle().fill(.quaternary).frame(width: 2)
        }
    }

    private func row(_ step: SessionLadder.Step) -> some View {
        HStack(spacing: 0) {
            Text(step.offset.map { String(format: "+%.3f s", $0) } ?? "—")
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .frame(width: Self.timeWidth, alignment: .leading)
            Button {
                if let provenance = step.provenance {
                    inspect(provenance)
                }
            } label: {
                ZStack {
                    lanes
                    arrow(step)
                }
                .frame(height: 30)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(step.provenance?.locator == nil)
            .help(step.provenance.map { "Open frame \($0.ordinal.rawValue.formatted())" } ?? "")
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText(step))
        .accessibilityAddTraits(.isButton)
        .accessibilityAction {
            if let provenance = step.provenance {
                inspect(provenance)
            }
        }
    }

    private func arrow(_ step: SessionLadder.Step) -> some View {
        let color: Color = step.isAttention ? .orange : .accentColor
        return VStack(spacing: 1) {
            Text(step.label)
                .font(Theme.Typography.micro)
                .foregroundStyle(step.isAttention ? Color.orange : Color.primary)
                .lineLimit(1)
            HStack(spacing: 0) {
                if step.direction == .bToA {
                    Image(systemName: "arrowtriangle.left.fill")
                        .font(.system(size: Theme.Icon.small))
                        .foregroundStyle(color)
                }
                Rectangle().fill(color).frame(height: 1.5)
                if step.direction == .aToB {
                    Image(systemName: "arrowtriangle.right.fill")
                        .font(.system(size: Theme.Icon.small))
                        .foregroundStyle(color)
                }
            }
        }
        .padding(.horizontal, 3)
    }

    private func accessibilityText(_ step: SessionLadder.Step) -> String {
        let route = switch step.direction {
        case .aToB: "from \(ladder.leftEndpoint) to \(ladder.rightEndpoint)"
        case .bToA: "from \(ladder.rightEndpoint) to \(ladder.leftEndpoint)"
        case nil: "no direction"
        }
        let time = step.offset.map { String(format: "at %.3f seconds", $0) } ?? "untimed"
        return "\(step.label), \(route), \(time)"
    }
}
