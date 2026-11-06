import SwiftUI

// MARK: - SourceFrameCommentMenuItem

struct SourceFrameCommentMenuItem: View {
    let row: CaptureFrameRow
    let coordinator: MainContentCoordinator
    let presentation: FrameSourceCommentsPresentationModel

    var body: some View {
        if row.hasComment {
            Button("View Source Comments…") { presentation.present(row, using: coordinator) }
                .disabled(!coordinator.isViewingSavedCapture)
        }
    }
}

// MARK: - SourceFrameCommentsSheet

struct SourceFrameCommentsSheet: View {
    // MARK: Internal

    let ordinal: UInt64
    let presentation: SourceFrameCommentPresentation
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            heading
            explanation
            Divider()
            content
            doneButton
        }
        .padding(Theme.Metrics.spacingL)
        .frame(minWidth: 420, minHeight: 280)
    }

    // MARK: Private

    private var heading: some View {
        Text("Source Comments — Frame \(ordinal.formatted())")
            .font(Theme.Typography.bodyEmphasis)
    }

    private var explanation: some View {
        Text("Read-only comments stored in this PCAPNG capture. They are separate from your Tracexy frame comment.")
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
    }

    @ViewBuilder private var content: some View {
        switch presentation {
        case .loading:
            ProgressView("Reading source comments…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case let .loaded(.comments(result)):
            comments(result)
        case .loaded(.unavailable),
             .loaded(.superseded):
            ContentUnavailableView(
                "Source Comments Unavailable",
                systemImage: "text.bubble",
                description: Text(
                    "The capture source changed, the packet options were malformed, or this comment could not be read safely."
                )
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var doneButton: some View {
        HStack {
            Spacer()
            Button("Done", action: onDone)
                .keyboardShortcut(.defaultAction)
        }
    }

    private func comments(_ result: CaptureFrameCommentReadResult) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
                ForEach(result.comments.indices, id: \.self) { index in
                    SourceFrameCommentCard(index: index, comment: result.comments[index])
                }
                if result.omittedCount > 0 {
                    Label(
                        "\(result.omittedCount.formatted()) additional comments omitted (maximum 16).",
                        systemImage: "ellipsis.circle"
                    )
                    .font(Theme.Typography.caption)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - SourceFrameCommentCard

private struct SourceFrameCommentCard: View {
    // MARK: Internal

    let index: Int
    let comment: CaptureBoundedText

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            heading
            message
            SourceFrameCommentNotices(comment: comment)
        }
        .padding(Theme.Metrics.spacingM)
        .background(Color(nsColor: .controlBackgroundColor), in: cardShape)
        .overlay {
            cardShape.strokeBorder(Color.primary.opacity(Theme.Glass.contentStrokeOpacity), lineWidth: 0.5)
        }
    }

    // MARK: Private

    private var cardShape: RoundedRectangle {
        RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius)
    }

    private var heading: some View {
        Text("Comment \(index + 1)")
            .font(Theme.Typography.captionMedium)
            .foregroundStyle(.secondary)
    }

    private var message: some View {
        let text = comment.text.isEmpty ? "(Empty comment)" : comment.text
        return Text(text)
            .font(Theme.Typography.body)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - SourceFrameCommentNotices

private struct SourceFrameCommentNotices: View {
    let comment: CaptureBoundedText

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            if comment.isTruncated {
                Label("Comment was truncated at 256 bytes.", systemImage: "exclamationmark.triangle")
                    .font(Theme.Typography.caption)
            }
            if comment.isLossy {
                Label(
                    "Source comment contains invalid UTF-8; replacement characters are shown.",
                    systemImage: "exclamationmark.triangle"
                )
                .font(Theme.Typography.caption)
            }
        }
    }
}
