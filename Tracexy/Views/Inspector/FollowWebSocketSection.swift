import SwiftUI

// MARK: - FollowWebSocketSection

/// The Stream facet's WebSocket section: every message after the upgrade in capture
/// order, then every frame behind a disclosure.
struct FollowWebSocketSection: View {
    // MARK: Internal

    let webSocket: FollowWebSocketPresentation
    let query: String
    /// Opens a captured frame in Layers.
    let openFrame: (SessionFrameProvenance) -> Void

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(webSocket.messages) { row in
                        messageRow(row)
                        if row.id != webSocket.messages.last?.id {
                            Divider()
                        }
                    }
                }
                DisclosureGroup(isExpanded: $showsFrames) {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(webSocket.frames) { frame in
                            frameRow(frame)
                        }
                    }
                    .padding(.top, Theme.Metrics.spacingS)
                } label: {
                    Text(webSocket.frameCount == 1 ? "1 frame" : "\(webSocket.frameCount.formatted()) frames")
                        .font(Theme.Typography.captionMedium)
                }
                .padding(.top, Theme.Metrics.spacingS)
                ForEach(webSocket.notes, id: \.self) { note in
                    Text(note)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingS)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(webSocket.messageCount == 1
                ? "WebSocket, 1 message"
                : "WebSocket, \(webSocket.messageCount.formatted()) messages")
                .font(Theme.Typography.captionMedium)
        }
        .accessibilityIdentifier("follow.websocket")
    }

    // MARK: Private

    @State private var showsFrames = false

    private func messageRow(_ row: FollowWebSocketMessageRow) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Metrics.spacingM) {
            Text(row.fromClient ? "Client" : "Server")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
                .frame(width: 44, alignment: .leading)
            Text(row.kind)
                .font(Theme.Typography.monoMicro)
                .frame(width: 52, alignment: .leading)
            Text(FollowTranscriptSearch.highlighted(row.content, query: query))
                .font(Theme.Typography.monoSmall)
                .lineLimit(1)
                .truncationMode(.tail)
                .textSelection(.enabled)
                .help(row.content)
            Spacer(minLength: Theme.Metrics.spacingS)
            Text(row.size)
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .help(row.isCompressed
                    ? "Size after decompressing; the message was compressed with permessage-deflate"
                    : "Message size")
            frameLink(provenance: row.frame)
                .accessibilityLabel("Open the first frame of \(row.kind) message \(row.id + 1)")
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
    }

    private func frameRow(_ row: FollowWebSocketFrameRow) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(row.fromClient ? "Client" : "Server")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
                .frame(width: 44, alignment: .leading)
            Text(row.opcode)
                .font(Theme.Typography.monoMicro)
                .frame(width: 88, alignment: .leading)
            Text(Self.flags(row))
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer(minLength: Theme.Metrics.spacingS)
            Text(row.length == 1 ? "1 byte" : "\(row.length.formatted()) bytes")
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .help("Payload length on the wire")
            frameLink(provenance: row.frame)
                .accessibilityLabel("Open the captured frame for \(row.opcode) frame \(row.id + 1)")
        }
        .accessibilityElement(children: .contain)
    }

    private func frameLink(provenance: SessionFrameProvenance?) -> some View {
        Button("Frame") {
            if let provenance {
                openFrame(provenance)
            }
        }
        .buttonStyle(.link)
        .font(Theme.Typography.captionMedium)
        .disabled(provenance?.locator == nil)
        .help(provenance?.locator == nil
            ? "This frame cannot be opened from the current source."
            : "Open this frame in Layers")
    }

    private static func flags(_ row: FollowWebSocketFrameRow) -> String {
        var flags: [String] = []
        if row.fin {
            flags.append("FIN")
        }
        if row.compressed {
            flags.append("RSV1")
        }
        if row.masked {
            flags.append("Masked")
        }
        return flags.joined(separator: ", ")
    }
}
