import SwiftUI

// MARK: - FollowHTTP2Section

/// The Stream facet's HTTP/2 section: one row per stream with its request, status
/// and headers, then every frame in capture order behind a disclosure.
struct FollowHTTP2Section: View {
    // MARK: Internal

    let http2: FollowHTTP2Presentation
    let query: String
    /// Opens a captured frame in Layers.
    let openFrame: (SessionFrameProvenance) -> Void

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(http2.streams) { row in
                    streamRow(row)
                    if row.id != http2.streams.last?.id {
                        Divider()
                    }
                }
                DisclosureGroup(isExpanded: $showsFrames) {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(http2.frames) { frame in
                            frameRow(frame)
                        }
                    }
                    .padding(.top, Theme.Metrics.spacingS)
                } label: {
                    Text(http2.frameCount == 1 ? "1 frame" : "\(http2.frameCount.formatted()) frames")
                        .font(Theme.Typography.captionMedium)
                }
                .padding(.top, Theme.Metrics.spacingS)
                ForEach(http2.notes, id: \.self) { note in
                    Text(note)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingS)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(http2.streams.count == 1 ? "HTTP/2, 1 stream" : "HTTP/2, \(http2.streams.count.formatted()) streams")
                .font(Theme.Typography.captionMedium)
        }
        .accessibilityIdentifier("follow.http2")
    }

    // MARK: Private

    @State private var showsFrames = false
    @State private var expandedStreams: Set<UInt32> = []

    private func streamRow(_ row: FollowHTTP2StreamRow) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: Theme.Metrics.spacingM) {
                Text(verbatim: "\(row.id)")
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .help("Stream identifier")
                Text(FollowTranscriptSearch.highlighted(row.request, query: query))
                    .font(Theme.Typography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(row.authority.map { "Authority: \($0)" } ?? row.request)
                Spacer(minLength: Theme.Metrics.spacingM)
                Text(row.status)
                    .font(Theme.Typography.captionMedium)
                    .foregroundStyle(row.isError ? Color(nsColor: .systemRed) : Color.primary)
                    .lineLimit(1)
            }
            HStack(spacing: Theme.Metrics.spacingM) {
                if let elapsed = row.elapsed {
                    Text(elapsed)
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .help("From the frame carrying the request headers to the frame carrying the response headers")
                }
                if let size = row.size {
                    Text(size)
                        .font(Theme.Typography.monoMicro)
                        .foregroundStyle(.secondary)
                        .help("Response data size")
                }
                Spacer(minLength: 0)
                if !row.requestHeaders.isEmpty || !row.responseHeaders.isEmpty {
                    Button(expandedStreams.contains(row.id) ? "Hide Headers" : "Headers") {
                        if expandedStreams.contains(row.id) {
                            expandedStreams.remove(row.id)
                        } else {
                            expandedStreams.insert(row.id)
                        }
                    }
                    .buttonStyle(.link)
                    .font(Theme.Typography.captionMedium)
                    .accessibilityLabel(expandedStreams.contains(row.id)
                        ? "Hide headers for stream \(row.id)"
                        : "Show headers for stream \(row.id)")
                }
                frameLink("Request", provenance: row.requestFrame)
                    .accessibilityLabel("Open request frame for stream \(row.id)")
                if row.responseFrame != nil {
                    frameLink("Response", provenance: row.responseFrame)
                        .accessibilityLabel("Open response frame for stream \(row.id)")
                }
            }
            if expandedStreams.contains(row.id) {
                headerList("Request headers", row.requestHeaders)
                headerList("Response headers", row.responseHeaders)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder
    private func headerList(_ title: LocalizedStringKey, _ headers: [HPACKHeader]) -> some View {
        if !headers.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(Theme.Typography.captionMedium)
                    .foregroundStyle(.secondary)
                ForEach(Array(headers.enumerated()), id: \.offset) { _, header in
                    Text(FollowTranscriptSearch.highlighted("\(header.name): \(header.value)", query: query))
                        .font(Theme.Typography.monoMicro)
                        .lineLimit(3)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
            .padding(.leading, Theme.Metrics.spacingL)
            .padding(.top, 2)
        }
    }

    private func frameRow(_ row: FollowHTTP2FrameRow) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(row.fromClient ? "Client" : "Server")
                .font(Theme.Typography.captionMedium)
                .foregroundStyle(.secondary)
                .frame(width: 44, alignment: .leading)
            Text(row.type)
                .font(Theme.Typography.monoMicro)
                .frame(width: 104, alignment: .leading)
            Text(row.streamID == 0 ? "Connection" : "Stream \(row.streamID)")
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .frame(width: 80, alignment: .leading)
            Text(row.detail)
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
                .help(row.detail)
            Spacer(minLength: Theme.Metrics.spacingS)
            Text(row.length == 1 ? "1 byte" : "\(row.length.formatted()) bytes")
                .font(Theme.Typography.monoMicro)
                .foregroundStyle(.secondary)
                .help("Payload length")
            frameLink("Frame", provenance: row.frame)
                .accessibilityLabel("Open the captured frame for \(row.type) on stream \(row.streamID)")
        }
        .accessibilityElement(children: .contain)
    }

    private func frameLink(_ label: LocalizedStringKey, provenance: SessionFrameProvenance?) -> some View {
        Button(label) {
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
}
