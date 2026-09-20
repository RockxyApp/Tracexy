import AppKit
import SwiftUI

// MARK: - CaptureInfoView

/// File ▸ Get Info (⌘I): the capture's own facts — what the file says about
/// itself — in a regular auxiliary window (HIG *Panels*: an Info window keeps the
/// same contents and is a window, not a panel). Grouped form sections; a native
/// `Table` for interfaces; every value comes from ``CaptureInfoSnapshot`` and
/// nothing is computed here. The window is bound to the capture it was opened
/// for and shows a closed state if that capture goes away.
struct CaptureInfoView: View {
    // MARK: Internal

    let coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let snapshot = coordinator.captureInfoSnapshot {
                content(snapshot)
                    .navigationTitle(Text("\(snapshot.title) Info"))
            } else {
                ContentUnavailableView {
                    Label("No Capture Open", systemImage: "doc")
                } description: {
                    Text("Open a capture or start a live capture, then choose File ▸ Get Info.")
                } actions: {
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                }
                .navigationTitle("Capture Info")
            }
        }
        .frame(minWidth: 560, minHeight: 480)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    coordinator.copyCaptureInfoReport()
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .help("Copy every value shown here as text")
                .disabled(coordinator.captureInfoSnapshot == nil)
            }
        }
        .accessibilityIdentifier("capture-info-window")
    }

    // MARK: Private

    private static let fileAuthoredTextNote = String(
        localized: """
        Comments, names, filters and application strings above were written by the tool that created this \
        file. They are shown only here and never enter Sources, History, automation or the Assistant.
        """
    )

    @Environment(\.dismiss) private var dismiss
    @State private var interfaceSortOrder: [KeyPathComparator<CaptureInterface>] = [
        KeyPathComparator(\.id.interfaceID),
    ]

    private func content(_ snapshot: CaptureInfoSnapshot) -> some View {
        Form {
            generalSection(snapshot)
            timeSection(snapshot)
            if let properties = snapshot.properties {
                ForEach(properties.sections) { section in
                    sectionSection(section, showsIndex: properties.sections.count > 1)
                }
                if properties.interfaceCount > 0 {
                    interfacesSection(properties)
                }
                statisticsSection(snapshot, properties)
                otherBlocksSection(properties)
                coverageSection(snapshot, properties)
            } else {
                liveSection(snapshot)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: General

    private func generalSection(_ snapshot: CaptureInfoSnapshot) -> some View {
        Section("General") {
            LabeledContent("Name", value: snapshot.fileName)
            if let url = snapshot.fileURL {
                LabeledContent("Where") {
                    HStack(spacing: Theme.Metrics.spacingS) {
                        Text(url.deletingLastPathComponent().path)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([url])
                        }
                        .controlSize(.small)
                    }
                }
                if case let .saved(capture) = snapshot.source {
                    LabeledContent("Kind", value: capture.isReferenced ? "Opened in place" : "Managed copy in Library")
                }
            }
            if let properties = snapshot.properties {
                LabeledContent("Format", value: CaptureInfoFormatting.format(properties))
                LabeledContent("Size", value: CaptureInfoFormatting.bytes(properties.fileSize))
                if case let .pcap(facts) = properties.container {
                    LabeledContent("Link type", value: CaptureInfoFormatting.linkType(facts.linkType))
                    LabeledContent("Snapshot length", value: CaptureInfoFormatting.snapLength(facts.snapLength))
                    if let fcs = facts.fcsLengthWords {
                        LabeledContent("FCS length hint", value: "\(fcs * 2) bytes")
                    }
                }
                digestsRows(snapshot)
            }
        }
    }

    @ViewBuilder
    private func digestsRows(_ snapshot: CaptureInfoSnapshot) -> some View {
        switch snapshot.hashState {
        case .idle:
            LabeledContent("Digests") {
                Button("Compute SHA-256 and SHA-1") { coordinator.beginCaptureHash() }
                    .controlSize(.small)
            }
        case let .computing(fraction):
            LabeledContent("Digests") {
                HStack(spacing: Theme.Metrics.spacingM) {
                    if let fraction {
                        ProgressView(value: fraction)
                            .frame(width: 160)
                            .accessibilityValue(Text(fraction, format: .percent))
                    } else {
                        ProgressView().controlSize(.small)
                    }
                    Button("Cancel") { coordinator.cancelCaptureHash() }
                        .controlSize(.small)
                }
            }
        case let .done(digests):
            LabeledContent("SHA-256") {
                Text(digests.sha256).font(Theme.Typography.mono).textSelection(.enabled)
            }
            LabeledContent("SHA-1") {
                Text(digests.sha1).font(Theme.Typography.mono).textSelection(.enabled)
            }
        case let .failed(message):
            LabeledContent("Digests") {
                HStack(spacing: Theme.Metrics.spacingM) {
                    Text(message).foregroundStyle(.secondary)
                    Button("Try Again") { coordinator.beginCaptureHash() }
                        .controlSize(.small)
                }
            }
        }
    }

    // MARK: Time

    private func timeSection(_ snapshot: CaptureInfoSnapshot) -> some View {
        Section("Time") {
            if let properties = snapshot.properties {
                LabeledContent(
                    "First frame",
                    value: properties.firstTimestamp.map(CaptureInfoFormatting.instant) ?? "Unknown"
                )
                LabeledContent(
                    "Last frame",
                    value: properties.lastTimestamp.map(CaptureInfoFormatting.instant) ?? "Unknown"
                )
                LabeledContent("Elapsed", value: properties.elapsed.map(CaptureInfoFormatting.elapsed) ?? "Unknown")
                LabeledContent(
                    "Time order",
                    value: properties.isStrictlyTimeOrdered
                        ? "Strict"
                        : "\(properties.outOfOrderFrameCount.formatted()) frames out of order"
                )
                if properties.untimedFrameCount > 0 {
                    LabeledContent("Untimed frames", value: properties.untimedFrameCount.formatted())
                }
            } else if let started = snapshot.captureStartedAt {
                LabeledContent("Started", value: CaptureInfoFormatting.instant(started))
            } else {
                LabeledContent("Started", value: "Unknown")
            }
        }
    }

    // MARK: Sections / interfaces

    @ViewBuilder
    private func sectionSection(_ section: CaptureSection, showsIndex: Bool) -> some View {
        let title = showsIndex ? "Section \(section.id + 1)" : "Capture"
        Section(title) {
            LabeledContent("Byte order", value: section.littleEndian ? "Little-endian" : "Big-endian")
            LabeledContent("Version", value: "\(section.majorVersion).\(section.minorVersion)")
            if let hardware = section.hardware {
                LabeledContent("Hardware", value: Self.text(hardware))
            }
            if let os = section.operatingSystem {
                LabeledContent("OS", value: Self.text(os))
            }
            if let application = section.application {
                LabeledContent("Application", value: Self.text(application))
            }
            ForEach(Array(section.comments.values.enumerated()), id: \.offset) { index, comment in
                LabeledContent(index == 0 ? "Comment" : "Comment \(index + 1)") {
                    Text(Self.text(comment)).textSelection(.enabled)
                }
            }
            if section.comments.omittedCount > 0 {
                LabeledContent("More comments", value: "\(section.comments.omittedCount.formatted()) not shown")
            }
            if section.interfaceOverflowCount > 0 {
                LabeledContent(
                    "Interfaces",
                    value: "\(section.interfaces.count.formatted()) shown, \(section.interfaceOverflowCount.formatted()) more declared"
                )
            }
        }
    }

    private func interfacesSection(_ properties: CaptureFileProperties) -> some View {
        Section("Interfaces") {
            Table(properties.allInterfaces, sortOrder: $interfaceSortOrder) {
                TableColumn("Interface", value: \.id.interfaceID) { interface in
                    Text(interface.displayName)
                }
                TableColumn("Description") { interface in
                    Text(interface.interfaceDescription.map(Self.text) ?? "—")
                }
                TableColumn("Link type", value: \.linkType) { interface in
                    Text(CaptureInfoFormatting.linkType(interface.linkType))
                }
                TableColumn("Snaplen", value: \.snapLength) { interface in
                    Text(CaptureInfoFormatting.snapLength(interface.snapLength))
                }
                TableColumn("Resolution", value: \.ticksPerSecond) { interface in
                    Text(CaptureInfoFormatting.resolution(interface.ticksPerSecond))
                }
                TableColumn("Filter") { interface in
                    Text(interface.filter.map(Self.text) ?? "—")
                }
                TableColumn("Frames", value: \.frameCount) { interface in
                    Text(interface.frameCount.formatted()).monospacedDigit()
                }
                TableColumn("Dropped") { interface in
                    Text(interface.statistics?.dropped.map { $0.formatted() } ?? "—").monospacedDigit()
                }
            }
            .alternatingRowBackgrounds()
            .frame(minHeight: 120, idealHeight: 44 + CGFloat(properties.interfaceCount) * 24)
            .accessibilityIdentifier("capture-info-interfaces")
        }
    }

    // MARK: Statistics / other / coverage

    private func statisticsSection(_ snapshot: CaptureInfoSnapshot, _ properties: CaptureFileProperties) -> some View {
        Section("Statistics") {
            LabeledContent("Frames", value: properties.totalFrames.formatted())
            if let activity = snapshot.activity {
                LabeledContent("Bytes", value: CaptureInfoFormatting.bytes(UInt64(max(0, activity.totalBytes))))
                if activity.totalFrames > 0 {
                    LabeledContent(
                        "Average frame size",
                        value: CaptureInfoFormatting.bytes(UInt64(activity.totalBytes / activity.totalFrames))
                    )
                }
                if let duration = activity.duration, duration > 0 {
                    LabeledContent(
                        "Average frames/s",
                        value: (Double(activity.totalFrames) / duration)
                            .formatted(.number.precision(.fractionLength(1)))
                    )
                }
            }
            LabeledContent("Sessions", value: snapshot.sessionCount.formatted())
            if snapshot.visibleSessionCount != snapshot.sessionCount {
                LabeledContent("Sessions in view", value: snapshot.visibleSessionCount.formatted())
            }
            if properties.commentedFrameCount > 0 {
                LabeledContent("Commented frames", value: properties.commentedFrameCount.formatted())
            }
        }
    }

    @ViewBuilder
    private func otherBlocksSection(_ properties: CaptureFileProperties) -> some View {
        let blocks = properties.blockInventory
        let hasAny = blocks.nameResolutionBlockCount > 0 || !blocks.decryptionSecrets.isEmpty
            || blocks.customBlockCount > 0 || blocks.obsoletePacketBlockCount > 0
            || blocks.systemdJournalBlockCount > 0 || !blocks.unknownBlockTypes.isEmpty
        if hasAny {
            Section("Other Blocks") {
                if blocks.nameResolutionBlockCount > 0 {
                    LabeledContent(
                        "Name resolution",
                        value: "\(blocks.nameResolutionBlockCount.formatted()) blocks — not applied to Sources"
                    )
                }
                if !blocks.decryptionSecrets.isEmpty {
                    LabeledContent("Decryption secrets") {
                        VStack(alignment: .trailing, spacing: 2) {
                            ForEach(Array(blocks.decryptionSecrets.enumerated()), id: \.offset) { _, secrets in
                                Text("\(secrets.kindLabel), \(CaptureInfoFormatting.bytes(secrets.secretsLength))")
                            }
                            Text("Present in the file. Tracexy does not read or use them.")
                                .font(Theme.Typography.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                if blocks.customBlockCount > 0 {
                    LabeledContent("Custom blocks", value: blocks.customBlockCount.formatted())
                }
                if blocks.obsoletePacketBlockCount > 0 {
                    LabeledContent(
                        "Obsolete packet blocks",
                        value: "\(blocks.obsoletePacketBlockCount.formatted()) — not decoded"
                    )
                }
                if blocks.systemdJournalBlockCount > 0 {
                    LabeledContent("systemd journal blocks", value: blocks.systemdJournalBlockCount.formatted())
                }
                ForEach(blocks.unknownBlockTypes.keys.sorted(), id: \.self) { type in
                    LabeledContent(
                        "Unknown block 0x\(String(type, radix: 16, uppercase: true))",
                        value: (blocks.unknownBlockTypes[type] ?? 0).formatted()
                    )
                }
                if blocks.unknownBlockOverflowCount > 0 {
                    LabeledContent("More unknown blocks", value: blocks.unknownBlockOverflowCount.formatted())
                }
            }
        }
    }

    @ViewBuilder
    private func coverageSection(_ snapshot: CaptureInfoSnapshot, _ properties: CaptureFileProperties) -> some View {
        let metadata = snapshot.metadata
        let hasCaveat = (metadata?.hasCoverageCaveat ?? false) || snapshot.warning != nil || properties
            .carriesFileAuthoredText
        if hasCaveat {
            Section("Coverage") {
                if let warning = snapshot.warning {
                    LabeledContent("Completeness", value: warning)
                }
                if let metadata, metadata.undecodableLinkLayerFrameCount > 0 {
                    LabeledContent(
                        "Undecoded link layer",
                        value: "\(metadata.undecodableLinkLayerFrameCount.formatted()) frames"
                    )
                }
                if let metadata, metadata.linkTypeOverflowFrameCount > 0 {
                    LabeledContent(
                        "Link types",
                        value: "more than \(metadata.linkTypeCounts.count.formatted()) distinct"
                    )
                }
                if properties.carriesFileAuthoredText {
                    Text(Self.fileAuthoredTextNote)
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func liveSection(_ snapshot: CaptureInfoSnapshot) -> some View {
        Section("Capture") {
            if case let .live(interface) = snapshot.source {
                LabeledContent("Interface", value: interface)
            }
            LabeledContent("Sessions", value: snapshot.sessionCount.formatted())
            Text(
                "Container facts (format, sections, comments, digests) are available once the capture is saved and opened as a file."
            )
            .font(Theme.Typography.caption)
            .foregroundStyle(.secondary)
        }
    }

    private static func text(_ value: CaptureBoundedText) -> String {
        var text = value.text
        if value.isTruncated {
            text += "…"
        }
        return text
    }
}
