import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - PacketBytesWindow

/// Show Packet Bytes: one run of captured bytes — a frame, a selected field, or an
/// HTTP body — decoded (Base64, gzip, deflate, percent, quoted-printable, ROT-13,
/// hex digits) and shown as text, pretty JSON, a hex dump, a C array or an image,
/// with an optional byte range, as Wireshark's dialog of the same name.
struct PacketBytesWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        Group {
            if let subject = coordinator.packetBytesInspection.subject {
                content(subject)
            } else {
                ContentUnavailableView(
                    "No Bytes Chosen",
                    systemImage: "doc.text.magnifyingglass",
                    description: Text(
                        "Choose Show Bytes… in the Layers facet, or Show Body… on an HTTP exchange in the Stream facet."
                    )
                )
            }
        }
        .frame(minWidth: 560, minHeight: 360)
        .onChange(of: coordinator.packetBytesInspection.revision, initial: true) { _, _ in
            if let subject = coordinator.packetBytesInspection.subject {
                decoding = subject.suggestedDecoding
                presentation = subject.suggestedPresentation
                rangeStart = 0
                rangeEnd = subject.bytes.count
            }
        }
    }

    // MARK: Private

    @State private var decoding: PacketBytesDecoding = .none
    @State private var presentation: PacketBytesPresentation = .text
    @State private var rangeStart = 0
    @State private var rangeEnd = 0

    private func content(_ subject: PacketBytesSubject) -> some View {
        let start = min(max(0, rangeStart), subject.bytes.count)
        let end = min(max(start, rangeEnd), subject.bytes.count)
        let input = Array(subject.bytes[start ..< end])
        let decoded = Result { () throws(PacketBytesDecoding.Failure) -> [UInt8] in try decoding.decode(input) }
        return VStack(spacing: 0) {
            controls(subject)
                .padding(Theme.Metrics.spacingL)
            Divider()
            switch decoded {
            case let .success(bytes):
                output(bytes)
            case let .failure(failure):
                ContentUnavailableView(
                    "Can’t Decode as \(decoding.title)",
                    systemImage: "exclamationmark.triangle",
                    description: Text(Self.message(failure))
                )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .tracexySafeAreaBar(edge: .bottom) {
            footer(inputCount: input.count, decoded: try? decoded.get(), title: subject.title)
        }
    }

    private func controls(_ subject: PacketBytesSubject) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingM) {
            Text(subject.title)
                .font(Theme.Typography.bodyEmphasis)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(subject.title)
            HStack(spacing: Theme.Metrics.spacingL) {
                Picker("Decode as", selection: $decoding) {
                    ForEach(PacketBytesDecoding.allCases) { step in
                        Text(step.title).tag(step)
                    }
                }
                .fixedSize()
                Picker("Show as", selection: $presentation) {
                    ForEach(PacketBytesPresentation.allCases) { kind in
                        Text(kind.title).tag(kind)
                    }
                }
                .fixedSize()
                Spacer(minLength: 0)
                HStack(spacing: Theme.Metrics.spacingS) {
                    Text("Bytes")
                        .foregroundStyle(.secondary)
                    TextField("Start", value: $rangeStart, format: .number)
                        .frame(width: 64)
                        .help("First byte of the range to decode (0-based)")
                    Text("to")
                        .foregroundStyle(.secondary)
                    TextField("End", value: $rangeEnd, format: .number)
                        .frame(width: 64)
                        .help("End of the range to decode (exclusive); the whole run is 0 to \(subject.bytes.count)")
                }
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private func output(_ bytes: [UInt8]) -> some View {
        if presentation == .image {
            if let image = NSImage(data: Data(bytes)) {
                ScrollView([.horizontal, .vertical]) {
                    Image(nsImage: image)
                        .accessibilityLabel(
                            "Decoded image, \(Int(image.size.width)) by \(Int(image.size.height)) points"
                        )
                        .padding(Theme.Metrics.spacingL)
                }
            } else {
                ContentUnavailableView(
                    "Not an Image",
                    systemImage: "photo",
                    description: Text("These bytes are not an image format macOS can read.")
                )
            }
        } else {
            ScrollView {
                Text(presentation.text(for: bytes) ?? "")
                    .font(Theme.Typography.mono)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Theme.Metrics.spacingL)
            }
        }
    }

    private func footer(inputCount: Int, decoded: [UInt8]?, title: String) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(decoded.map { "\(inputCount.formatted()) bytes in, \($0.count.formatted()) bytes out" }
                ?? "\(inputCount.formatted()) bytes in")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .monospacedDigit()
            if presentation == .json, let decoded, !PacketBytesPresentation.isJSON(decoded) {
                Text("Not valid JSON, shown as text")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Copy") {
                guard let decoded else {
                    return
                }
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(presentation.text(for: decoded) ?? "", forType: .string)
            }
            .disabled(decoded == nil || presentation == .image)
            Button("Save As…") {
                if let decoded {
                    save(decoded, suggestedName: title)
                }
            }
            .disabled(decoded == nil)
            .help("Save the decoded bytes exactly, before any text rendering")
        }
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    private static func message(_ failure: PacketBytesDecoding.Failure) -> String {
        switch failure {
        case let .notApplicable(reason): reason
        case let .outputTooLarge(limit):
            String(localized: "Decoding would produce more than \(ByteUnits.string(Int64(limit))); it was stopped.")
        }
    }

    private func save(_ bytes: [UInt8], suggestedName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bytes.bin"
        panel.allowedContentTypes = [.data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        try? Data(bytes).write(to: url, options: .atomic)
    }
}
