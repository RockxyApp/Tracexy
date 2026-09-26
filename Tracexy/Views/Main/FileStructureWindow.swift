import AppKit
import SwiftUI

// MARK: - FileStructureWindow

/// File ▸ Show File Structure: the capture file itself, block by block — each pcapng
/// block, or the pcap header and records — with its offset, length and key fields,
/// as Wireshark's Reload as File Format/Capture. Secrets are sized, never shown.
struct FileStructureWindow: View {
    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .tracexySafeAreaBar(edge: .bottom) { footer }
            .frame(minWidth: 620, minHeight: 320)
            .task(id: coordinator.adoptedSavedCaptureIdentity) { controller.run(from: coordinator) }
            .onDisappear { controller.cancel() }
    }

    /// "29,422 blocks: 29,420 Enhanced Packet Blocks, 1 Section Header Block, …",
    /// most common first.
    static func breakdown(_ structure: CaptureFileStructure) -> String {
        structure.countsByTitle
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .map { "\($0.value.formatted()) \($0.key)" }
            .joined(separator: ", ")
    }

    // MARK: Private

    @State private var selection: CaptureFileBlock.ID?
    @State private var notice: String?

    private var controller: FileStructureController {
        FileStructureController.shared
    }

    /// The format and block count, and where the walk stopped if it stopped early.
    private var summary: String {
        guard let structure = controller.structure else {
            return ""
        }
        let count = String(localized: "\(structure.totalBlocks.formatted()) blocks in a \(structure.format) file")
        if let stopped = structure.stoppedEarly {
            return String(localized: "\(count). \(stopped)")
        }
        if structure.totalBlocks > structure.blocks.count {
            return String(localized: "\(count), the first \(structure.blocks.count.formatted()) listed")
        }
        return count
    }

    @ViewBuilder private var content: some View {
        // Also before the first read, so the view is never empty and its `.task` runs.
        if controller.isLoading || (controller.structure == nil && controller.error == nil) {
            ProgressView("Reading the file…")
                .controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error = controller.error {
            ContentUnavailableView("Structure Unavailable", systemImage: "square.stack.3d.up", description: Text(error))
        } else if let structure = controller.structure {
            Table(structure.blocks, selection: $selection) {
                TableColumn("#") { block in
                    Text(block.index.formatted()).monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 40, ideal: 56)
                TableColumn("Offset") { block in
                    Text(String(format: "0x%08llX", block.offset)).font(Theme.Typography.mono)
                }
                .width(min: 80, ideal: 96)
                TableColumn("Block") { block in
                    Text(block.title).lineLimit(1)
                }
                .width(min: 140, ideal: 190)
                TableColumn("Length") { block in
                    Text(block.length.formatted()).monospacedDigit().frame(maxWidth: .infinity, alignment: .trailing)
                }
                .width(min: 56, ideal: 70)
                TableColumn("Contents") { block in
                    Text(block.detail).lineLimit(1).truncationMode(.tail).help(block.detail)
                }
                .width(min: 160, ideal: 320)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Text(notice ?? summary)
                .lineLimit(1)
                .truncationMode(.tail)
                .help(controller.structure.map(Self.breakdown) ?? "")
            Spacer()
            Button("Reload") { controller.run(from: coordinator) }
                .disabled(controller.isLoading)
        }
        .font(Theme.Typography.caption)
        .foregroundStyle(.secondary)
        .controlSize(.small)
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }
}
