import AppKit
import SwiftUI

extension AllFramesWindow {
    func copyMenu(for row: CaptureFrameRow, values: [String], rowIndex: UInt64) -> some View {
        Menu("Copy") {
            Menu("Bytes") {
                ForEach(PacketBytesFormat.allCases) { format in
                    Button(format.menuTitle) {
                        copyFrameBytes(row, format: format)
                    }
                }
            }
            .disabled(coordinator.allFramesUnavailableReason != nil)
            Divider()
            ForEach(FrameSummaryCopy.Format.allCases) { format in
                Button(format.title) {
                    copySummary(values, format: format, rowIndex: rowIndex)
                }
            }
        }
    }

    /// Packet List → Copy → Bytes, read from the stable source after an explicit
    /// user action.
    private func copyFrameBytes(_ row: CaptureFrameRow, format: PacketBytesFormat) {
        let pasteboardChangeCount = NSPasteboard.general.changeCount
        Task { @MainActor in
            let outcome = await coordinator.frameBytesForCopy(row)
            guard NSPasteboard.general.changeCount == pasteboardChangeCount else {
                return
            }
            let bytes: [UInt8]
            switch outcome {
            case let .bytes(value):
                bytes = value
            case let .unavailable(message):
                notice = message
                return
            case .superseded:
                return
            }
            let value = format.clipboardValue(for: bytes[...])
            NSPasteboard.general.clearContents()
            switch value {
            case let .text(text):
                NSPasteboard.general.setString(text, forType: .string)
            case let .data(data, type):
                NSPasteboard.general.setData(data, forType: NSPasteboard.PasteboardType(type))
            }
        }
    }

    /// Copy the packet-list row as text, CSV, YAML or HTML.
    private func copySummary(_ values: [String], format: FrameSummaryCopy.Format, rowIndex: UInt64) {
        coordinator.allFrames.frameBytesCopyRequestID &+= 1
        let copied = FrameSummaryCopy.copy(
            values, format: format, rowIndex: rowIndex,
            captureName: coordinator.activeSavedCapture?.name ?? String(localized: "live capture")
        )
        NSPasteboard.general.clearContents()
        if let html = copied.html {
            NSPasteboard.general.setString(html, forType: .html)
        }
        NSPasteboard.general.setString(copied.text, forType: .string)
    }
}
