import SwiftUI

extension AllFramesWindow {
    func relativeTCPNumbersToggle(state: CaptureFrameListState) -> some View {
        Toggle(
            "Relative TCP Seq/Ack",
            isOn: Binding(
                get: { state.showsRelativeTCPNumbers },
                set: { state.showsRelativeTCPNumbers = $0 }
            )
        )
        .toggleStyle(.checkbox)
        .disabled(state.list == nil || state.isLoading || state.error != nil)
        .help(
            "Show Seq/Ack relative to the first observed segment in each direction; "
                + "ACK is unknown until the reverse direction is observed, and values are bounded to 200,000 conversations"
        )
    }

    func frameTimeColumn(
        format: FrameTimeFormat,
        time: @escaping (CaptureFrameRow) -> String
    )
        -> some TableColumnContent<CaptureFrameRow, Never>
    {
        TableColumn(format == .sinceSessionStart ? String(localized: "Time") : format.columnTitle) { row in
            let isReference = coordinator.sessionTimeDisplay.isCaptureTimeReference(ordinal: row.ordinal)
            let value = time(row)
            colorizedCell(row) {
                Text(value)
                    .monospacedDigit()
                    .fontWeight(isReference ? .semibold : .regular)
                    .accessibilityLabel(isReference ? String(localized: "Time reference") : value)
            }
        }
        .width(min: 90, ideal: 110)
    }

    /// An Apply as Column slot: capture-interface direction for each frame.
    func captureDirectionColumn() -> some TableColumnContent<CaptureFrameRow, Never> {
        TableColumn("I/O") { row in
            let label = switch row.captureDirection {
            case .unknown: String(localized: "Unknown capture direction")
            case .inbound: String(localized: "Inbound to the capture interface")
            case .outbound: String(localized: "Outbound from the capture interface")
            }
            let mark = switch row.captureDirection {
            case .unknown: "—"
            case .inbound: "I"
            case .outbound: "O"
            }
            colorizedCell(row) { Text(mark).help(label).accessibilityLabel(label) }
        }
        .width(min: 36, ideal: 44)
    }

    func frameCumulativeBytesColumn() -> some TableColumnContent<CaptureFrameRow, Never> {
        TableColumn("Cumulative Bytes") { row in
            colorizedCell(row) {
                Text(row.cumulativeCapturedBytes?.formatted() ?? "—")
                    .monospacedDigit()
                    .help(
                        "Captured bytes through this frame, including this frame; reset at the latest capture-wide time reference. Hidden frames and pages still count."
                    )
            }
        }
        .width(min: 100, ideal: 120)
        .customizationID("cumulativeBytes")
        .disabledCustomizationBehavior(.all)
    }
}
