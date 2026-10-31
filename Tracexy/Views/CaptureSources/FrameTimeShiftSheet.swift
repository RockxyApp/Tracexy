import SwiftUI

// MARK: - FrameTimeShiftSheet

struct FrameTimeShiftSheet: View {
    // MARK: Lifecycle

    init(coordinator: MainContentCoordinator) {
        self.coordinator = coordinator
        firstCorrectedTime = Date()
        secondCorrectedTime = Date().addingTimeInterval(1)
    }

    // MARK: Internal

    @Bindable var coordinator: MainContentCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Time Shift")
                .font(Theme.Typography.surfaceTitle)
            Text(
                "Apply one correction to every frame in this saved capture, including ignored frames and frames hidden by filters. "
                    + "The source file stays unchanged. Undo restores its original timestamps."
            )
            .foregroundStyle(.secondary)
            Picker("Correction", selection: $mode) {
                ForEach(Mode.allCases) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.segmented)

            switch mode {
            case .constant:
                HStack {
                    Text("Shift all frames by")
                    TextField("Seconds", text: $shiftSeconds)
                        .frame(width: 100)
                    Text("seconds")
                        .foregroundStyle(.secondary)
                }
            case .oneAnchor:
                anchorRow(frame: $firstFrame, correctedTime: $firstCorrectedTime, title: "Frame")
            case .twoAnchors:
                anchorRow(frame: $firstFrame, correctedTime: $firstCorrectedTime, title: "First frame")
                anchorRow(frame: $secondFrame, correctedTime: $secondCorrectedTime, title: "Second frame")
                Text("The corrected times must preserve time order. Frames are numbered from 1.")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }

            if let error = coordinator.timeShiftError {
                Text(error)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }

            HStack {
                if coordinator.canUndoTimeShift {
                    Button("Undo All Shifts") {
                        coordinator.undoTimeShift()
                    }
                }
                Spacer()
                Button("Cancel", role: .cancel) {
                    coordinator.cancelTimeShiftResolution()
                }
                Button(coordinator.timeShiftTask == nil ? "Apply to All Frames" : "Resolving Anchors…") {
                    if let request {
                        coordinator.applyTimeShift(request)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!coordinator.canTimeShiftSavedCapture || request == nil)
            }
        }
        .padding(24)
        .frame(width: 600)
        .fixedSize(horizontal: false, vertical: true)
        .onChange(of: mode) {
            coordinator.timeShiftError = nil
        }
    }

    // MARK: Private

    private enum Mode: String, CaseIterable, Identifiable {
        case constant
        case oneAnchor
        case twoAnchors

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .constant: "Offset"
            case .oneAnchor: "One anchor"
            case .twoAnchors: "Clock drift"
            }
        }
    }

    @State private var mode = Mode.constant
    @State private var shiftSeconds = "0"
    @State private var firstFrame = "1"
    @State private var secondFrame = "2"
    @State private var firstCorrectedTime: Date
    @State private var secondCorrectedTime: Date

    private var request: CaptureTimeCorrectionRequest? {
        switch mode {
        case .constant:
            guard let value = Double(shiftSeconds), value.isFinite else {
                return nil
            }
            return .shiftBy(value)
        case .oneAnchor:
            guard let ordinal = UInt64(firstFrame), ordinal > 0 else {
                return nil
            }
            return .anchor(frameOrdinal: ordinal, correctedTime: firstCorrectedTime)
        case .twoAnchors:
            guard let first = UInt64(firstFrame), first > 0,
                  let second = UInt64(secondFrame), second > 0 else
            {
                return nil
            }
            return .anchors(
                firstFrameOrdinal: first, firstCorrectedTime: firstCorrectedTime,
                secondFrameOrdinal: second, secondCorrectedTime: secondCorrectedTime
            )
        }
    }

    private func anchorRow(frame: Binding<String>, correctedTime: Binding<Date>, title: String) -> some View {
        HStack {
            Text(title)
            TextField("Frame number", text: frame)
                .frame(width: 80)
            DatePicker("should have time", selection: correctedTime)
                .labelsHidden()
                .datePickerStyle(.field)
        }
    }
}
