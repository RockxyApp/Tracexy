import SwiftUI

// MARK: - SplitCaptureSheet

/// File ▸ Split Capture…: how to cut the open capture into a file set.
struct SplitCaptureSheet: View {
    // MARK: Internal

    enum Unit: String, CaseIterable, Identifiable {
        case frames
        case seconds

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .frames: "Frames"
            case .seconds: "Seconds"
            }
        }
    }

    var coordinator: MainContentCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            Text("Split Capture")
                .font(Theme.Typography.title)
            Text("Write this capture as a set of files. The original is not changed.")
                .font(Theme.Typography.body)
                .foregroundStyle(.secondary)
            Form {
                LabeledContent("Start a new file every") {
                    HStack(spacing: Theme.Metrics.spacingM) {
                        TextField("Size of each file", value: $amount, format: .number)
                            .frame(width: 90)
                            .labelsHidden()
                        Picker("Unit", selection: $unit) {
                            ForEach(Unit.allCases) { unit in
                                Text(unit.title).tag(unit)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .fixedSize()
                    }
                }
                LabeledContent("Shift times by") {
                    HStack(spacing: Theme.Metrics.spacingM) {
                        TextField("Time shift in seconds", value: $shift, format: .number)
                            .frame(width: 90)
                            .labelsHidden()
                        Text("seconds").foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.columns)
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button("Split…") {
                    let options = CaptureSplitOptions(
                        boundary: unit == .frames ? .frames(Int(amount)) : .seconds(amount),
                        timeShift: shift
                    )
                    dismiss()
                    coordinator.presentSplitSavePanel(options: options)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil)
            }
        }
        .padding(Theme.Metrics.spacingL + 4)
        .frame(width: 440)
    }

    // MARK: Private

    @Environment(\.dismiss) private var dismiss
    @State private var amount: Double = 10_000
    @State private var unit: Unit = .frames
    @State private var shift: Double = 0

    private var problem: String? {
        guard amount.isFinite, amount > 0, unit == .seconds || amount.rounded() == amount else {
            return unit == .frames ? "Enter a whole number of frames above zero." : "Enter a number of seconds above zero."
        }
        guard shift.isFinite, abs(shift) <= 3_153_600_000 else {
            return "Enter a time shift within a century."
        }
        return nil
    }
}
