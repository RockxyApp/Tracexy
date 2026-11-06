import AppKit
import Foundation

/// Small, export-panel accessory for asking the exporter to build a corrected
/// copy from one or two frame/time anchors. The selected capture is never edited.
@MainActor
final class FrameTimeCorrectionControls: NSView {
    // MARK: Lifecycle

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)

        enabledCheckbox.target = self
        enabledCheckbox.action = #selector(controlChanged)
        enabledCheckbox.toolTip = String(
            localized: """
            Write a corrected PCAPNG copy using one frame to set a fixed offset or two frames to correct clock drift.
            The source file is never edited, and the corrected copy opens in place of the capture you are viewing.
            The whole capture is written, so scope, ignored frames and the other packet options do not apply.
            """
        )
        enabledCheckbox.setAccessibilityLabel(String(localized: "Correct timestamps in exported copy"))
        modePopUp.addItems(withTitles: [
            String(localized: "One frame: fixed offset"),
            String(localized: "Two frames: clock drift"),
        ])
        modePopUp.target = self
        modePopUp.action = #selector(controlChanged)
        modePopUp.setAccessibilityLabel(String(localized: "Time correction method"))
        configureOrdinal(firstOrdinalField, label: "First anchor frame number")
        configureOrdinal(secondOrdinalField, label: "Second anchor frame number")
        configurePicker(firstTimePicker, label: "Corrected time for first anchor")
        configurePicker(secondTimePicker, label: "Corrected time for second anchor")
        firstOrdinalField.stringValue = "1"
        secondOrdinalField.stringValue = "2"
        firstTimePicker.dateValue = Date()
        secondTimePicker.dateValue = Date().addingTimeInterval(1)
        modePopUp.selectItem(at: 0)

        let ordinalRow = NSStackView(views: [
            NSTextField(labelWithString: String(localized: "Frame")), firstOrdinalField,
            NSTextField(labelWithString: String(localized: "should have time")), firstTimePicker,
        ])
        ordinalRow.orientation = .horizontal
        ordinalRow.spacing = 6
        let secondRow = NSStackView(views: [
            NSTextField(labelWithString: String(localized: "Frame")), secondOrdinalField,
            NSTextField(labelWithString: String(localized: "should have time")), secondTimePicker,
        ])
        secondRow.orientation = .horizontal
        secondRow.spacing = 6
        let note = NSTextField(wrappingLabelWithString: String(
            localized: "All frames are written to a new PCAPNG at microsecond precision; unknown times stay unknown. Anchor frame times are read from the source."
        ))
        note.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        note.textColor = .secondaryLabelColor
        let content = NSStackView(views: [enabledCheckbox, modePopUp, ordinalRow, secondRow, note])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 4
        content.translatesAutoresizingMaskIntoConstraints = false
        addSubview(content)
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: topAnchor),
            content.leadingAnchor.constraint(equalTo: leadingAnchor),
            content.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            content.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        updateVisibility()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        nil
    }

    // MARK: Internal

    var onChange: (() -> Void)?

    var isEnabled: Bool {
        enabledCheckbox.state == .on
    }

    var request: CaptureTimeCorrectionRequest? {
        guard isEnabled,
              let firstOrdinal = UInt64(firstOrdinalField.stringValue), firstOrdinal > 0 else
        {
            return nil
        }
        if modePopUp.indexOfSelectedItem == 1 {
            guard let secondOrdinal = UInt64(secondOrdinalField.stringValue), secondOrdinal > 0 else {
                return nil
            }
            return .anchors(
                firstFrameOrdinal: firstOrdinal,
                firstCorrectedTime: firstTimePicker.dateValue,
                secondFrameOrdinal: secondOrdinal,
                secondCorrectedTime: secondTimePicker.dateValue
            )
        }
        return .anchor(frameOrdinal: firstOrdinal, correctedTime: firstTimePicker.dateValue)
    }

    var validationIssue: String? {
        guard isEnabled else {
            return nil
        }
        guard let firstOrdinal = UInt64(firstOrdinalField.stringValue), firstOrdinal > 0 else {
            return String(localized: "Enter a first anchor frame number greater than zero.")
        }
        if modePopUp.indexOfSelectedItem == 1 {
            guard let secondOrdinal = UInt64(secondOrdinalField.stringValue), secondOrdinal > 0 else {
                return String(localized: "Enter a second anchor frame number greater than zero.")
            }
            guard firstOrdinal != secondOrdinal else {
                return String(localized: "Choose two different anchor frames.")
            }
        }
        return nil
    }

    func setAvailable(_ available: Bool) {
        enabledCheckbox.isEnabled = available
        if !available {
            enabledCheckbox.state = .off
        }
        modePopUp.isEnabled = available && isEnabled
        firstOrdinalField.isEnabled = available && isEnabled
        firstTimePicker.isEnabled = available && isEnabled
        let needsSecond = modePopUp.indexOfSelectedItem == 1
        secondOrdinalField.isEnabled = available && isEnabled && needsSecond
        secondTimePicker.isEnabled = available && isEnabled && needsSecond
        updateVisibility()
    }

    // MARK: Private

    private let enabledCheckbox = NSButton(
        checkboxWithTitle: String(localized: "Correct timestamps in exported copy"), target: nil, action: nil
    )
    private let modePopUp = NSPopUpButton(frame: .zero, pullsDown: false)
    private let firstOrdinalField = NSTextField()
    private let secondOrdinalField = NSTextField()
    private let firstTimePicker = NSDatePicker()
    private let secondTimePicker = NSDatePicker()

    private func configureOrdinal(_ field: NSTextField, label: String) {
        field.formatter = {
            let formatter = NumberFormatter()
            formatter.numberStyle = .none
            formatter.minimum = 1
            formatter.maximum = NSNumber(value: UInt64.max)
            return formatter
        }()
        field.widthAnchor.constraint(equalToConstant: 68).isActive = true
        field.setAccessibilityLabel(label)
        field.target = self
        field.action = #selector(controlChanged)
    }

    private func configurePicker(_ picker: NSDatePicker, label: String) {
        picker.datePickerStyle = .textFieldAndStepper
        picker.datePickerElements = [.yearMonthDay, .hourMinuteSecond]
        picker.setAccessibilityLabel(label)
        picker.target = self
        picker.action = #selector(controlChanged)
    }

    private func updateVisibility() {
        let enabled = isEnabled
        modePopUp.isHidden = !enabled
        let isTwoAnchor = modePopUp.indexOfSelectedItem == 1
        firstOrdinalField.isEnabled = enabled
        firstTimePicker.isEnabled = enabled
        secondOrdinalField.isHidden = !enabled || !isTwoAnchor
        secondTimePicker.isHidden = !enabled || !isTwoAnchor
    }

    @objc
    private func controlChanged() {
        updateVisibility()
        onChange?()
    }
}
