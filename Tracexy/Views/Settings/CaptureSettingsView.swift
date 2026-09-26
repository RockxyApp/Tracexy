import SwiftUI

// MARK: - CaptureSettingsView

/// Capture defaults, all behavioral: the coordinator reads these preferences fresh
/// at each capture start and maps them to a validated `CaptureConfiguration`
/// (interface, snap length, promiscuous mode, optional BPF) honored by both the
/// direct and privileged-helper backends, and sizes the in-memory save/export
/// retention window from "Retain up to".
struct CaptureSettingsView: View {
    // MARK: Internal

    var body: some View {
        SettingsPane {
            SettingsSection("Interface") {
                SettingsRow(label: "Default interface:") {
                    Picker("", selection: $defaultInterface) {
                        Text("Automatic").tag("")
                        ForEach(interfaceGroups) { group in
                            Section(group.category.title) {
                                ForEach(group.interfaces) { iface in
                                    Text(iface.pickerLabel).tag(iface.id)
                                }
                            }
                        }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(240))
                    .frame(minHeight: metrics.controlHeight)
                }

                if let note = CaptureSourceGuidance.tunnelNote(for: defaultInterface, in: allInterfaces) {
                    SettingsIndented {
                        SettingsFootnote(note)
                    }
                }

                SettingsDivider()

                SettingsCheckbox(
                    isOn: $autoStart,
                    title: "Auto-start capture on launch",
                    description: "Begin capturing on the default interface as soon as a workspace opens."
                )
            }

            SettingsSection("Filter") {
                SettingsRow(label: "Capture filter:") {
                    Picker("", selection: $filterMode) {
                        ForEach(CaptureFilterMode.allCases) { Text($0.title).tag($0.rawValue) }
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }

                SettingsDivider()

                SettingsRow(label: "BPF expression:") {
                    TextField("tcp port 443 or udp port 53", text: $bpf)
                        .textFieldStyle(.roundedBorder)
                        .font(metrics.monospacedFont())
                        .frame(width: metrics.fieldWidth(280))
                        .frame(minHeight: metrics.controlHeight)
                        .disabled(filterMode != CaptureFilterMode.custom.rawValue)
                }

                if filterMode == CaptureFilterMode.custom.rawValue {
                    SettingsIndented {
                        VStack(alignment: .leading, spacing: 6) {
                            filterValidationLine
                            savedFilterControls
                        }
                    }
                }

                SettingsDivider()

                SettingsIndented {
                    VStack(alignment: .leading, spacing: 4) {
                        Button("Import Capture Filter…") { isImportingFilter = true }
                            .accessibilityLabel("Import Capture Filter")
                        SettingsFootnote(
                            "Reuse a named BPF expression from a capture-filter list file. "
                                + "Applying one replaces this Project’s custom expression; nothing else in the file is imported."
                        )
                    }
                }
            }

            SettingsSection("Buffer") {
                SettingsRow(label: "Snap length:") {
                    Picker("", selection: $snapLength) {
                        Text("Full packet (65 536 bytes)").tag(65_536)
                        Text("256 KiB").tag(262_144)
                        Text("Headers only (128 bytes)").tag(128)
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(240))
                    .frame(minHeight: metrics.controlHeight)
                }

                SettingsDivider()

                SettingsCheckbox(
                    isOn: $promiscuous,
                    title: "Promiscuous mode",
                    description: "Capture all frames on the interface, not only those addressed to this Mac."
                )

                SettingsDivider()

                SettingsRow(label: "Stop automatically:") {
                    HStack(spacing: 8) {
                        Picker("Stop after time", selection: $autoStopMinutes) {
                            Text("Never").tag(0)
                            Text("After 1 minute").tag(1)
                            Text("After 5 minutes").tag(5)
                            Text("After 15 minutes").tag(15)
                            Text("After 1 hour").tag(60)
                            Text("After 8 hours").tag(480)
                        }
                        .labelsHidden()
                        .frame(width: metrics.menuWidth(160))
                        Picker("Stop after packets", selection: $autoStopPackets) {
                            Text("Any packet count").tag(0)
                            Text("After 10,000 packets").tag(10_000)
                            Text("After 100,000 packets").tag(100_000)
                            Text("After 1,000,000 packets").tag(1_000_000)
                        }
                        .labelsHidden()
                        .frame(width: metrics.menuWidth(200))
                    }
                    .frame(minHeight: metrics.controlHeight)
                }

                SettingsIndented {
                    SettingsFootnote(
                        "A live capture stops by itself at whichever limit comes first, and its sessions go to History "
                            + "as when you press Stop. Clearing the list during capture restarts the packet count."
                    )
                }

                SettingsDivider()

                SettingsRow(label: "Save as a file set:") {
                    HStack(spacing: 8) {
                        Picker("New file after size", selection: $fileSetMegabytes) {
                            Text("Off").tag(0)
                            Text("Every 10 MB").tag(10)
                            Text("Every 100 MB").tag(100)
                            Text("Every 1 GB").tag(1_000)
                        }
                        .labelsHidden()
                        .frame(width: metrics.menuWidth(140))
                        Picker("New file after time", selection: $fileSetMinutes) {
                            Text("Any duration").tag(0)
                            Text("Every minute").tag(1)
                            Text("Every 10 minutes").tag(10)
                            Text("Every hour").tag(60)
                        }
                        .labelsHidden()
                        .frame(width: metrics.menuWidth(160))
                        Picker("Files to keep", selection: $fileSetKeep) {
                            Text("Keep every file").tag(0)
                            Text("Keep newest 5").tag(5)
                            Text("Keep newest 20").tag(20)
                            Text("Keep newest 100").tag(100)
                        }
                        .labelsHidden()
                        .disabled(fileSetMegabytes == 0 && fileSetMinutes == 0)
                        .frame(width: metrics.menuWidth(160))
                    }
                    .frame(minHeight: metrics.controlHeight)
                }

                SettingsIndented {
                    SettingsFootnote(
                        "While capturing, Tracexy starts a new file at whichever limit comes first and keeps the set in "
                            + "this Project’s Captures folder, named so File ▸ Next File in Set walks it. Keeping only the "
                            + "newest files deletes older ones as the capture runs; a finding that cites a deleted file "
                            + "says so. Follow and Frames read the newest file; Save Capture keeps every file still kept."
                    )
                }

                SettingsDivider()

                SettingsRow(label: "Retain up to:") {
                    Picker("", selection: $retainPackets) {
                        Text("8 000 packets").tag(8_000)
                        Text("20 000 packets").tag(20_000)
                        Text("50 000 packets").tag(50_000)
                    }
                    .labelsHidden()
                    .frame(width: metrics.menuWidth(200))
                    .frame(minHeight: metrics.controlHeight)
                }
            }
        }
        .onAppear { interfaceGroups = listedGroups }
        .onChange(of: InterfacePreferences.shared.settings) { interfaceGroups = listedGroups }
        .task(id: bpf) {
            // Debounced so validation follows typing without compiling every keystroke.
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else {
                return
            }
            let expression = bpf
            validation = await Task.detached(priority: .utility) {
                CaptureFilterValidator.validate(expression)
            }.value
        }
        .sheet(isPresented: $isImportingFilter) {
            CaptureFilterImportSheet(bpf: $bpf, filterMode: $filterMode)
        }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.defaultInterface) private var defaultInterface = ""
    @AppStorage(SettingsKeys.autoStartCapture) private var autoStart = false
    @AppStorage(SettingsKeys.captureFilterMode) private var filterMode = CaptureFilterMode.all.rawValue
    @AppStorage(SettingsKeys.bpfExpression) private var bpf = ""
    @AppStorage(SettingsKeys.snapLength) private var snapLength = 65_536
    @AppStorage(SettingsKeys.promiscuous) private var promiscuous = false
    @AppStorage(SettingsKeys.retainPackets) private var retainPackets = 8_000
    @AppStorage(SettingsKeys.autoStopMinutes) private var autoStopMinutes = 0
    @AppStorage(SettingsKeys.autoStopPackets) private var autoStopPackets = 0
    @AppStorage(SettingsKeys.fileSetMegabytes) private var fileSetMegabytes = 0
    @AppStorage(SettingsKeys.fileSetMinutes) private var fileSetMinutes = 0
    @AppStorage(SettingsKeys.fileSetKeep) private var fileSetKeep = 0

    @AppStorage(SettingsKeys.savedCaptureFilters) private var savedFiltersData = Data("[]".utf8)

    @State private var interfaceGroups: [InterfaceGroup] = []

    @State private var isImportingFilter = false
    @State private var validation: CaptureFilterValidation = .empty
    @State private var isNamingFilter = false
    @State private var filterName = ""

    private let metrics = SettingsDisplayMetrics.standard

    /// The interfaces Capture ▸ Manage Interfaces leaves listed; the default stays listed.
    private var listedGroups: [InterfaceGroup] {
        NetworkInterfaces.grouped(InterfacePreferences.shared.settings, keeping: defaultInterface)
    }

    private var savedFilters: [SavedCaptureFilter] {
        SavedCaptureFilter.decode(savedFiltersData)
    }

    /// The discovered interfaces, flattened out of their display groups, for the
    /// tunnel-guidance lookup.
    private var allInterfaces: [NetworkInterface] {
        interfaceGroups.flatMap(\.interfaces)
    }

    /// libpcap's verdict on the expression, checked without opening an interface.
    @ViewBuilder private var filterValidationLine: some View {
        switch validation {
        case .empty:
            SettingsFootnote("With no expression, every packet is captured.")
        case let .valid(count):
            Label("Valid filter", systemImage: "checkmark.circle")
                .font(Theme.Typography.chrome)
                .foregroundStyle(.secondary)
                .help(
                    "libpcap compiled it to \(count) BPF instructions for Ethernet interfaces using optimization. "
                        + "The count can differ if optimization is disabled for the selected interface."
                )
        case let .invalid(message):
            Label(message, systemImage: "exclamationmark.triangle")
                .font(Theme.Typography.chrome)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        case .unavailable:
            SettingsFootnote("This expression is checked when capture starts.")
        }
    }

    private var savedFilterControls: some View {
        HStack(spacing: 8) {
            Menu("Saved Filters") {
                ForEach(savedFilters) { filter in
                    Button(filter.name) { bpf = filter.expression }
                        .help(filter.expression)
                }
                if !savedFilters.isEmpty {
                    Divider()
                    Menu("Delete") {
                        ForEach(savedFilters) { filter in
                            Button(filter.name, role: .destructive) {
                                savedFiltersData = SavedCaptureFilter.encode(savedFilters.filter { $0.id != filter.id })
                            }
                        }
                    }
                }
            }
            .disabled(savedFilters.isEmpty)
            .fixedSize()

            Button("Save Filter…") {
                filterName = ""
                isNamingFilter = true
            }
            .disabled({
                if case .valid = validation {
                    return false
                }
                return true
            }())
            .help("Keep this expression under a name in this Project")
            .popover(isPresented: $isNamingFilter, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Save Capture Filter")
                        .font(Theme.Typography.surfaceTitle)
                    TextField("Name", text: $filterName)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .onSubmit(saveFilter)
                    HStack {
                        Spacer()
                        Button("Cancel") { isNamingFilter = false }
                        Button("Save", action: saveFilter)
                            .keyboardShortcut(.defaultAction)
                            .disabled(filterName.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
                .padding(14)
            }
        }
        .controlSize(.small)
    }

    private func saveFilter() {
        if let updated = SavedCaptureFilter.saving(bpf, named: filterName, into: savedFilters) {
            savedFiltersData = SavedCaptureFilter.encode(updated)
            isNamingFilter = false
        }
    }
}

// MARK: - CaptureSourceGuidance

/// Derives the compact, evidence-based note shown when the selected default
/// interface is a tunnel (VPN) source. Pure and deterministic so its visibility
/// and text are unit-testable without rendering the view.
///
/// A tunnel interface carries the inner, already-decapsulated IP packets, so a
/// capture there sees pre-encryption IP traffic the physical link never exposes —
/// but a tunnel has no Ethernet framing, so link-layer/MAC detail is absent. The
/// note states exactly that tradeoff and nothing more. It is shown only for a
/// tunnel-category interface; "Automatic" (no explicit selection) and every
/// non-tunnel interface get no note.
enum CaptureSourceGuidance {
    static func tunnelNote(for interfaceID: String, in interfaces: [NetworkInterface]) -> String? {
        guard !interfaceID.isEmpty,
              let interface = interfaces.first(where: { $0.id == interfaceID }),
              interface.category == .tunnels else
        {
            return nil
        }
        return "This is a tunnel (VPN) interface. You’ll capture the inner, pre-encryption IP traffic it "
            + "carries — which the physical link never exposes — but not link-layer or MAC details, because "
            + "a tunnel has no Ethernet framing."
    }
}

#Preview {
    CaptureSettingsView()
}
