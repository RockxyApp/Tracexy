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
                                    Text(iface.menuLabel).tag(iface.id)
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
        .onAppear { interfaceGroups = NetworkInterfaces.grouped() }
    }

    // MARK: Private

    @AppStorage(SettingsKeys.defaultInterface) private var defaultInterface = ""
    @AppStorage(SettingsKeys.autoStartCapture) private var autoStart = false
    @AppStorage(SettingsKeys.captureFilterMode) private var filterMode = CaptureFilterMode.all.rawValue
    @AppStorage(SettingsKeys.bpfExpression) private var bpf = ""
    @AppStorage(SettingsKeys.snapLength) private var snapLength = 65_536
    @AppStorage(SettingsKeys.promiscuous) private var promiscuous = false
    @AppStorage(SettingsKeys.retainPackets) private var retainPackets = 8_000

    @State private var interfaceGroups: [InterfaceGroup] = []

    private let metrics = SettingsDisplayMetrics.standard

    /// The discovered interfaces, flattened out of their display groups, for the
    /// tunnel-guidance lookup.
    private var allInterfaces: [NetworkInterface] {
        interfaceGroups.flatMap(\.interfaces)
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
