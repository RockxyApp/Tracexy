import SwiftUI

// MARK: - CaptureSettingsView

/// Capture defaults. `Default interface` is honored by the coordinator on launch;
/// the filter/buffer options persist and will drive the capture engine as those
/// paths land (BPF, snaplen, promiscuous, and retention are not yet wired to
/// `LiveCapture`).
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
}

#Preview {
    CaptureSettingsView()
}
