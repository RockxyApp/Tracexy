import Foundation
import Testing
@testable import Tracexy

/// The interface pickers name each interface's address, or that it is not connected.
struct NetworkInterfaceLabelTests {
    @Test
    func pickerLabels() {
        let wifi = NetworkInterface(
            id: "en0", displayName: "Wi-Fi", category: .wifi, ipv4: "192.0.2.5", isUp: true, isLoopback: false
        )
        let cable = NetworkInterface(
            id: "en5", displayName: "USB LAN", category: .ethernet, ipv4: nil, isUp: false, isLoopback: false
        )
        let tunnel = NetworkInterface(
            id: "utun3", displayName: "utun3", category: .tunnels, ipv4: nil, isUp: true, isLoopback: false
        )
        #expect(wifi.pickerLabel == "Wi-Fi (en0) — 192.0.2.5")
        #expect(cable.pickerLabel == "USB LAN (en5) — not connected")
        #expect(tunnel.pickerLabel == "utun3 (utun3)")
    }
}
