import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureSettingsTests

@Suite("Capture settings and configuration")
struct CaptureSettingsTests {
    @Test("Configuration validates, normalizes, and clamps untrusted values")
    func validation() throws {
        let raw = CaptureConfiguration(
            interface: "  en0  ",
            snapLength: Int.max,
            promiscuous: true,
            bpf: "  tcp port 443  "
        )
        let validated = try raw.validated().get()

        #expect(validated.interface == "en0")
        #expect(validated.snapLength == CaptureConfiguration.snapLengthRange.upperBound)
        #expect(validated.promiscuous)
        #expect(validated.bpf == "tcp port 443")
        #expect(CaptureConfiguration.clampedSnapLength(0) == CaptureConfiguration.defaultSnapLength)
    }

    @Test("Configuration rejects an empty interface and oversized BPF")
    func rejection() {
        let empty = CaptureConfiguration(interface: "  ", snapLength: 64, promiscuous: false, bpf: nil)
        let oversized = CaptureConfiguration(
            interface: "en0",
            snapLength: 64,
            promiscuous: false,
            bpf: String(repeating: "x", count: CaptureConfiguration.maxBPFLength + 1)
        )

        #expect(empty.validated().failure == .emptyInterface)
        #expect(oversized.validated().failure == .bpfTooLong)
    }

    @Test("Secure coding round-trip preserves the typed XPC command")
    func secureCodingRoundTrip() throws {
        let original = CaptureConfiguration(
            interface: "utun4",
            snapLength: 131_072,
            promiscuous: false,
            bpf: "udp port 53"
        )
        let data = try NSKeyedArchiver.archivedData(withRootObject: original, requiringSecureCoding: true)
        let unarchived = try NSKeyedUnarchiver.unarchivedObject(
            ofClass: CaptureConfiguration.self,
            from: data
        )
        let decoded = try #require(unarchived)

        #expect(decoded.interface == original.interface)
        #expect(decoded.snapLength == original.snapLength)
        #expect(decoded.promiscuous == original.promiscuous)
        #expect(decoded.bpf == original.bpf)
    }

    @Test("Persisted settings resolve to bounded capture inputs")
    func settingsResolution() throws {
        let suiteName = "CaptureSettingsTests.\(UUID().uuidString)"
        let suite = try #require(UserDefaults(suiteName: suiteName))
        defer { suite.removePersistentDomain(forName: suiteName) }
        suite.set(-1, forKey: SettingsKeys.snapLength)
        suite.set(true, forKey: SettingsKeys.promiscuous)
        suite.set(CaptureFilterMode.custom.rawValue, forKey: SettingsKeys.captureFilterMode)
        suite.set("  host 1.1.1.1  ", forKey: SettingsKeys.bpfExpression)
        suite.set(50_000, forKey: SettingsKeys.retainPackets)

        let configuration = CaptureSettingsResolver.configuration(interface: "en0", defaults: suite)
        #expect(configuration.snapLength == CaptureConfiguration.defaultSnapLength)
        #expect(configuration.promiscuous)
        #expect(configuration.bpf == "host 1.1.1.1")
        #expect(CaptureSettingsResolver.retainCapacity(defaults: suite) == 50_000)
        #expect(CaptureSettingsResolver.resolvedRetainPackets(1_000_000) == 8_000)
    }

    @Test("Tunnel guidance appears only for a selected tunnel source")
    func tunnelGuidance() {
        let interfaces = [
            NetworkInterface(
                id: "en0", displayName: "Wi-Fi", category: .wifi,
                ipv4: "192.0.2.10", isUp: true, isLoopback: false
            ),
            NetworkInterface(
                id: "utun4", displayName: "VPN", category: .tunnels,
                ipv4: nil, isUp: true, isLoopback: false
            ),
        ]

        #expect(CaptureSourceGuidance.tunnelNote(for: "", in: interfaces) == nil)
        #expect(CaptureSourceGuidance.tunnelNote(for: "en0", in: interfaces) == nil)
        #expect(CaptureSourceGuidance.tunnelNote(for: "utun4", in: interfaces)?.contains("pre-encryption") == true)
    }
}

private extension Result {
    var failure: Failure? {
        guard case let .failure(error) = self else {
            return nil
        }
        return error
    }
}
