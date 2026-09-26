import Foundation
import Testing
@testable import Tracexy

@MainActor
@Suite("Capture auto-stop limits")
struct CaptureAutoStopTests {
    @Test("Whichever limit comes first stops the capture; zero means never")
    func limits() {
        let off = CaptureAutoStop.Limits(minutes: 0, packets: 0)
        #expect(!off.isEnabled)
        #expect(off.reason(elapsed: 1e9, acceptedPackets: .max) == nil)

        let time = CaptureAutoStop.Limits(minutes: 5, packets: 0)
        #expect(time.reason(elapsed: 299, acceptedPackets: 10_000_000) == nil)
        #expect(time.reason(elapsed: 300, acceptedPackets: 0) == "stopped after 5 minutes")
        #expect(CaptureAutoStop.Limits(minutes: 1, packets: 0).reason(elapsed: 60, acceptedPackets: 0)
            == "stopped after 1 minute")

        let packets = CaptureAutoStop.Limits(minutes: 0, packets: 10_000)
        #expect(packets.reason(elapsed: 1e9, acceptedPackets: 9_999) == nil)
        #expect(packets.reason(elapsed: 0, acceptedPackets: 10_000) == "stopped after \(10_000.formatted()) packets")
    }

    @Test("Limits are read from the Project's own settings")
    func resolvesFromDefaults() throws {
        let suite = "com.amunx.tracexy.tests.autostop.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        #expect(!CaptureAutoStop.Limits.resolve(defaults: defaults).isEnabled)
        defaults.set(15, forKey: SettingsKeys.autoStopMinutes)
        defaults.set(-3, forKey: SettingsKeys.autoStopPackets)
        #expect(CaptureAutoStop.Limits.resolve(defaults: defaults) == .init(minutes: 15, packets: 0))
    }
}
