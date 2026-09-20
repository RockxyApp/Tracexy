import Foundation
import Testing
@testable import Tracexy

/// The General → "Confirm before quitting while capturing" setting gates the quit
/// confirmation: on by default, only an explicit false turns it off, and an idle
/// app never asks.
@Suite("Quit confirmation while capturing")
struct QuitConfirmationTests {
    @Test("An active capture asks by default, and honors an explicit opt-out")
    func capturingAsksUnlessOptedOut() throws {
        let suite = "tracexy.quit-confirmation.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        #expect(AppDelegate.shouldConfirmQuit(isCapturing: true, defaults: defaults))
        defaults.set(false, forKey: SettingsKeys.confirmQuitWhileCapturing)
        #expect(!AppDelegate.shouldConfirmQuit(isCapturing: true, defaults: defaults))
        defaults.set(true, forKey: SettingsKeys.confirmQuitWhileCapturing)
        #expect(AppDelegate.shouldConfirmQuit(isCapturing: true, defaults: defaults))
    }

    @Test("An idle app never asks, whatever the setting")
    func idleNeverAsks() throws {
        let suite = "tracexy.quit-confirmation.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(true, forKey: SettingsKeys.confirmQuitWhileCapturing)
        #expect(!AppDelegate.shouldConfirmQuit(isCapturing: false, defaults: defaults))
    }
}
