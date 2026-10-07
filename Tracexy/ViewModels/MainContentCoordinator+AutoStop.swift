import Foundation
import Observation

// MARK: - CaptureAutoStop

/// Settings → Capture → Stop automatically: a live capture ends on its own after a
/// set time or a set number of packets, so it can be left running unattended.
///
/// The check runs once a second from a task armed at each confirmed capture start.
/// It holds no capture state of its own: it reads the coordinator's start instant
/// and accepted-frame count, and it stops only the exact capture generation it was
/// armed for — a manual stop, a restart or a Project switch retires it silently.
@MainActor
@Observable
final class CaptureAutoStop {
    /// The limits a start adopts, read from the active Project's settings.
    struct Limits: Equatable {
        var minutes: Int
        var packets: Int

        var isEnabled: Bool {
            minutes > 0 || packets > 0
        }

        static func resolve(defaults: UserDefaults) -> Limits {
            Limits(
                minutes: max(0, defaults.integer(forKey: SettingsKeys.autoStopMinutes)),
                packets: max(0, defaults.integer(forKey: SettingsKeys.autoStopPackets))
            )
        }

        /// The reason to stop now, or `nil` to keep capturing.
        func reason(elapsed: TimeInterval, acceptedPackets: Int) -> String? {
            if minutes > 0, elapsed >= TimeInterval(minutes * 60) {
                return minutes == 1 ? "stopped after 1 minute" : "stopped after \(minutes) minutes"
            }
            if packets > 0, acceptedPackets >= packets {
                return "stopped after \(packets.formatted()) packets"
            }
            return nil
        }
    }

    /// Why the last capture stopped on its own, shown until the next capture starts.
    private(set) var stoppedReason: String?

    @ObservationIgnored var task: Task<Void, Never>?

    func clear() {
        stoppedReason = nil
    }

    func record(_ reason: String) {
        stoppedReason = reason
    }
}

// MARK: - Arming

@MainActor
extension MainContentCoordinator {
    /// Arm the automatic stop for the capture generation that just started. Called
    /// from the confirmed-start path; a clear during capture re-arms against the same
    /// start instant, so the time limit still counts from the start.
    func armAutoStop(captureGeneration: Int) {
        autoStop.task?.cancel()
        autoStop.clear()
        let limits = CaptureAutoStop.Limits.resolve(defaults: activeProjectDefaults)
        guard limits.isEnabled else {
            autoStop.task = nil
            return
        }
        autoStop.task = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else {
                    return
                }
                guard self.isCapturing, self.startGeneration == captureGeneration,
                      let started = self.captureStartedAt else
                {
                    return
                }
                let accepted = self.retainedFrames.frames.count + Int(self.retainedFrames.evictionCount)
                if let reason = limits.reason(elapsed: Date().timeIntervalSince(started), acceptedPackets: accepted) {
                    self.stopCapture()
                    self.autoStop.record(reason)
                    return
                }
            }
        }
    }
}
