import Foundation
import Testing
@testable import Tracexy

// MARK: - ReplayBenchmarkTests

/// An **opt-in, informational** replay throughput benchmark.
///
/// Ordinary CI never runs the timed path: normal gates assert deterministic
/// outputs and structural bounds, never wall-clock time. Timing is enabled only
/// when the `TRACEXY_RUN_BENCHMARKS` Swift compilation condition is active, so
/// the standard unit run performs just a lightweight schedule assertion. The
/// timed path uses `ContinuousClock`, a fixed
/// warm-up / workload / repetition schedule, and prints frames/s plus bytes/s for
/// the decode-and-fold path in whatever configuration (Debug/Release) it is built.
/// It makes **no** absolute timing or RSS pass/fail promise and commits no machine
/// baseline — a number here is a local observation, not a threshold.
///
/// Run it with, e.g.:
///   xcodebuild ... test \
///     SWIFT_ACTIVE_COMPILATION_CONDITIONS='$(inherited) TRACEXY_RUN_BENCHMARKS' \
///     -only-testing:TracexyTests/ReplayBenchmarkTests
struct ReplayBenchmarkTests {
    // MARK: Internal

    @Test
    func decodeAndFoldThroughput() {
        guard Self.isOptedIn else {
            // Not opted in: assert only that the fixed schedule is well-formed,
            // without allocating the replicated workload or timing anything.
            #expect(Self.workloadCopies > 0)
            #expect(Self.warmUpRepetitions > 0)
            #expect(Self.measuredRepetitions > 0)
            return
        }

        let frames = Self.workload()
        let totalFrames = frames.count
        let totalBytes = frames.reduce(0) { $0 + $1.bytes.count }

        // Fixed warm-up passes (not measured), then fixed measured repetitions.
        for _ in 0 ..< Self.warmUpRepetitions {
            _ = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        }

        let clock = ContinuousClock()
        var best = Duration.seconds(Int.max)
        for _ in 0 ..< Self.measuredRepetitions {
            let elapsed = clock.measure {
                _ = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
            }
            if elapsed < best {
                best = elapsed
            }
        }

        let seconds = Self.seconds(best)
        let framesPerSecond = seconds > 0 ? Double(totalFrames) / seconds : 0
        let bytesPerSecond = seconds > 0 ? Double(totalBytes) / seconds : 0
        print(
            """
            [ReplayBenchmark] decode+fold \
            frames=\(totalFrames) bytes=\(totalBytes) \
            best=\(String(format: "%.4f", seconds))s \
            throughput=\(String(format: "%.0f", framesPerSecond)) frames/s, \
            \(String(format: "%.0f", bytesPerSecond)) bytes/s \
            (informational only — no threshold)
            """
        )
        // The only assertion is structural: the workload really was processed.
        #expect(totalFrames == ReplayCorpus.conversation().count * Self.workloadCopies)
    }

    // MARK: Private

    /// Fixed schedule — deliberately compile-time constants so a run is reproducible
    /// in shape (its *timing* is not, and is never asserted).
    private static let warmUpRepetitions = 2
    private static let measuredRepetitions = 5
    private static let workloadCopies = 200

    private static var isOptedIn: Bool {
        #if TRACEXY_RUN_BENCHMARKS
        true
        #else
        false
        #endif
    }

    /// The fixed workload: the primary conversation replicated a fixed number of
    /// times into one ordered frame array.
    private static func workload() -> [CapturedFrame] {
        let base = ReplayCorpus.conversationCapturedFrames()
        var frames: [CapturedFrame] = []
        frames.reserveCapacity(base.count * workloadCopies)
        for _ in 0 ..< workloadCopies {
            frames.append(contentsOf: base)
        }
        return frames
    }

    private static func seconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
