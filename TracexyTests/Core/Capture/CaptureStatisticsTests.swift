import Foundation
import Testing
@testable import Tracexy

@Suite("Capture statistics")
struct CaptureStatisticsTests {
    @Test("A clean capture reports full fidelity")
    func cleanCapture() {
        let stats = CaptureStatistics(received: 10_000, droppedByKernel: 0, droppedByInterface: 0)

        #expect(stats.totalDropped == 0)
        #expect(stats.totalOffered == 10_000)
        #expect(stats.fidelity == 1.0)
        #expect(!stats.isLossy)
    }

    @Test("Fidelity counts both kernel and interface drops")
    func bothDropSources() {
        let stats = CaptureStatistics(received: 900, droppedByKernel: 60, droppedByInterface: 40)

        #expect(stats.totalDropped == 100)
        #expect(stats.totalOffered == 1_000)
        #expect(stats.fidelity == 0.9)
        #expect(stats.isLossy)
    }

    @Test("Zero packets is unmeasured, not perfect")
    func zeroIsUnmeasured() {
        let stats = CaptureStatistics()

        // Reporting 100% over nothing would be technically true and practically
        // a lie, so callers get an absence they must handle.
        #expect(stats.fidelity == nil)
        #expect(!stats.isLossy)
    }

    @Test("A single dropped packet is visible but not yet alarming")
    func trivialLossIsNotAlarming() {
        let stats = CaptureStatistics(received: 999_999, droppedByKernel: 1, droppedByInterface: 0)

        #expect(stats.totalDropped == 1)
        #expect((stats.fidelity ?? 0) < 1.0)
        #expect(!stats.isLossy)
    }

    @Test("Loss past the threshold is flagged")
    func materialLossIsFlagged() {
        let stats = CaptureStatistics(received: 990, droppedByKernel: 10, droppedByInterface: 0)

        #expect(stats.fidelity == 0.99)
        #expect(stats.isLossy)
    }

    @Test("Combined 32-bit pcap counters widen instead of wrapping")
    func combinedCountersDoNotWrap() {
        let stats = CaptureStatistics(
            received: UInt32.max,
            droppedByKernel: UInt32.max,
            droppedByInterface: UInt32.max
        )

        #expect(stats.totalDropped == UInt64(UInt32.max) * 2)
        #expect(stats.totalOffered == UInt64(UInt32.max) * 3)
        #expect((stats.fidelity ?? 0) > 0.333)
        #expect((stats.fidelity ?? 1) < 0.334)
    }
}
