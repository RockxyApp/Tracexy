import Foundation

// MARK: - CaptureStatistics

/// Kernel-side capture accounting, read from `pcap_stats`.
///
/// This is the figure every other number in the app is conditional on. Session
/// counts, error rates, throughput and latency percentiles are all computed over
/// the packets that were *captured*, not the packets that existed — so without a
/// loss figure none of them can be falsified. A capture tool that cannot say how
/// much it missed is asking to be trusted rather than checked.
///
/// `CLAUDE.md` §3 requires drop-counting on the capture path; this is it.
nonisolated struct CaptureStatistics: Sendable, Equatable {
    /// Packets delivered to us by the kernel filter.
    var received: UInt32 = 0
    /// Packets the kernel buffer dropped because we did not drain it fast enough.
    var droppedByKernel: UInt32 = 0
    /// Packets the interface itself dropped before the filter saw them.
    var droppedByInterface: UInt32 = 0

    var totalDropped: UInt64 {
        UInt64(droppedByKernel) + UInt64(droppedByInterface)
    }

    /// Everything the capture could have seen.
    var totalOffered: UInt64 {
        UInt64(received) + totalDropped
    }

    /// Fraction of offered packets actually captured, `0...1`.
    ///
    /// `nil` when nothing has been offered yet. Reporting "100% captured" over
    /// zero packets would be technically true and practically a lie, so the UI
    /// gets an absence it has to handle rather than a reassuring number.
    var fidelity: Double? {
        guard totalOffered > 0 else {
            return nil
        }
        return Double(received) / Double(totalOffered)
    }

    /// True once loss is material enough that the user should distrust the
    /// derived numbers. Any loss at all is worth showing; this is the threshold
    /// for actively warning.
    var isLossy: Bool {
        guard let fidelity else {
            return false
        }
        return fidelity < 0.995
    }
}

// MARK: - CaptureStatistics + HelperCaptureStats

extension CaptureStatistics {
    /// Maps the helper's raw `pcap_stats` carrier onto the richer app figure. An
    /// explicit conversion in an extension (so the struct keeps its memberwise
    /// initializer) — the helper stays free of the app's fidelity/threshold
    /// policy and only reports the three counters it actually has.
    nonisolated init(helperStats: HelperCaptureStats) {
        self.init(
            received: helperStats.received,
            droppedByKernel: helperStats.droppedByKernel,
            droppedByInterface: helperStats.droppedByInterface
        )
    }
}
