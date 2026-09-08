import Foundation

/// Validates a known instant before narrowing it into a capture-file counter.
nonisolated enum CaptureTimestampEncoding {
    static func microseconds(_ date: Date) throws -> UInt64 {
        let interval = date.timeIntervalSince1970
        let scaled = (interval * 1_000_000).rounded()
        guard interval.isFinite, interval >= 0, scaled.isFinite,
              let ticks = UInt64(exactly: scaled) else
        {
            throw SessionExportError.timestampNotRepresentable
        }
        return ticks
    }

    static func classic(_ date: Date) throws -> (seconds: UInt32, microseconds: UInt32) {
        let interval = date.timeIntervalSince1970
        guard interval.isFinite, interval >= 0,
              let seconds = UInt32(exactly: interval.rounded(.down)) else
        {
            throw SessionExportError.timestampNotRepresentable
        }
        let fraction = ((interval - interval.rounded(.down)) * 1_000_000).rounded()
        return (seconds, min(UInt32(fraction), 999_999))
    }
}
