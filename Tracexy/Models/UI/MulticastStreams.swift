import Foundation

// MARK: - MulticastStreamRow

/// One UDP multicast stream (source and group endpoints) as Wireshark's Statistics ▸
/// UDP Multicast Streams reports it: packets, rates, the largest burst inside the
/// burst interval, and how full a receiver's buffer drained at the empty speed would
/// have grown. Rates in bits per second, buffers in bytes.
nonisolated struct MulticastStreamRow: Identifiable, Hashable, Sendable {
    // MARK: Internal

    let source: IPEndpoint
    let destination: IPEndpoint
    let packets: Int
    let packetsPerSecond: Double
    let averageBitsPerSecond: Double
    let maxBitsPerSecond: Double
    let maxBurst: Int
    let burstAlarms: Int
    let maxBufferBytes: Int
    let bufferAlarms: Int
    let firstFrame: UInt64

    var id: String {
        "\(source.display)>\(destination.display)"
    }

    /// Addresses as Wireshark prints them (RFC 5952 for IPv6), with the port.
    var sourceText: String {
        Self.text(source)
    }

    var groupText: String {
        Self.text(destination)
    }

    /// The Session Expression that finds the stream's session.
    var term: String {
        "ip == \(source.ip) and ip == \(destination.ip) and port == \(source.port) and port == \(destination.port)"
    }

    static func address(_ endpoint: IPEndpoint) -> String {
        IPAddressValue(parsing: endpoint.ip)?.compressedText ?? endpoint.ip
    }

    // MARK: Private

    private static func text(_ endpoint: IPEndpoint) -> String {
        let address = address(endpoint)
        return address.contains(":") ? "[\(address)]:\(endpoint.port)" : "\(address):\(endpoint.port)"
    }
}

// MARK: - MulticastStreamTotals

/// All multicast streams taken together, as the dialog's summary line reports them.
nonisolated struct MulticastStreamTotals: Hashable, Sendable {
    let averageBitsPerSecond: Double
    let maxBitsPerSecond: Double
    let maxBurst: Int
    let maxBufferBytes: Int
}

// MARK: - MulticastStreams

/// Statistics ▸ UDP Multicast Streams, computed as Wireshark's `mcaststream_packet`
/// (ui/mcast_stream.c) does, per UDP datagram to an IPv4 224/4 or IPv6 ff00::/8
/// group: bytes are the UDP length field; a burst counts the stream's earlier
/// datagrams within the burst interval of this one; the buffer fills with each
/// datagram and drains at the empty speed for the time since the previous one (from
/// time zero for the first). Every quirk of that code is kept so the numbers match.
nonisolated enum MulticastStreams {
    // MARK: Internal

    /// The dialog's editable parameters, with Wireshark's defaults and ranges.
    struct Parameters: Hashable, Sendable {
        static let burstIntervalRange = 1 ... 1_000
        static let emptySpeedRange = 1 ... 10_000_000

        /// Milliseconds.
        var burstInterval = 100
        /// Datagrams inside one burst interval.
        var burstAlarmThreshold = 50
        /// Bytes.
        var bufferAlarmThreshold = 10_000
        /// kbit/s drained from one stream's buffer.
        var streamEmptySpeed = 5_000
        /// kbit/s drained from the buffer all streams share.
        var totalEmptySpeed = 100_000

        var isValid: Bool {
            Self.burstIntervalRange.contains(burstInterval) && burstAlarmThreshold >= 1 && bufferAlarmThreshold >= 1
                && Self.emptySpeedRange.contains(streamEmptySpeed) && Self.emptySpeedRange.contains(totalEmptySpeed)
        }
    }

    struct Result: Sendable {
        let streams: [MulticastStreamRow]
        let totals: MulticastStreamTotals?
    }

    static func streams(rows: [CaptureFrameRow], parameters: Parameters = Parameters()) -> Result {
        let origin = rows.lazy.compactMap(\.provenance.timestamp).first
        var states: [String: State] = [:]
        var order: [String] = []
        var all: State?
        for row in rows {
            guard let fact = row.multicast, let time = row.provenance.timestamp, let origin else {
                continue
            }
            // Microseconds, as the capture's own timestamps are; `Date` alone would
            // carry a fraction of a microsecond of rounding noise.
            let relative = Int64((time.timeIntervalSince(origin) * 1_000_000).rounded()) * 1_000
            let key = "\(fact.source.display)>\(fact.destination.display)"
            let bytes = Int32(fact.udpLength)
            if states[key] == nil {
                order.append(key)
                states[key] = State(fact: fact, frame: row.ordinal, start: relative, bytes: bytes)
                if all == nil {
                    all = State(fact: fact, frame: row.ordinal, start: relative, bytes: bytes)
                }
            }
            states[key]?.add(
                at: relative,
                bytes: bytes,
                emptySpeed: Double(parameters.streamEmptySpeed) * 1_000,
                parameters: parameters
            )
            all?.add(
                at: relative,
                bytes: bytes,
                emptySpeed: Double(parameters.totalEmptySpeed) * 1_000,
                parameters: parameters
            )
        }
        let streams = order.compactMap { states[$0]?.row }
        let totals = all.map {
            MulticastStreamTotals(
                averageBitsPerSecond: $0.averageBitsPerSecond,
                maxBitsPerSecond: $0.maxBitsPerSecond,
                maxBurst: Int($0.topBurstSize),
                maxBufferBytes: Int($0.topBufferUsage)
            )
        }
        return Result(streams: streams, totals: totals)
    }

    static func csv(_ streams: [MulticastStreamRow]) -> String {
        let header = [
            "Source Address", "Source Port", "Destination Address", "Destination Port", "Packets", "Packets/s",
            "Avg BW (bps)", "Max BW (bps)", "Max Burst", "Burst Alarms", "Max Buffers (B)", "Buffer Alarms",
        ]
        let lines = streams.map { row in
            [
                MulticastStreamRow.address(row.source), String(row.source.port),
                MulticastStreamRow.address(row.destination), String(row.destination.port),
                String(row.packets), String(format: "%.2f", row.packetsPerSecond),
                String(format: "%.0f", row.averageBitsPerSecond), String(format: "%.0f", row.maxBitsPerSecond),
                String(row.maxBurst), String(row.burstAlarms), String(row.maxBufferBytes), String(row.bufferAlarms),
            ].joined(separator: ",")
        }
        return ([header.joined(separator: ",")] + lines).joined(separator: "\r\n") + "\r\n"
    }

    // MARK: Private

    /// One stream's running state, `mcast_stream_info_t` and its `t_buffer`.
    private struct State {
        // MARK: Lifecycle

        init(fact: MulticastFrameFact, frame: UInt64, start: Int64, bytes: Int32) {
            source = fact.source
            destination = fact.destination
            firstFrame = frame
            self.start = start
            stop = start
            bufferUsage = bytes
            topBufferUsage = bytes
        }

        // MARK: Internal

        let source: IPEndpoint
        let destination: IPEndpoint
        let firstFrame: UInt64
        let start: Int64
        var stop: Int64
        var packets = 0
        var totalBytes: Int64 = 0
        /// Arrival times of the datagrams still inside the burst interval.
        var window: [Int64] = []
        var windowHead = 0
        /// The previous datagram's arrival; Wireshark reads a zeroed slot (time
        /// zero) before the first.
        var previous: Int64 = 0
        var topBurstSize: Int32 = 1
        var burstAlarmOn = false
        var burstAlarms = 0
        var bufferUsage: Int32
        var topBufferUsage: Int32
        var bufferAlarmOn = false
        var bufferAlarms = 0
        var maxBitsPerSecond = 0.0

        var seconds: Double {
            Double(stop - start) / 1_000_000_000
        }

        var averageBitsPerSecond: Double {
            seconds > 0 ? Double(totalBytes * 8) / seconds : 0
        }

        var row: MulticastStreamRow {
            MulticastStreamRow(
                source: source,
                destination: destination,
                packets: packets,
                packetsPerSecond: seconds > 0 ? Double(packets) / seconds : 0,
                averageBitsPerSecond: averageBitsPerSecond,
                maxBitsPerSecond: maxBitsPerSecond,
                maxBurst: Int(topBurstSize),
                burstAlarms: burstAlarms,
                maxBufferBytes: Int(topBufferUsage),
                bufferAlarms: bufferAlarms,
                firstFrame: firstFrame
            )
        }

        mutating func add(at time: Int64, bytes: Int32, emptySpeed: Double, parameters: Parameters) {
            stop = time
            totalBytes += Int64(bytes)
            packets += 1
            slide(to: time, bytes: bytes, parameters: parameters)
            fillBuffer(at: time, bytes: bytes, emptySpeed: emptySpeed, alarm: Int32(parameters.bufferAlarmThreshold))
        }

        // MARK: Private

        /// `(t2.secs − t1.secs) × 1000 + (t2.nsecs − t1.nsecs) / 1000000`, each part
        /// in C integer arithmetic.
        private static func milliseconds(from first: Int64, to second: Int64) -> Int {
            let (firstSeconds, firstNanos) = split(first)
            let (secondSeconds, secondNanos) = split(second)
            return Int((secondSeconds - firstSeconds) * 1_000 + (secondNanos - firstNanos) / 1_000_000)
        }

        private static func split(_ nanoseconds: Int64) -> (Int64, Int64) {
            let seconds = nanoseconds >= 0 ? nanoseconds / 1_000_000_000 : (nanoseconds + 1) / 1_000_000_000 - 1
            return (seconds, nanoseconds - seconds * 1_000_000_000)
        }

        /// `slidingwindow`: drop earlier arrivals more than the burst interval before
        /// this one (compared in whole milliseconds, truncated, as `comparetimes`).
        private mutating func slide(to time: Int64, bytes: Int32, parameters: Parameters) {
            while windowHead < window.count,
                  Self.milliseconds(from: window[windowHead], to: time) > parameters.burstInterval
            {
                windowHead += 1
            }
            if windowHead > 4_096 {
                window.removeFirst(windowHead)
                windowHead = 0
            }
            let burst = Int32(window.count - windowHead)
            window.append(time)
            if burst > topBurstSize {
                topBurstSize = burst
                maxBitsPerSecond = Double(topBurstSize) * 1_000 / Double(parameters.burstInterval) * Double(bytes) * 8
            }
            if burst >= Int32(parameters.burstAlarmThreshold), !burstAlarmOn {
                burstAlarmOn = true
                burstAlarms += 1
            } else if burst < Int32(parameters.burstAlarmThreshold) {
                burstAlarmOn = false
            }
        }

        /// `buffusagecalc`, with its 32-bit arithmetic: the drained bytes convert to
        /// an unsigned 32-bit value (saturating, as on Apple silicon) and the
        /// subtraction wraps before the clamp at zero.
        private mutating func fillBuffer(at time: Int64, bytes: Int32, emptySpeed: Double, alarm: Int32) {
            let elapsed = Double(time - previous) / 1_000_000_000
            previous = time
            let drained = elapsed * emptySpeed / 8
            let drainedBytes: UInt32 = drained >= Double(UInt32.max) ? .max : (drained <= 0 ? 0 : UInt32(drained))
            bufferUsage = bufferUsage &+ bytes
            bufferUsage = Int32(bitPattern: UInt32(bitPattern: bufferUsage) &- drainedBytes)
            bufferUsage = max(bufferUsage, 0)
            topBufferUsage = max(topBufferUsage, bufferUsage)
            if bufferUsage >= alarm, !bufferAlarmOn {
                bufferAlarmOn = true
                bufferAlarms += 1
            } else if bufferUsage < alarm {
                bufferAlarmOn = false
            }
        }
    }
}
