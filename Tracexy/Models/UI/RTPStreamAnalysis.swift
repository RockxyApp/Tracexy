import Foundation

// MARK: - RTPStreamAnalysis

/// Telephony ▸ RTP ▸ Stream Analysis for one stream, as Wireshark's RTP Stream Analysis
/// computes it packet by packet (`ui/tap-rtp-analysis.c`): the time since the previous
/// in-order packet, the RFC 3550 jitter, the skew between the timestamp's clock and the
/// arrival clock, the bandwidth over the last second (IP and UDP headers included), the
/// marker bit and a status — plus the stream's summary.
nonisolated struct RTPStreamAnalysis: Equatable, Sendable {
    // MARK: Lifecycle

    init(stream: RTPStreamRow, rows: [CaptureFrameRow]) {
        let origin = rows.lazy.compactMap(\.provenance.timestamp).first
        var state = State()
        var packets: [Packet] = []
        for row in rows {
            guard let fact = row.rtp, fact.ssrc == stream.ssrc, fact.source == stream.source,
                  fact.destination == stream.destination, let time = row.provenance.timestamp, let origin else
            {
                continue
            }
            let now = (time.timeIntervalSince(origin) * 1e6).rounded() / 1e3
            var packet = state.add(fact, frame: row.ordinal, milliseconds: now, isIPv6: fact.source.ip.contains(":"))
            packet.time = now - state.startTime
            packets.append(packet)
        }
        self.packets = packets
        maxDelta = state.maxDelta
        maxDeltaFrame = state.maxDeltaFrame
        maxJitter = state.maxJitter
        meanJitter = state.meanJitter
        maxSkew = state.maxSkew
        expected = Int(state.stopSequence - state.startSequence + 1)
        sequenceErrors = state.sequenceErrors
        duration = (packets.last.map { _ in state.time } ?? 0) - state.startTime
        // Wireshark's least-squares fit of nominal against arrival time (`rtpstream_info_calculate`).
        let count = Double(packets.count)
        let denominator = count * state.sumt2 - state.sumt * state.sumt
        if count > 0, state.sumt2 > 0, denominator != 0 {
            let drift = (count * state.sumtTS - state.sumt * state.sumTS) / denominator
            clockDrift = duration * (drift - 1)
            frequencyDrift = drift * Double(UInt32(state.clockRate * drift))
            frequencyDriftPercent = 100 * (drift - 1)
        } else {
            clockDrift = 0
            frequencyDrift = 0
            frequencyDriftPercent = 0
        }
    }

    // MARK: Internal

    struct Packet: Identifiable, Hashable, Sendable {
        let frame: UInt64
        /// Milliseconds since the stream's first packet.
        var time: Double = 0
        let sequence: UInt16
        /// Milliseconds.
        let delta: Double
        let jitter: Double
        let skew: Double
        /// Kilobits per second over the last second.
        let bandwidth: Double
        let isMarker: Bool
        /// Wireshark's status, or `nil` when the packet is in order ("OK").
        let status: String?

        var id: UInt64 {
            frame
        }
    }

    let packets: [Packet]
    let maxDelta: Double
    let maxDeltaFrame: UInt64?
    let maxJitter: Double
    let meanJitter: Double
    let maxSkew: Double
    let expected: Int
    let sequenceErrors: Int
    /// Milliseconds from the first packet to the last in-order one.
    let duration: Double
    /// How far the sender's clock ran from the arrival clock over the stream, in ms.
    let clockDrift: Double
    /// The sender's effective clock rate in Hz, as Wireshark computes it.
    let frequencyDrift: Double
    let frequencyDriftPercent: Double

    var lost: Int {
        expected - packets.count
    }

    var csv: String {
        let lines = packets.map { packet in
            [
                String(packet.frame), String(packet.sequence), String(format: "%.3f", packet.delta),
                String(format: "%.3f", packet.jitter), String(format: "%.3f", packet.skew),
                String(format: "%.1f", packet.bandwidth), packet.isMarker ? "SET" : "", packet.status ?? "OK",
            ].joined(separator: ",")
        }
        return (["Packet,Sequence,Delta (ms),Jitter (ms),Skew,Bandwidth,Marker,Status"] + lines)
            .joined(separator: "\r\n") + "\r\n"
    }

    // MARK: Private

    private struct State {
        // MARK: Internal

        var isFirst = true
        var sequence: UInt16 = 0
        var startSequence: Int64 = 0
        var stopSequence: Int64 = 0
        var seqTimestamp: Int64 = 0
        var time = 0.0
        var startTime = 0.0
        var payloadType: UInt8 = 0
        var regularPayloadType: UInt8 = 0
        var delta = 0.0
        var jitter = 0.0
        var skew = 0.0
        var lastNominal = 0.0
        var lastArrival = 0.0
        var maxDelta = 0.0
        var maxDeltaFrame: UInt64?
        var maxJitter = 0.0
        var meanJitter = 0.0
        var maxSkew = 0.0
        var sequenceErrors = 0
        var total = 0
        var window: [(time: Double, bytes: Int)] = []
        var sequenceCycles: Int64 = 0
        var lastSequence: UInt16 = 0
        var timestampCycles: Int64 = 0
        var lastTimestamp: UInt32 = 0
        var seen = 0
        var sumt = 0.0
        var sumTS = 0.0
        var sumt2 = 0.0
        var sumtTS = 0.0
        var clockRate = 0.0

        mutating func add(_ fact: RTPFrameFact, frame: UInt64, milliseconds now: Double, isIPv6: Bool) -> Packet {
            seen += 1
            let extendedSequence = extend(sequence: fact.sequence)
            let extendedTimestamp = extend(timestamp: fact.timestamp)
            let bandwidth = bandwidth(now: now, bytes: fact.length + (isIPv6 ? 48 : 28))
            if isFirst {
                isFirst = false
                startSequence = extendedSequence
                stopSequence = extendedSequence
                sequence = fact.sequence
                startTime = now
                seqTimestamp = extendedTimestamp
                time = now
                payloadType = fact.payloadType
                regularPayloadType = fact.payloadType
                total = 1
                return Packet(
                    frame: frame, sequence: fact.sequence, delta: 0, jitter: 0, skew: 0, bandwidth: bandwidth,
                    isMarker: fact.isMarker, status: Self.comfortNoise(fact.payloadType)
                )
            }
            let inTimeSequence = seqTimestamp <= extendedTimestamp
            var wrongSequence = false
            if inTimeSequence, sequence &+ 1 == fact.sequence || (sequence == 65_535 && fact.sequence == 0) {
                sequence = fact.sequence
            } else if inTimeSequence,
                      Int(sequence) + 1 < Int(fact.sequence) || Int(sequence) - Int(fact.sequence) > 0xFF00
            {
                sequence = fact.sequence
                sequenceErrors += 1
                wrongSequence = true
            } else if Int(sequence) + 1 > Int(fact.sequence) {
                sequenceErrors += 1
                wrongSequence = true
            }
            let isComfortNoise = fact.payloadType == 13 || fact.payloadType == 19
            let followsComfortNoise = payloadType == 13 || payloadType == 19
            let payloadChanged = fact.payloadType != payloadType
            payloadType = fact.payloadType
            let clock = RTPStreams.clockRate(payloadType)
            var currentJitter = 0.0
            if clock != 0 {
                let nominalDifference = Double(extendedTimestamp - seqTimestamp) / (clock / 1_000)
                currentJitter = (15 * jitter + abs(now - (time + nominalDifference))) / 16
                delta = now - time
                jitter = currentJitter
                let nominal = lastNominal + nominalDifference
                let arrival = lastArrival + delta
                skew = nominal - arrival
                if abs(skew) > abs(maxSkew) {
                    maxSkew = skew
                }
                clockRate = clock
                sumt += arrival
                sumTS += nominal
                sumt2 += arrival * arrival
                sumtTS += arrival * nominal
                lastNominal = nominal
                lastArrival = arrival
            } else {
                delta = now - time
            }
            if !fact.isMarker, !isComfortNoise, inTimeSequence, !followsComfortNoise {
                if delta > maxDelta {
                    maxDelta = delta
                    maxDeltaFrame = frame
                }
                if clock != 0 {
                    maxJitter = max(maxJitter, jitter)
                    meanJitter = (meanJitter * Double(total - 1) + currentJitter) / Double(total)
                }
            }
            let regularChanged = !isComfortNoise && payloadType != regularPayloadType
            if !isComfortNoise {
                regularPayloadType = payloadType
            }
            if inTimeSequence {
                time = now
                seqTimestamp = extendedTimestamp
            }
            startSequence = min(startSequence, extendedSequence)
            stopSequence = max(stopSequence, extendedSequence)
            total += 1
            let status: String? = if let noise = Self.comfortNoise(payloadType) {
                noise
            } else if wrongSequence {
                String(localized: "Wrong sequence number")
            } else if regularChanged {
                String(localized: "Payload changed to PT=\(payloadType)")
            } else if !inTimeSequence {
                String(localized: "Incorrect timestamp")
            } else if payloadChanged, followsComfortNoise, !fact.isMarker {
                String(localized: "Marker missing?")
            } else {
                nil
            }
            return Packet(
                frame: frame, sequence: fact.sequence, delta: delta, jitter: jitter, skew: skew, bandwidth: bandwidth,
                isMarker: fact.isMarker, status: status
            )
        }

        // MARK: Private

        private static func comfortNoise(_ type: UInt8) -> String? {
            switch type {
            case 13: String(localized: "Comfort noise (PT=13, RFC 3389)")
            case 19: String(localized: "Comfort noise (PT=19, reserved)")
            default: nil
            }
        }

        /// Kilobits per second of this packet and those less than a second before it.
        private mutating func bandwidth(now: Double, bytes: Int) -> Double {
            window.append((now, bytes))
            while let first = window.first, first.time + 1_000 < now {
                window.removeFirst()
            }
            return Double(window.reduce(0) { $0 + $1.bytes } * 8) / 1_000
        }

        private mutating func extend(sequence value: UInt16) -> Int64 {
            if seen > 1 {
                if value < lastSequence, lastSequence - value > 0x8000 {
                    sequenceCycles += 1
                } else if value > lastSequence, value - lastSequence > 0x8000, sequenceCycles > 0 {
                    lastSequence = value
                    return (sequenceCycles - 1) << 16 | Int64(value)
                }
            }
            lastSequence = value
            return sequenceCycles << 16 | Int64(value)
        }

        private mutating func extend(timestamp value: UInt32) -> Int64 {
            if seen > 1 {
                if value < lastTimestamp, lastTimestamp - value > 0x80000000 {
                    timestampCycles += 1
                } else if value > lastTimestamp, value - lastTimestamp > 0x80000000, timestampCycles > 0 {
                    lastTimestamp = value
                    return (timestampCycles - 1) << 32 | Int64(value)
                }
            }
            lastTimestamp = value
            return timestampCycles << 32 | Int64(value)
        }
    }
}
