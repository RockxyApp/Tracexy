import Foundation

// MARK: - RTPStreamRow

/// One RTP stream (source, destination and SSRC) as Wireshark's Telephony ▸ RTP ▸
/// RTP Streams and `tshark -z rtp,streams` report it. Times in seconds from the
/// first frame; deltas and jitter in milliseconds.
nonisolated struct RTPStreamRow: Identifiable, Hashable, Sendable {
    let source: IPEndpoint
    let destination: IPEndpoint
    let ssrc: UInt32
    let payloads: String
    let start: Double
    let end: Double
    let packets: Int
    let expected: Int
    let sequenceErrors: Int
    let minDelta: Double
    let meanDelta: Double
    let maxDelta: Double
    /// `nil` when the payload type's clock rate is unknown (a dynamic type), as
    /// Wireshark can then not measure jitter.
    let jitter: (min: Double, mean: Double, max: Double)?
    let hasProblem: Bool
    let firstFrame: UInt64

    var id: String {
        "\(source.display)>\(destination.display)#\(ssrc)"
    }

    var lost: Int {
        expected - packets
    }

    var lostPercent: Double {
        expected > 0 ? Double(lost) * 100 / Double(expected) : 0
    }

    var ssrcText: String {
        String(format: "0x%08X", ssrc)
    }

    /// The Session Expression that finds the stream's session.
    var term: String {
        "ip == \(source.ip) and ip == \(destination.ip) and port == \(source.port) and port == \(destination.port)"
    }

    static func == (lhs: RTPStreamRow, rhs: RTPStreamRow) -> Bool {
        lhs.id == rhs.id && lhs.packets == rhs.packets && lhs.end == rhs.end
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

// MARK: - RTPStreams

/// Statistics ▸ RTP Streams, computed as Wireshark's `rtppacket_analyse`
/// (ui/tap-rtp-analysis.c) does, per packet: extended sequence numbers, RFC 3550
/// jitter from the payload type's clock rate, deltas and jitter over regular
/// packets only (not the first, a marked one or comfort noise), lost = expected −
/// received, and a problem flag for a wrong sequence number or timestamp.
nonisolated enum RTPStreams {
    // MARK: Internal

    static func streams(rows: [CaptureFrameRow]) -> [RTPStreamRow] {
        let origin = rows.lazy.compactMap(\.provenance.timestamp).first
        var states: [String: State] = [:]
        var order: [String] = []
        for row in rows {
            guard let fact = row.rtp, let time = row.provenance.timestamp, let origin else {
                continue
            }
            let key = "\(fact.source.display)>\(fact.destination.display)#\(fact.ssrc)"
            if states[key] == nil {
                order.append(key)
                states[key] = State(fact: fact, frame: row.ordinal)
            }
            states[key]?.add(fact, milliseconds: time.timeIntervalSince(origin) * 1_000)
        }
        return order.compactMap { states[$0]?.row }
    }

    static func csv(_ rows: [RTPStreamRow]) -> String {
        var lines = [
            "Source Address,Source Port,Destination Address,Destination Port,SSRC,Payload,Packets,Lost,Lost %,"
                +
                "Min Delta (ms),Mean Delta (ms),Max Delta (ms),Min Jitter (ms),Mean Jitter (ms),Max Jitter (ms),Problem",
        ]
        for row in rows {
            let jitter = row.jitter.map { [format($0.min), format($0.mean), format($0.max)] } ?? ["", "", ""]
            lines.append(([
                row.source.ip, String(row.source.port), row.destination.ip, String(row.destination.port), row.ssrcText,
                row.payloads, String(row.packets), String(row.lost), format(row.lostPercent, digits: 1),
                format(row.minDelta), format(row.meanDelta), format(row.maxDelta),
            ] + jitter + [row.hasProblem ? "yes" : "no"]).map(csvField).joined(separator: ","))
        }
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    /// Wireshark's short names for the static payload types; dynamic ones are
    /// `DynamicRTP-Type-N`.
    static func payloadName(_ type: UInt8) -> String {
        switch type {
        case 0: "g711U"
        case 1: "fs-1016"
        case 2: "g721"
        case 3: "GSM"
        case 4: "g723"
        case 5: "DVI4 8k"
        case 6: "DVI4 16k"
        case 7: "LPC"
        case 8: "g711A"
        case 9: "g722"
        case 10: "L16 stereo"
        case 11: "L16 mono"
        case 12: "QCELP"
        case 13: "CN"
        case 14: "MPA"
        case 15: "g728"
        case 16: "DVI4 11k"
        case 17: "DVI4 22k"
        case 18: "g729"
        case 19: "CN(old)"
        case 25: "CellB"
        case 26: "JPEG"
        case 28: "NV"
        case 31: "h261"
        case 32: "MPV"
        case 33: "MP2T"
        case 34: "h263"
        case 96 ... 127: "DynamicRTP-Type-\(type)"
        default: "Unassigned-\(type)"
        }
    }

    /// Sampling clocks of the static payload types (IANA); 0 = unknown.
    static func clockRate(_ type: UInt8) -> Double {
        switch type {
        case 0 ... 5,
             7 ... 9,
             12,
             13,
             15,
             18,
             19: 8_000
        case 6: 16_000
        case 10,
             11: 44_100
        case 16: 11_025
        case 17: 22_050
        case 14,
             25,
             26,
             28,
             31 ... 34: 90_000
        default: 0
        }
    }

    // MARK: Private

    /// One stream's running statistics, field for field as `tap_rtp_stat_t`.
    private struct State {
        // MARK: Lifecycle

        init(fact: RTPFrameFact, frame: UInt64) {
            source = fact.source
            destination = fact.destination
            ssrc = fact.ssrc
            firstFrame = frame
        }

        // MARK: Internal

        let source: IPEndpoint
        let destination: IPEndpoint
        let ssrc: UInt32
        let firstFrame: UInt64
        var payloadTypes: [UInt8] = []
        var packetCount = 0
        var totalCount = 0
        var startTime = 0.0
        var stopTime = 0.0
        var time = 0.0
        var sequence: UInt16 = 0
        var sequenceCycles: Int64 = 0
        var lastSequence: UInt16 = 0
        var startSequence: Int64 = 0
        var stopSequence: Int64 = 0
        var timestampCycles: Int64 = 0
        var lastTimestamp: UInt32 = 0
        var seqTimestamp: Int64 = 0
        var payloadType: UInt8 = 0
        var delta = 0.0
        var minDelta = -1.0
        var maxDelta = 0.0
        var meanDelta = 0.0
        var jitter = 0.0
        var minJitter = -1.0
        var maxJitter = 0.0
        var meanJitter = 0.0
        var measuredJitter = false
        var sequenceErrors = 0
        var hasProblem = false

        var row: RTPStreamRow {
            RTPStreamRow(
                source: source, destination: destination, ssrc: ssrc,
                payloads: payloadTypes.map(RTPStreams.payloadName).joined(separator: ", "),
                start: startTime / 1_000, end: stopTime / 1_000, packets: packetCount,
                expected: Int(stopSequence - startSequence + 1), sequenceErrors: sequenceErrors,
                minDelta: max(minDelta, 0), meanDelta: meanDelta, maxDelta: maxDelta,
                jitter: measuredJitter ? (max(minJitter, 0), meanJitter, maxJitter) : nil,
                hasProblem: hasProblem, firstFrame: firstFrame
            )
        }

        mutating func add(_ fact: RTPFrameFact, milliseconds now: Double) {
            if !payloadTypes.contains(fact.payloadType) {
                payloadTypes.append(fact.payloadType)
            }
            packetCount += 1
            stopTime = now
            let extendedSequence = extend(sequence: fact.sequence)
            let extendedTimestamp = extend(timestamp: fact.timestamp)
            guard totalCount > 0 else {
                startSequence = extendedSequence
                stopSequence = extendedSequence
                sequence = fact.sequence
                startTime = now
                seqTimestamp = extendedTimestamp
                time = now
                payloadType = fact.payloadType
                totalCount = 1
                return
            }
            let inTimeSequence = seqTimestamp <= extendedTimestamp
            var wrongSequence = false
            if inTimeSequence, sequence &+ 1 == fact.sequence {
                sequence = fact.sequence
            } else if inTimeSequence, sequence == 65_535, fact.sequence == 0 {
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
            payloadType = fact.payloadType
            let clock = RTPStreams.clockRate(payloadType)
            var currentJitter = 0.0
            if clock != 0 {
                let nominal = Double(extendedTimestamp - seqTimestamp) / (clock / 1_000)
                let difference = abs(now - (time + nominal))
                currentJitter = (15 * jitter + difference) / 16
                delta = now - time
                jitter = currentJitter
            } else {
                delta = now - time
            }
            if wrongSequence || !inTimeSequence {
                hasProblem = true
            }
            let isRegular = !fact.isMarker && !isComfortNoise && inTimeSequence && !followsComfortNoise
            if isRegular {
                maxDelta = max(maxDelta, delta)
                minDelta = minDelta == -1 ? delta : min(minDelta, delta)
                meanDelta = (meanDelta * Double(totalCount - 1) + delta) / Double(totalCount)
                if clock != 0 {
                    measuredJitter = true
                    maxJitter = max(maxJitter, jitter)
                    meanJitter = (meanJitter * Double(totalCount - 1) + currentJitter) / Double(totalCount)
                    minJitter = minJitter == -1 ? jitter : min(minJitter, jitter)
                }
            }
            if inTimeSequence {
                time = now
                seqTimestamp = extendedTimestamp
            }
            startSequence = min(startSequence, extendedSequence)
            stopSequence = max(stopSequence, extendedSequence)
            totalCount += 1
        }

        // MARK: Private

        /// The sequence number with its wrap count, as the RTP dissector extends it.
        private mutating func extend(sequence value: UInt16) -> Int64 {
            if packetCount > 1 {
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
            if packetCount > 1 {
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

    private static func format(_ value: Double, digits: Int = 3) -> String {
        String(format: "%.\(digits)f", value)
    }

    private static func csvField(_ text: String) -> String {
        text.contains { [",", "\"", "\n"].contains($0) } ? "\"" + text
            .replacingOccurrences(of: "\"", with: "\"\"") + "\"" : text
    }
}
