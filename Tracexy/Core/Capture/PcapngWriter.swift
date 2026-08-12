import Foundation

// MARK: - PcapngWriter

/// Writer for pcapng capture files. Each distinct link type receives its own
/// Interface Description Block, so exported sessions preserve per-frame link
/// metadata that classic pcap cannot represent.
nonisolated enum PcapngWriter {
    // MARK: Internal

    static func data(defaultLinkType: UInt32, frames: [CapturedFrame]) throws -> Data {
        let linkTypes = orderedLinkTypes(defaultLinkType: defaultLinkType, frames: frames)
        guard linkTypes.allSatisfy({ $0 <= UInt32(UInt16.max) }) else {
            throw SessionExportError.unsupportedLinkType
        }

        var interfaceIDs: [UInt32: UInt32] = [:]
        for (index, linkType) in linkTypes.enumerated() {
            interfaceIDs[linkType] = UInt32(index)
        }

        var output = Data()
        appendBlock(type: 0x0A0D0D0A, to: &output) { body in
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
        }

        for linkType in linkTypes {
            appendBlock(type: 0x00000001, to: &output) { body in
                append16(UInt16(linkType), to: &body)
                append16(0, to: &body)
                append32(PcapWriter.snapLength, to: &body)
            }
        }

        for frame in frames {
            let linkType = frame.linkType ?? defaultLinkType
            guard let interfaceID = interfaceIDs[linkType] else {
                continue
            }
            let microseconds = timestampMicroseconds(frame.timestamp)
            appendBlock(type: 0x00000006, to: &output) { body in
                append32(interfaceID, to: &body)
                append32(UInt32(microseconds >> 32), to: &body)
                append32(UInt32(microseconds & UInt64(UInt32.max)), to: &body)
                append32(UInt32(frame.bytes.count), to: &body)
                append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &body)
                body.append(contentsOf: frame.bytes)
            }
        }
        return output
    }

    static func write(defaultLinkType: UInt32, frames: [CapturedFrame], to url: URL) throws {
        try data(defaultLinkType: defaultLinkType, frames: frames).write(to: url, options: .atomic)
    }

    // MARK: Private

    private static func orderedLinkTypes(defaultLinkType: UInt32, frames: [CapturedFrame]) -> [UInt32] {
        var seen = Set<UInt32>()
        var result: [UInt32] = []
        for frame in frames {
            let linkType = frame.linkType ?? defaultLinkType
            if seen.insert(linkType).inserted {
                result.append(linkType)
            }
        }
        return result.isEmpty ? [defaultLinkType] : result
    }

    private static func timestampMicroseconds(_ date: Date) -> UInt64 {
        let interval = max(0, date.timeIntervalSince1970)
        let scaled = interval * 1_000_000
        return UInt64(min(scaled.rounded(), Double(UInt64.max)))
    }

    private static func appendBlock(type: UInt32, to data: inout Data, body build: (inout Data) -> Void) {
        var body = Data()
        build(&body)
        while body.count % 4 != 0 {
            body.append(0)
        }
        let totalLength = UInt32(12 + body.count)
        append32(type, to: &data)
        append32(totalLength, to: &data)
        data.append(body)
        append32(totalLength, to: &data)
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }

    private static func append64(_ value: UInt64, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
}
