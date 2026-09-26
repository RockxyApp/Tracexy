import Foundation

// MARK: - PcapngBlockWriter

/// The few PCAPNG blocks Tracexy writes when it builds a new file from frames it
/// read — merge, split — little-endian, with a Tracexy `shb_userappl`.
nonisolated enum PcapngBlockWriter {
    // MARK: Internal

    static func sectionHeader(comment: String?) -> Data {
        var body = Data()
        append32(0x1A2B3C4D, to: &body)
        append16(1, to: &body)
        append16(0, to: &body)
        append64(UInt64.max, to: &body)
        if let comment {
            appendOption(code: 1, value: utf8Prefix(comment, maxBytes: 8_192), to: &body)
        }
        appendOption(code: 4, value: Array("Tracexy".utf8), to: &body)
        append32(0, to: &body)
        return block(type: 0x0A0D0D0A, body: body)
    }

    /// Frames whose times are shifted by `shift` seconds are written at the shifted
    /// instant; a shift that moves a frame before 1970 or past the 64-bit
    /// microsecond range throws, like any unencodable time.
    static func enhancedPacket(
        _ event: CaptureFrameEvent,
        interfaceID: UInt32,
        time: Date,
        shift: TimeInterval = 0
    )
        throws -> Data
    {
        let micros = try CaptureTimestampEncoding.microseconds(time.addingTimeInterval(shift))
        var body = Data(capacity: 20 + event.bytes.count)
        append32(interfaceID, to: &body)
        append32(UInt32(micros >> 32), to: &body)
        append32(UInt32(micros & UInt64(UInt32.max)), to: &body)
        append32(UInt32(event.reference.capturedLength), to: &body)
        append32(UInt32(max(event.reference.originalLength, event.reference.capturedLength)), to: &body)
        body.append(contentsOf: event.bytes)
        return block(type: 0x00000006, body: body)
    }

    /// An Enhanced Packet Block for bytes Tracexy built (Export PDUs), captured whole.
    static func enhancedPacket(bytes: [UInt8], interfaceID: UInt32, time: Date?) throws -> Data {
        let micros = try time.map(CaptureTimestampEncoding.microseconds) ?? 0
        var body = Data(capacity: 20 + bytes.count)
        append32(interfaceID, to: &body)
        append32(UInt32(micros >> 32), to: &body)
        append32(UInt32(micros & UInt64(UInt32.max)), to: &body)
        append32(UInt32(bytes.count), to: &body)
        append32(UInt32(bytes.count), to: &body)
        body.append(contentsOf: bytes)
        return block(type: 0x00000006, body: body)
    }

    static func interfaceDescription(linkType: UInt32, name: String?, fileName: String) -> Data {
        var body = Data()
        append16(UInt16(linkType), to: &body)
        append16(0, to: &body)
        append32(0, to: &body) // snap length 0: no limit
        if let name, !name.isEmpty {
            appendOption(code: 2, value: utf8Prefix(name, maxBytes: 1_024), to: &body)
        }
        appendOption(code: 3, value: utf8Prefix(fileName, maxBytes: 1_024), to: &body)
        append32(0, to: &body)
        return block(type: 0x00000001, body: body)
    }

    /// At most `maxBytes` of `text`'s UTF-8, never splitting a character.
    static func utf8Prefix(_ text: String, maxBytes: Int) -> [UInt8] {
        var kept: [UInt8] = []
        for character in text {
            let bytes = Array(String(character).utf8)
            guard kept.count + bytes.count <= maxBytes else {
                break
            }
            kept += bytes
        }
        return kept
    }

    // MARK: Private

    private static func appendOption(code: UInt16, value: [UInt8], to data: inout Data) {
        append16(code, to: &data)
        append16(UInt16(clamping: value.count), to: &data)
        data.append(contentsOf: value)
        while data.count % 4 != 0 {
            data.append(0)
        }
    }

    private static func block(type: UInt32, body: Data) -> Data {
        var padded = body
        while padded.count % 4 != 0 {
            padded.append(0)
        }
        let total = UInt32(12 + padded.count)
        var out = Data(capacity: Int(total))
        append32(type, to: &out)
        append32(total, to: &out)
        out.append(padded)
        append32(total, to: &out)
        return out
    }

    private static func append16(_ value: UInt16, to data: inout Data) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private static func append32(_ value: UInt32, to data: inout Data) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }

    private static func append64(_ value: UInt64, to data: inout Data) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }
}
