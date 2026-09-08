import Foundation

// MARK: - PcapngWriter

/// Writer for pcapng capture files. Each distinct link type receives its own
/// Interface Description Block, so exported sessions preserve per-frame link
/// metadata that classic pcap cannot represent.
///
/// A frame with no capture time is written as a Simple Packet Block, which is the
/// one packet block in the format that carries no timestamp field. An SPB always
/// refers to interface 0 and derives its captured length from that interface's snap
/// length, so preserving a frame's exact link type *and* its captured/original
/// lengths means the writer opens a fresh section whenever the required interface-0
/// shape changes. That is the whole reason sections appear in the output at all.
nonisolated enum PcapngWriter {
    // MARK: Internal

    static func data(defaultLinkType: UInt32, frames: [CapturedFrame]) throws -> Data {
        // Known-only output is byte-for-byte what it has always been: one section,
        // one IDB per distinct link type, then one EPB per frame.
        guard frames.contains(where: { $0.timestamp == nil }) else {
            return try timedOnlyData(defaultLinkType: defaultLinkType, frames: frames)
        }
        return try mixedTimingData(defaultLinkType: defaultLinkType, frames: frames)
    }

    static func write(defaultLinkType: UInt32, frames: [CapturedFrame], to url: URL) throws {
        try data(defaultLinkType: defaultLinkType, frames: frames).write(to: url, options: .atomic)
    }

    // MARK: Private

    /// One Interface Description Block's identity, as far as this writer cares.
    private struct Interface: Equatable {
        let linkType: UInt32
        /// `0` means "no snap length declared", which a reader treats as untruncated.
        let snapLength: UInt32
    }

    /// The interfaces declared so far in the section currently being written.
    /// Interface ids are declaration order, and interface 0 is fixed for the whole
    /// section because a Simple Packet Block can only refer to it.
    private struct SectionState {
        let interfaceZero: Interface
        private(set) var interfaces: [Interface]

        /// The id for `linkType` in this section, declaring a new IDB the first time
        /// it is needed. New interfaces use the writer's standard snap length; only
        /// interface 0 has to satisfy an SPB's derived-length rule.
        mutating func interfaceID(for linkType: UInt32, capturedLength: Int, appendingTo output: inout Data) -> UInt32 {
            if let index = interfaces
                .firstIndex(where: {
                    $0.linkType == linkType && ($0.snapLength == 0 || Int($0.snapLength) >= capturedLength)
                })
            {
                return UInt32(index)
            }
            let declared = Interface(linkType: linkType, snapLength: max(PcapWriter.snapLength, UInt32(capturedLength)))
            PcapngWriter.appendInterface(declared, to: &output)
            interfaces.append(declared)
            return UInt32(interfaces.count - 1)
        }
    }

    private static func timedOnlyData(defaultLinkType: UInt32, frames: [CapturedFrame]) throws -> Data {
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
            try appendEnhancedPacket(frame, interfaceID: interfaceID, to: &output)
        }
        return output
    }

    /// Write frames in order, opening a new section whenever the next untimed frame
    /// needs a different interface-0 shape than the current section provides.
    ///
    /// A timed frame is always an EPB, which states its own captured/original
    /// lengths, so it simply uses (or declares) an interface for its link type in
    /// the current section. An untimed frame is an SPB, whose reader-visible
    /// captured length is `snapLength == 0 ? origLen : min(origLen, snapLength)`;
    /// the required interface-0 snap length is therefore derived exactly from the
    /// frame's own lengths and never guessed.
    private static func mixedTimingData(defaultLinkType: UInt32, frames: [CapturedFrame]) throws -> Data {
        var output = Data()
        var section: SectionState?

        for frame in frames {
            let linkType = frame.linkType ?? defaultLinkType
            guard linkType <= UInt32(UInt16.max) else {
                throw SessionExportError.unsupportedLinkType
            }

            if frame.timestamp == nil {
                let required = try simplePacketInterface(for: frame, linkType: linkType)
                if section?.interfaceZero != required {
                    section = beginSection(interfaceZero: required, to: &output)
                }
                appendSimplePacket(frame, to: &output)
                continue
            }

            if section == nil {
                section = beginSection(
                    interfaceZero: Interface(linkType: linkType, snapLength: PcapWriter.snapLength),
                    to: &output
                )
            }
            guard var current = section else {
                continue
            }
            let interfaceID = current.interfaceID(
                for: linkType,
                capturedLength: frame.bytes.count,
                appendingTo: &output
            )
            section = current
            try appendEnhancedPacket(frame, interfaceID: interfaceID, to: &output)
        }

        if section == nil {
            // Unreachable for a real call (this path runs only when some frame was
            // untimed, so at least one section was opened), but a pcapng file still
            // needs a section and an interface to be readable at all.
            _ = beginSection(
                interfaceZero: Interface(linkType: defaultLinkType, snapLength: PcapWriter.snapLength),
                to: &output
            )
        }
        return output
    }

    /// The interface-0 shape an untimed frame requires so a reader recovers its
    /// exact captured and original lengths.
    ///
    /// A frame captured in full needs `snapLength == 0` (no truncation); a truncated
    /// frame needs `snapLength` equal to its captured length. A frame that captured
    /// zero bytes of a non-empty wire frame is unrepresentable as an SPB — no snap
    /// length yields `captured == 0 < original` — so it is rejected rather than
    /// silently rewritten or given a fabricated timestamp.
    private static func simplePacketInterface(
        for frame: CapturedFrame,
        linkType: UInt32
    )
        throws -> Interface
    {
        let captured = frame.bytes.count
        let original = max(frame.originalLength, captured)
        if captured == original {
            return Interface(linkType: linkType, snapLength: 0)
        }
        guard captured > 0 else {
            throw SessionExportError.untimedFrameNotRepresentable
        }
        return Interface(linkType: linkType, snapLength: UInt32(captured))
    }

    private static func beginSection(interfaceZero: Interface, to output: inout Data) -> SectionState {
        appendBlock(type: 0x0A0D0D0A, to: &output) { body in
            append32(0x1A2B3C4D, to: &body)
            append16(1, to: &body)
            append16(0, to: &body)
            append64(UInt64.max, to: &body)
        }
        appendInterface(interfaceZero, to: &output)
        return SectionState(interfaceZero: interfaceZero, interfaces: [interfaceZero])
    }

    private static func appendInterface(_ interface: Interface, to output: inout Data) {
        appendBlock(type: 0x00000001, to: &output) { body in
            append16(UInt16(interface.linkType), to: &body)
            append16(0, to: &body)
            append32(interface.snapLength, to: &body)
        }
    }

    private static func appendEnhancedPacket(
        _ frame: CapturedFrame,
        interfaceID: UInt32,
        to output: inout Data
    )
        throws
    {
        guard let timestamp = frame.timestamp else {
            throw SessionExportError.untimedFramesRequirePcapng
        }
        let microseconds = try CaptureTimestampEncoding.microseconds(timestamp)
        appendBlock(type: 0x00000006, to: &output) { body in
            append32(interfaceID, to: &body)
            append32(UInt32(microseconds >> 32), to: &body)
            append32(UInt32(microseconds & UInt64(UInt32.max)), to: &body)
            append32(UInt32(frame.bytes.count), to: &body)
            append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &body)
            body.append(contentsOf: frame.bytes)
        }
    }

    private static func appendSimplePacket(_ frame: CapturedFrame, to output: inout Data) {
        appendBlock(type: 0x00000003, to: &output) { body in
            append32(UInt32(max(frame.originalLength, frame.bytes.count)), to: &body)
            body.append(contentsOf: frame.bytes)
        }
    }

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
