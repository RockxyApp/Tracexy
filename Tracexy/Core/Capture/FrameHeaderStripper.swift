import Foundation

// MARK: - FrameHeaderStrip

/// Wireshark's Strip Headers: the encapsulation each exported frame is cut down to.
nonisolated enum FrameHeaderStrip: String, CaseIterable, Identifiable, Sendable {
    /// From the innermost IPv4 or IPv6 header, written as raw IP (`LINKTYPE_RAW`).
    case innerIP
    /// From the Ethernet header a VXLAN or GRE tunnel carries, written as Ethernet.
    case innerEthernet

    // MARK: Internal

    var id: String {
        rawValue
    }
}

// MARK: - FrameHeaderStripper

/// Cuts a frame down to its inner packet, at the byte offset the shared decoder
/// read the inner header from. A frame without the requested inner layer is not
/// stripped (`nil`), so the export leaves it out and counts it.
nonisolated enum FrameHeaderStripper {
    static func strip(_ event: CaptureFrameEvent, to target: FrameHeaderStrip) -> CaptureFrameEvent? {
        let packet = PacketDecoder.decode(
            PacketBuffer(event.bytes), linkType: event.reference.linkType, timestamp: nil,
            originalLength: event.reference.originalLength
        )
        let start: Int?
        let linkType: UInt32
        switch target {
        case .innerIP:
            start = packet.layers.last { $0.proto == .ipv4 || $0.proto == .ipv6 }?.byteRange?.lowerBound
            linkType = LinkType.raw
        case .innerEthernet:
            let tunnel = packet.layers.lastIndex { $0.proto == .gre || $0.proto == .vxlan }
            start = tunnel.flatMap { index in
                packet.layers[(index + 1)...].first { $0.proto == .ethernet }?.byteRange?.lowerBound
            }
            linkType = LinkType.ethernet
        }
        guard let start, start < event.bytes.count else {
            return nil
        }
        if start == 0, event.reference.linkType == linkType {
            return event
        }
        let reference = CaptureFrameReference(
            payloadOffset: event.reference.payloadOffset + UInt64(start),
            capturedLength: event.reference.capturedLength - start,
            originalLength: max(event.reference.originalLength - start, event.reference.capturedLength - start),
            timestamp: event.reference.timestamp,
            linkType: linkType,
            sectionIndex: event.reference.sectionIndex,
            interfaceID: event.reference.interfaceID,
            hasComment: event.reference.hasComment,
            copyableOptionsRange: event.reference.copyableOptionsRange
        )
        return CaptureFrameEvent(reference: reference, bytes: Array(event.bytes[start...]), progress: event.progress)
    }
}
