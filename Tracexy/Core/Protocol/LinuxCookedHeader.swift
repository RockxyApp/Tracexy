import Foundation

/// Linux's synthetic capture header. Its address belongs to the capture source;
/// it is not an Ethernet source/destination pair or an interface on this Mac.
nonisolated struct LinuxCookedHeader: Sendable, Equatable {
    enum Version: Sendable, Equatable {
        case sll
        case sll2

        // MARK: Internal

        var headerLength: Int {
            self == .sll ? 16 : 20
        }
    }

    let version: Version
    let packetType: UInt16
    let hardwareType: UInt16
    let declaredAddressLength: UInt16
    /// At most eight bytes exist in the header, even for a longer declared address.
    let addressPrefix: [UInt8]
    let protocolNumber: UInt16
    let interfaceIndex: UInt32?
    let reserved: UInt16?

    /// These hardware types assign different meanings to the protocol/payload.
    /// Preserve their header facts without passing their bytes to an IP decoder.
    var usesEtherTypePayload: Bool {
        ![UInt16(770), 803, 824].contains(hardwareType)
    }

    static func parse(_ buffer: PacketBuffer, version: Version) throws -> Self {
        // Validate the complete fixed header before publishing any of its fields.
        _ = try buffer.subset(from: 0, count: version.headerLength)
        switch version {
        case .sll:
            let addressLength = try buffer.u16(4)
            return try Self(
                version: version,
                packetType: buffer.u16(0),
                hardwareType: buffer.u16(2),
                declaredAddressLength: addressLength,
                addressPrefix: buffer.bytes(6, min(Int(addressLength), 8)),
                protocolNumber: buffer.u16(14),
                interfaceIndex: nil,
                reserved: nil
            )
        case .sll2:
            let addressLength = try UInt16(buffer.u8(11))
            return try Self(
                version: version,
                packetType: UInt16(buffer.u8(10)),
                hardwareType: buffer.u16(8),
                declaredAddressLength: addressLength,
                addressPrefix: buffer.bytes(12, min(Int(addressLength), 8)),
                protocolNumber: buffer.u16(0),
                interfaceIndex: buffer.u32(4),
                reserved: buffer.u16(2)
            )
        }
    }
}
