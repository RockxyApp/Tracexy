import Testing
@testable import Tracexy

@Suite("Linux cooked capture headers")
struct LinuxCookedHeaderTests {
    // MARK: Internal

    @Test("SLL fields retain network order and only the stored address prefix")
    func sllFields() throws {
        let bytes: [UInt8] = [0, 4, 0, 1, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0x86, 0xDD]
        let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: .sll)
        #expect(header.packetType == 4)
        #expect(header.hardwareType == 1)
        #expect(header.declaredAddressLength == 12)
        #expect(header.addressPrefix == [1, 2, 3, 4, 5, 6, 7, 8])
        #expect(header.protocolNumber == 0x86DD)
        #expect(header.interfaceIndex == nil)
        #expect(header.reserved == nil)
    }

    @Test("SLL2 preserves capture interface and reserved facts without interpretation")
    func sll2Fields() throws {
        let bytes: [UInt8] = [8, 0, 0x12, 0x34, 1, 2, 3, 4, 0, 1, 4, 6, 1, 2, 3, 4, 5, 6, 0xAA, 0xBB]
        let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: .sll2)
        #expect(header.protocolNumber == 0x0800)
        #expect(header.reserved == 0x1234)
        #expect(header.interfaceIndex == 0x01020304)
        #expect(header.packetType == 4)
        #expect(header.hardwareType == 1)
        #expect(header.declaredAddressLength == 6)
        #expect(header.addressPrefix == [1, 2, 3, 4, 5, 6])
    }

    @Test("Every truncated fixed header fails without partial field fabrication")
    func truncatedHeaders() {
        for version in [LinuxCookedHeader.Version.sll, .sll2] {
            for count in 0 ..< version.headerLength {
                #expect(throws: PacketError.self) {
                    try LinuxCookedHeader.parse(PacketBuffer(Array(repeating: 0, count: count)), version: version)
                }
            }
        }
    }

    @Test("Address lengths are bounded by storage, including absent addresses", arguments: [0, 6, 8, 255])
    func addressLengths(length: Int) throws {
        for version in [LinuxCookedHeader.Version.sll, .sll2] {
            var bytes = Array(repeating: UInt8(0), count: version.headerLength)
            bytes[version == .sll ? 5 : 11] = UInt8(length)
            let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: version)
            #expect(header.declaredAddressLength == UInt16(length))
            #expect(header.addressPrefix.count == min(length, 8))
        }
    }

    @Test("An SLL address length beyond one byte is preserved and still bounded by storage")
    func sllAddressLengthAboveAByte() throws {
        var bytes = Array(repeating: UInt8(0), count: 16)
        // 256 in network order across the two-byte SLL length field.
        bytes[4] = 1
        bytes[5] = 0
        bytes.replaceSubrange(6 ..< 14, with: [1, 2, 3, 4, 5, 6, 7, 8] as [UInt8])
        let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: .sll)
        #expect(header.declaredAddressLength == 256)
        #expect(header.addressPrefix == [1, 2, 3, 4, 5, 6, 7, 8])
    }

    @Test(
        "Special hardware payloads cannot be assumed to be EtherType payloads in either version",
        arguments: [770, 803, 824]
    )
    func specialHardware(hardware: Int) throws {
        for version in [LinuxCookedHeader.Version.sll, .sll2] {
            let bytes = Self.header(version: version, hardware: UInt16(hardware), protocolNumber: 0x0800)
            let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: version)
            // The protocol field still reads as IPv4 — only the hardware type says
            // that number cannot be taken as an EtherType here.
            #expect(header.hardwareType == UInt16(hardware))
            #expect(header.protocolNumber == 0x0800)
            #expect(!header.usesEtherTypePayload)
        }
    }

    @Test("Hardware types outside the exclusion set keep their EtherType meaning", arguments: [1, 768, 772, 778])
    func ordinaryHardware(hardware: Int) throws {
        for version in [LinuxCookedHeader.Version.sll, .sll2] {
            let bytes = Self.header(version: version, hardware: UInt16(hardware), protocolNumber: 0x0800)
            let header = try LinuxCookedHeader.parse(PacketBuffer(bytes), version: version)
            #expect(header.usesEtherTypePayload)
        }
    }

    // MARK: Private

    /// A zero-filled fixed header of `version` carrying only a hardware type and a
    /// protocol value, each at that version's own offsets.
    private static func header(
        version: LinuxCookedHeader.Version, hardware: UInt16, protocolNumber: UInt16
    )
        -> [UInt8]
    {
        var bytes = Array(repeating: UInt8(0), count: version.headerLength)
        let hardwareOffset = version == .sll ? 2 : 8
        bytes[hardwareOffset] = UInt8(hardware >> 8)
        bytes[hardwareOffset + 1] = UInt8(hardware & 0xFF)
        let protocolOffset = version == .sll ? 14 : 0
        bytes[protocolOffset] = UInt8(protocolNumber >> 8)
        bytes[protocolOffset + 1] = UInt8(protocolNumber & 0xFF)
        return bytes
    }
}
