import Foundation

extension PacketDecoder {
    /// RFC 7323 caps the effective window scale at 14 while preserving the raw
    /// observed byte separately.
    private static let tcpMaxWindowScale: UInt8 = 14

    /// Parses the TCP option list (offset 20 → `end`) into decoded fields. Our
    /// own walk of the kind/length/value TLV format (RFC 793/7323), referencing
    /// the option-parsing approach in PcapPlusPlus/libtins.
    static func tcpOptions(
        _ buf: PacketBuffer, end: Int
    )
        throws -> (fields: [DecodedField], facts: TCPOptionFacts)
    {
        var fields: [DecodedField] = []
        var facts = TCPOptionFacts()
        var offset = 20
        var guardCounter = 0
        while offset < end, guardCounter < 40 {
            guardCounter += 1
            let kind = try buf.u8(offset)
            if kind == 0 { // End of Option List
                break
            }
            if kind == 1 { // No-Operation (single byte, no length)
                offset += 1
                continue
            }
            guard offset + 1 < end else {
                break
            }
            let length = try Int(buf.u8(offset + 1))
            guard length >= 2, offset + length <= end else {
                break
            }
            if kind == 5 {
                fields += try tcpSACKOptionFields(buf, at: offset, length: length, facts: &facts)
            } else {
                fields.append(tcpOptionField(kind: kind, buf: buf, at: offset, length: length, facts: &facts))
            }
            offset += length
        }
        return (fields, facts)
    }

    private static func tcpOptionField(
        kind: UInt8, buf: PacketBuffer, at offset: Int, length: Int, facts: inout TCPOptionFacts
    )
        -> DecodedField
    {
        let range = (buf.start + offset) ..< (buf.start + offset + length)
        switch kind {
        case 2 where length == 4:
            let mss = (try? buf.u16(offset + 2)) ?? 0
            facts.maximumSegmentSize = mss
            return DecodedField(name: "Option: MSS", value: "\(mss)", byteRange: range)
        case 3 where length == 3:
            let shift = (try? buf.u8(offset + 2)) ?? 0
            facts.windowScaleRaw = shift
            // RFC 7323 section 2.3 requires an observed value above 14 to be
            // treated as 14. Preserve both raw and effective values and never
            // shift by the invalid raw byte.
            if shift <= tcpMaxWindowScale {
                facts.windowScale = shift
                return DecodedField(name: "Option: Window Scale", value: "\(shift) (×\(1 << shift))", byteRange: range)
            }
            facts.windowScale = tcpMaxWindowScale
            return DecodedField(
                name: "Option: Window Scale", value: "\(shift) (effective 14)", byteRange: range
            )
        case 4 where length == 2:
            facts.sackPermitted = true
            return DecodedField(name: "Option: SACK Permitted", value: "yes", byteRange: range)
        case 8 where length == 10:
            let tsval = (try? buf.u32(offset + 2)) ?? 0
            let tsecr = (try? buf.u32(offset + 6)) ?? 0
            facts.timestamps = TCPTimestamps(value: tsval, echoReply: tsecr)
            return DecodedField(name: "Option: Timestamps", value: "tsval=\(tsval) tsecr=\(tsecr)", byteRange: range)
        default:
            return DecodedField(name: "Option: kind \(kind)", value: "\(length) bytes", byteRange: range)
        }
    }

    /// RFC 2018 block edges remain raw observations. Sequence wrap, D-SACK, and
    /// repeated ranges prohibit sorting or validating them with ordinary `<`.
    private static func tcpSACKOptionFields(
        _ buf: PacketBuffer, at offset: Int, length: Int, facts: inout TCPOptionFacts
    )
        throws -> [DecodedField]
    {
        let range = (buf.start + offset) ..< (buf.start + offset + length)
        guard length >= 10, (length - 2).isMultiple(of: 8) else {
            return [DecodedField(name: "Option: SACK", value: "Malformed block length", byteRange: range)]
        }
        let count = (length - 2) / 8
        guard count <= TCPOptionFacts.maximumSACKBlockCount - facts.sackBlocks.count else {
            return [DecodedField(name: "Option: SACK", value: "Exceeds TCP option space", byteRange: range)]
        }
        var fields = [DecodedField(
            name: "Option: SACK", value: "\(count) \(count == 1 ? "block" : "blocks")", byteRange: range
        )]
        var blocks: [TCPSACKBlock] = []
        for index in 0 ..< count {
            let edgeOffset = offset + 2 + index * 8
            let leftEdge = try buf.u32(edgeOffset)
            let rightEdge = try buf.u32(edgeOffset + 4)
            let blockNumber = facts.sackBlocks.count + index + 1
            blocks.append(TCPSACKBlock(leftEdge: leftEdge, rightEdge: rightEdge))
            fields.append(ranged("SACK Block \(blockNumber) Left Edge", "\(leftEdge)", in: buf, at: edgeOffset, 4))
            fields.append(ranged(
                "SACK Block \(blockNumber) Right Edge",
                "\(rightEdge)",
                in: buf,
                at: edgeOffset + 4,
                4
            ))
        }
        facts.sackBlocks += blocks
        return fields
    }
}
