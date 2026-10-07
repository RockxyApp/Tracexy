import Foundation

// MARK: - PacketDecoder local-network services

/// DHCP and NTP: the two services behind "why did this Mac get that address?" and
/// "why is its clock wrong?". Both are read from exact offsets with every access
/// bounds-checked; a short or malformed message keeps whatever was read before the
/// failure and claims nothing more. Only header facts and well-known options are
/// named; everything else is left unnamed rather than guessed.
extension PacketDecoder {
    // MARK: Internal

    /// BOOTP/DHCP (RFC 2131/2132) on UDP 67/68. A message without the DHCP magic
    /// cookie is plain BOOTP and is labelled so.
    static func dhcp(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let operation = try buf.u8(0)
        let transactionID = try buf.u32(4)
        var fields: [DecodedField] = [
            ranged(
                "Operation",
                operation == 1 ? "Request" : operation == 2 ? "Reply" : "\(operation)",
                in: buf,
                at: 0,
                1
            ),
            ranged("Transaction ID", String(format: "0x%08X", transactionID), in: buf, at: 4, 4),
        ]
        let client = try ipv4Address(buf, 12)
        let your = try ipv4Address(buf, 16)
        let server = try ipv4Address(buf, 20)
        let relay = try ipv4Address(buf, 24)
        for (name, value, offset) in [
            ("Client address", client, 12), ("Your address", your, 16),
            ("Next server", server, 20), ("Relay agent", relay, 24),
        ] where value != "0.0.0.0" {
            fields.append(ranged(name, value, in: buf, at: offset, 4))
        }
        let hardwareLength = try min(Int(buf.u8(2)), 16)
        if hardwareLength == 6 {
            let mac = try buf.bytes(28, 6).map { String(format: "%02x", $0) }.joined(separator: ":")
            fields.append(ranged("Client hardware address", mac, in: buf, at: 28, 6))
        }

        packet.appProtocol = .dhcp
        guard (try? buf.u32(236)) == 0x63825363 else {
            packet.layers.append(DecodedLayer(
                proto: .dhcp, title: "Bootstrap Protocol", summary: "BOOTP", fields: fields,
                byteRange: span(buf, buf.length)
            ))
            return
        }
        let options = dhcpOptions(buf, from: 240)
        fields += options.fields
        let kind = options.messageType.map(dhcpMessageName) ?? "DHCP"
        var summary = kind
        if your != "0.0.0.0" {
            summary += " \(your)"
        } else if let requested = options.requestedAddress {
            summary += " \(requested)"
        }
        packet.layers.append(DecodedLayer(
            proto: .dhcp, title: "Dynamic Host Configuration Protocol", summary: summary, fields: fields,
            byteRange: span(buf, buf.length)
        ))
    }

    /// NTP (RFC 5905) on UDP 123: the 48-byte header only. Extension fields and
    /// authenticators are not read.
    static func ntp(_ buf: PacketBuffer, into packet: inout DecodedPacket) throws {
        let first = try buf.u8(0)
        let leap = first >> 6
        let version = (first >> 3) & 0x07
        let mode = first & 0x07
        let stratum = try buf.u8(1)
        let poll = try Int8(bitPattern: buf.u8(2))
        let precision = try Int8(bitPattern: buf.u8(3))
        packet.appProtocol = .ntp
        var fields: [DecodedField] = [
            ranged("Leap indicator", leapName(leap), in: buf, at: 0, 1),
            ranged("Version", "\(version)", in: buf, at: 0, 1),
            ranged("Mode", ntpModeName(mode), in: buf, at: 0, 1),
            ranged("Stratum", stratumName(stratum), in: buf, at: 1, 1),
            ranged("Poll interval", "2^\(poll) s", in: buf, at: 2, 1),
            ranged("Precision", "2^\(precision) s", in: buf, at: 3, 1),
        ]
        if let reference = try? buf.bytes(12, 4) {
            let value = stratum <= 1
                ? String(bytes: reference.prefix { $0 != 0 }, encoding: .ascii) ?? ""
                : reference.map(String.init).joined(separator: ".")
            if !value.isEmpty {
                fields.append(ranged("Reference ID", value, in: buf, at: 12, 4))
            }
        }
        if let seconds = try? buf.u32(40), seconds != 0 {
            // NTP era 0 counts from 1900; 2,208,988,800 s separate it from 1970.
            let date = Date(timeIntervalSince1970: TimeInterval(seconds) - 2_208_988_800)
            fields.append(ranged(
                "Transmit time", date.formatted(Date.ISO8601FormatStyle()), in: buf, at: 40, 8
            ))
        }
        var summary = "NTP v\(version) \(ntpModeName(mode).lowercased())"
        if mode == 4 || mode == 5 {
            summary += ", stratum \(stratum)"
        }
        packet.layers.append(DecodedLayer(
            proto: .ntp, title: "Network Time Protocol", summary: summary, fields: fields,
            byteRange: span(buf, min(buf.length, 48))
        ))
    }

    /// An NTP header is at least 48 bytes with a version 1–4 and a defined mode.
    static func isNTP(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 48, let first = try? buf.u8(0) else {
            return false
        }
        let version = (first >> 3) & 0x07
        let mode = first & 0x07
        return (1 ... 4).contains(version) && mode != 0
    }

    /// A BOOTP header is 236 bytes with a request/reply operation and Ethernet-sized
    /// hardware fields.
    static func isDHCP(_ buf: PacketBuffer) -> Bool {
        guard buf.length >= 236, let operation = try? buf.u8(0), let hardwareType = try? buf.u8(1) else {
            return false
        }
        return (operation == 1 || operation == 2) && hardwareType == 1
    }

    // MARK: Private

    private struct DHCPOptions {
        var fields: [DecodedField] = []
        var messageType: UInt8?
        var requestedAddress: String?
    }

    /// The bounded option walk: stops at End (255), at a truncated option, or after
    /// 64 options; Pad (0) is skipped.
    private static func dhcpOptions(_ buf: PacketBuffer, from start: Int) -> DHCPOptions {
        var result = DHCPOptions()
        var offset = start
        var seen = 0
        while offset < buf.length, seen < 64 {
            guard let code = try? buf.u8(offset) else {
                break
            }
            if code == 0 {
                offset += 1
                continue
            }
            if code == 255 {
                break
            }
            guard let length = try? Int(buf.u8(offset + 1)),
                  let value = try? buf.bytes(offset + 2, length) else
            {
                break
            }
            seen += 1
            if let (name, rendered) = dhcpOption(code, value) {
                result.fields.append(ranged(name, rendered, in: buf, at: offset, length + 2))
            }
            if code == 53, length == 1 {
                result.messageType = value[0]
            }
            if code == 50, length == 4 {
                result.requestedAddress = value.map(String.init).joined(separator: ".")
            }
            offset += length + 2
        }
        return result
    }

    private static func dhcpOption(_ code: UInt8, _ value: [UInt8]) -> (String, String)? {
        func addresses() -> String? {
            guard !value.isEmpty, value.count.isMultiple(of: 4) else {
                return nil
            }
            return stride(from: 0, to: value.count, by: 4)
                .map { value[$0 ..< $0 + 4].map(String.init).joined(separator: ".") }
                .joined(separator: ", ")
        }
        func seconds() -> String? {
            guard value.count == 4 else {
                return nil
            }
            let total = value.reduce(0) { UInt32($0) << 8 | UInt32($1) }
            return total == 0xFFFFFFFF ? "infinite" : "\(total) s"
        }
        func text() -> String? {
            String(bytes: value.prefix { $0 != 0 }, encoding: .utf8)
        }
        switch code {
        case 53: return value.count == 1 ? ("Message type", dhcpMessageName(value[0])) : nil
        case 50: return addresses().map { ("Requested address", $0) }
        case 54: return addresses().map { ("Server identifier", $0) }
        case 51: return seconds().map { ("Lease time", $0) }
        case 1: return addresses().map { ("Subnet mask", $0) }
        case 3: return addresses().map { ("Router", $0) }
        case 6: return addresses().map { ("DNS servers", $0) }
        case 12: return text().map { ("Host name", $0) }
        case 15: return text().map { ("Domain name", $0) }
        case 60: return text().map { ("Vendor class", $0) }
        case 61: return ("Client identifier", value.map { String(format: "%02x", $0) }.joined(separator: ":"))
        default: return nil
        }
    }

    private static func dhcpMessageName(_ type: UInt8) -> String {
        switch type {
        case 1: "DHCP Discover"
        case 2: "DHCP Offer"
        case 3: "DHCP Request"
        case 4: "DHCP Decline"
        case 5: "DHCP ACK"
        case 6: "DHCP NAK"
        case 7: "DHCP Release"
        case 8: "DHCP Inform"
        default: "DHCP type \(type)"
        }
    }

    private static func ntpModeName(_ mode: UInt8) -> String {
        switch mode {
        case 1: "Symmetric active"
        case 2: "Symmetric passive"
        case 3: "Client"
        case 4: "Server"
        case 5: "Broadcast"
        case 6: "Control"
        case 7: "Private"
        default: "Reserved"
        }
    }

    private static func leapName(_ leap: UInt8) -> String {
        switch leap {
        case 0: "No warning"
        case 1: "Last minute has 61 seconds"
        case 2: "Last minute has 59 seconds"
        default: "Clock not synchronized"
        }
    }

    private static func stratumName(_ stratum: UInt8) -> String {
        switch stratum {
        case 0: "0 (unspecified)"
        case 1: "1 (primary reference)"
        case 16: "16 (unsynchronized)"
        default: "\(stratum)"
        }
    }
}
