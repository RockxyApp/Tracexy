import Foundation

// MARK: - SubnetName

/// A name the investigator gave an IPv4 block in this Project, as Wireshark's
/// `subnets` file: `192.168.1.0/24 office` shows `192.168.1.5` as `office.5`.
nonisolated struct SubnetName: Hashable, Sendable {
    let block: CIDRValue
    let name: String

    /// The block as typed back: network address and prefix, `192.168.1.0/24`.
    var text: String {
        SubnetNames.text(of: block)
    }
}

// MARK: - SubnetNames

nonisolated enum SubnetNames {
    // MARK: Internal

    /// An IPv4 block (`/1` to `/32`); `nil` for anything else. Host bits are cleared.
    static func block(_ text: String) -> CIDRValue? {
        guard let block = CIDRValue(parsing: text.trimmingCharacters(in: .whitespaces)),
              block.network.family == .v4, block.prefixLength >= 1 else
        {
            return nil
        }
        return block
    }

    static func text(of block: CIDRValue) -> String {
        "\(dotted(block.network.bytes))/\(block.prefixLength)"
    }

    /// The most specific named block holding `address`.
    static func lookup(_ address: String, in subnets: [SubnetName]) -> SubnetName? {
        guard let value = IPAddressValue(parsing: address), value.family == .v4 else {
            return nil
        }
        return subnets.filter { $0.block.contains(value) }.max { $0.block.prefixLength < $1.block.prefixLength }
    }

    /// Wireshark's form: the name, then the host part's octets that the mask does
    /// not fully cover (`office.5` for a /24, `office.1.5` for a /20, `office` for a /32).
    static func label(_ address: String, in subnet: SubnetName) -> String {
        guard let value = IPAddressValue(parsing: address), value.bytes.count == 4 else {
            return subnet.name
        }
        let prefix = subnet.block.prefixLength
        var host = value.bytes
        for index in host.indices {
            let covered = min(max(prefix - index * 8, 0), 8)
            host[index] &= covered == 8 ? 0 : UInt8(0xFF) >> covered
        }
        let kept = host.dropFirst(prefix / 8)
        return kept.isEmpty ? subnet.name : subnet.name + "." + dotted(Array(kept))
    }

    // MARK: Private

    private static func dotted(_ bytes: [UInt8]) -> String {
        bytes.map(String.init).joined(separator: ".")
    }
}
