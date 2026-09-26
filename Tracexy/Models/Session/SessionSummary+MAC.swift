import Foundation

// MARK: - Session MAC addresses

nonisolated extension SessionSummary {
    /// The client's and server's Ethernet addresses, lower-case, read from the
    /// session's representative frame and turned to the client → server direction
    /// by its IP source. `nil` for a session without an Ethernet header.
    var macAddresses: (client: String, server: String)? {
        guard let ethernet = decodedLayers.first(where: { $0.proto == .ethernet }),
              let source = ethernet.fields.first(where: { $0.name == "Source" })?.value.lowercased(),
              let destination = ethernet.fields.first(where: { $0.name == "Destination" })?.value.lowercased() else
        {
            return nil
        }
        let ipSource = decodedLayers.first { $0.proto == .ipv4 || $0.proto == .ipv6 }?
            .fields.first { $0.name == "Source" }?.value
        let fromServer = ipSource != nil && ipSource == destinationEndpointValue?.ip
        return fromServer ? (destination, source) : (source, destination)
    }

    /// `aa:bb:cc:dd:ee:ff` from a MAC written with `:` or `-` separators in either
    /// case, or `nil` when it is not six hex octets.
    static func normalizedMAC(_ text: String) -> String? {
        let octets = text.lowercased().split(whereSeparator: { $0 == ":" || $0 == "-" })
        guard octets.count == 6,
              octets.allSatisfy({ $0.count == 2 && $0.allSatisfy(\.isHexDigit) }) else
        {
            return nil
        }
        return octets.joined(separator: ":")
    }
}
