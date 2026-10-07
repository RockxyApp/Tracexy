import Foundation

// MARK: - FrameAddressNames

/// View ▸ Name Resolution ▸ Resolve Network Addresses for the frame lists: the name
/// to show for an address — one given in this Project, else the first name the
/// capture's own DNS or mDNS answers carried, else its named subnet's form — or the
/// address itself. Only names the Project or the capture already hold are used;
/// nothing is ever looked up on the network.
@MainActor
enum FrameAddressNames {
    static func resolver(sessions: [SessionSummary], book: AddressNameBook) -> (String) -> String {
        var learned: [String: String] = [:]
        for row in ResolvedAddresses.rows(sessions: sessions, namedAddresses: [:])
            where learned[row.address] == nil
        {
            learned[row.address] = row.name
        }
        return { address in
            book.name(for: address) ?? learned[address] ?? book.displayName(for: address) ?? address
        }
    }
}
