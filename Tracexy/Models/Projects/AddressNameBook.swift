import Foundation
import Observation

// MARK: - AddressNameBook

/// Names the investigator gave to addresses in this Project ("192.0.2.5 is the NAS").
/// A name is shown where a session's host is only that bare address; it never replaces
/// a name the capture itself supplied (DNS, SNI, HTTP Host), and it is never sent
/// anywhere. Written through to the Project's own preference suite.
@MainActor
@Observable
final class AddressNameBook {
    // MARK: Internal

    static let maximumEntries = 500
    static let maximumNameCharacters = 60

    static let maximumSubnets = 200

    private(set) var names: [String: String] = [:]
    /// ``subnetNames`` as validated blocks.
    private(set) var subnets: [SubnetName] = []

    /// Named IPv4 blocks, keyed by their text (`192.168.1.0/24`).
    private(set) var subnetNames: [String: String] = [:] {
        didSet {
            subnets = subnetNames.compactMap { text, name in
                SubnetNames.block(text).map { SubnetName(block: $0, name: name) }
            }
        }
    }

    func bind(to defaults: UserDefaults) {
        self.defaults = defaults
        let data = defaults.data(forKey: ProjectScopedSettingsKeys.addressNames) ?? Data()
        names = (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
        let subnetData = defaults.data(forKey: ProjectScopedSettingsKeys.subnetNames) ?? Data()
        subnetNames = (try? JSONDecoder().decode([String: String].self, from: subnetData)) ?? [:]
    }

    /// The name to show for `address`: the one given to the address itself, else its
    /// most specific named subnet's form (`office.5`).
    func displayName(for address: String) -> String? {
        name(for: address) ?? SubnetNames.lookup(address, in: subnets).map { SubnetNames.label(address, in: $0) }
    }

    /// Set, replace or (blank) remove the name of an IPv4 block. Returns `false` for
    /// text that is not an IPv4 block, or when the list is full and the block new.
    @discardableResult
    func setSubnetName(_ name: String, for blockText: String) -> Bool {
        guard let block = SubnetNames.block(blockText) else {
            return false
        }
        let key = SubnetNames.text(of: block)
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maximumNameCharacters))
        if trimmed.isEmpty {
            subnetNames.removeValue(forKey: key)
        } else {
            guard subnetNames[key] != nil || subnetNames.count < Self.maximumSubnets else {
                return false
            }
            subnetNames[key] = trimmed
        }
        if let data = try? JSONEncoder().encode(subnetNames) {
            defaults?.set(data, forKey: ProjectScopedSettingsKeys.subnetNames)
        }
        return true
    }

    func name(for address: String) -> String? {
        names[Self.canonical(address)]
    }

    /// Set, replace or (blank) remove the name for `address`. Returns `false` for a
    /// string that is not an IP address, or when the book is full and the address new.
    @discardableResult
    func setName(_ name: String, for address: String) -> Bool {
        guard IPAddressValue(parsing: address) != nil else {
            return false
        }
        let key = Self.canonical(address)
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maximumNameCharacters))
        if trimmed.isEmpty {
            names.removeValue(forKey: key)
        } else {
            guard names[key] != nil || names.count < Self.maximumEntries else {
                return false
            }
            names[key] = trimmed
        }
        persist()
        return true
    }

    /// The host a session list should show: the investigator's name for a bare
    /// address host, or the host as the capture named it.
    func displayHost(for session: SessionSummary) -> String {
        guard IPAddressValue(parsing: session.host) != nil, let name = displayName(for: session.host) else {
            return session.host
        }
        return "\(name) (\(session.host))"
    }

    // MARK: Private

    @ObservationIgnored private var defaults: UserDefaults?

    /// One spelling per address, so `2001:DB8::1` and `2001:db8::1` share a name.
    private static func canonical(_ address: String) -> String {
        address.lowercased()
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(names) else {
            return
        }
        defaults?.set(data, forKey: ProjectScopedSettingsKeys.addressNames)
    }
}
