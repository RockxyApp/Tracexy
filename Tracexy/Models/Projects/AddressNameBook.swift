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

    nonisolated static let maximumEntries = 500
    nonisolated static let maximumNameCharacters = 60

    nonisolated static let maximumSubnets = 200

    private(set) var names: [String: String] = [:]
    private(set) var canEditNames = true
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
        if let data = defaults.data(forKey: ProjectScopedSettingsKeys.addressNames) {
            do {
                storedNames = try JSONDecoder().decode([String: String].self, from: data)
                canEditNames = true
            } catch {
                // Keep corrupt user data intact until it can be recovered; never
                // replace it with an empty dictionary during an unrelated save.
                storedNames = [:]
                canEditNames = false
            }
        } else {
            storedNames = [:]
            canEditNames = true
        }
        names = Self.canonicalProjection(storedNames)
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

    /// Distinct names stored for alternative spellings of one canonical IP.
    /// Callers can surface the conflict before an explicit save resolves it.
    func conflictingNames(for address: String) -> [String] {
        let key = Self.canonical(address)
        let values = Set(storedNames.compactMap { storedAddress, name in
            Self.canonical(storedAddress) == key ? name : nil
        })
        return values.count > 1 ? values.sorted() : []
    }

    /// Adds imported names only for addresses this Project does not already name.
    /// Existing and conflicting aliases are deliberately preserved for review.
    func importNames(_ imported: [String: String]) -> AddressNameImportResult {
        guard canEditNames else {
            return AddressNameImportResult(added: 0, alreadyNamed: imported.count, invalid: 0, full: false)
        }
        var added = 0
        var alreadyNamed = 0
        var invalid = 0
        let existingAddresses = Set(storedNames.keys.map(Self.canonical))
        var addresses = existingAddresses
        for address in imported.keys.sorted() {
            guard let value = IPAddressValue(parsing: address),
                  let name = imported[address]?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !name.isEmpty else
            {
                invalid += 1
                continue
            }
            let key = Self.canonical(value.compressedText)
            guard !addresses.contains(key) else {
                alreadyNamed += 1
                continue
            }
            guard addresses.count < Self.maximumEntries else {
                names = Self.canonicalProjection(storedNames)
                persist()
                return AddressNameImportResult(
                    added: added, alreadyNamed: alreadyNamed, invalid: invalid, full: true
                )
            }
            storedNames[key] = String(name.prefix(Self.maximumNameCharacters))
            addresses.insert(key)
            added += 1
        }
        names = Self.canonicalProjection(storedNames)
        if added > 0 {
            persist()
        }
        return AddressNameImportResult(added: added, alreadyNamed: alreadyNamed, invalid: invalid, full: false)
    }

    /// Set, replace or (blank) remove the name for `address`. Returns `false` for a
    /// string that is not an IP address, or when the book is full and the address new.
    @discardableResult
    func setName(_ name: String, for address: String) -> Bool {
        guard canEditNames, IPAddressValue(parsing: address) != nil else {
            return false
        }
        let key = Self.canonical(address)
        let trimmed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maximumNameCharacters))
        let matchingKeys = storedNames.keys.filter { Self.canonical($0) == key }
        if trimmed.isEmpty {
            for matchingKey in matchingKeys {
                storedNames.removeValue(forKey: matchingKey)
            }
        } else {
            let distinctAddresses = Set(storedNames.keys.map(Self.canonical))
            guard distinctAddresses.contains(key) || distinctAddresses.count < Self.maximumEntries else {
                return false
            }
            // Saving is an explicit conflict resolution for this IP. Other
            // addresses and their original key/value pairs remain untouched.
            for matchingKey in matchingKeys {
                storedNames.removeValue(forKey: matchingKey)
            }
            storedNames[key] = trimmed
        }
        names = Self.canonicalProjection(storedNames)
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
    @ObservationIgnored private var storedNames: [String: String] = [:]

    /// One spelling per address, so `2001:DB8::1` and `2001:db8::1` share a name.
    private static func canonical(_ address: String) -> String {
        IPAddressValue(parsing: address)?.compressedText.lowercased() ?? address.lowercased()
    }

    /// Build a stable display projection without rewriting the user's stored keys.
    /// A canonical spelling wins display; collisions remain intact until explicit edit.
    private static func canonicalProjection(_ storedNames: [String: String]) -> [String: String] {
        storedNames.keys.sorted { lhs, rhs in
            let lhsCanonical = canonical(lhs)
            let rhsCanonical = canonical(rhs)
            let lhsIsCanonical = lhs == lhsCanonical
            let rhsIsCanonical = rhs == rhsCanonical
            if lhsIsCanonical != rhsIsCanonical {
                return lhsIsCanonical
            }
            return lhs < rhs
        }.reduce(into: [:]) { result, key in
            let canonicalKey = canonical(key)
            if result[canonicalKey] == nil {
                result[canonicalKey] = storedNames[key]
            }
        }
    }

    private func persist() {
        guard canEditNames, let data = try? JSONEncoder().encode(storedNames) else {
            return
        }
        defaults?.set(data, forKey: ProjectScopedSettingsKeys.addressNames)
    }
}

// MARK: - AddressNameImportResult

struct AddressNameImportResult: Equatable {
    let added: Int
    let alreadyNamed: Int
    let invalid: Int
    let full: Bool
}
