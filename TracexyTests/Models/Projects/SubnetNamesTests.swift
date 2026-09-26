import Foundation
import Testing
@testable import Tracexy

/// Subnet names, as Wireshark's `subnets` file shows them (`office.5`), kept per
/// Project beside address names, and Endpoints' grouping by named subnet.
@MainActor
struct SubnetNamesTests {
    // MARK: Internal

    /// Wireshark prints the host bits the mask leaves and skips the octets it fully
    /// covers (`subnet_name_lookup` in `addr_resolv.c`).
    @Test(arguments: [
        ("192.168.1.0/24", "192.168.1.5", "office.5"),
        ("192.168.16.0/20", "192.168.17.5", "office.1.5"),
        ("10.0.0.0/8", "10.20.30.40", "office.20.30.40"),
        ("10.1.0.0/16", "10.1.2.3", "office.2.3"),
        ("192.168.1.7/32", "192.168.1.7", "office"),
        ("192.168.1.128/25", "192.168.1.200", "office.72"),
        // tshark -N n with a `subnets` file names these exactly so (2026-09-24).
        ("192.0.2.0/24", "192.0.2.10", "office.10"),
        ("203.0.113.0/20", "203.0.113.53", "office.1.53"),
    ])
    func labelsLikeWireshark(block: String, address: String, expected: String) throws {
        let subnet = try SubnetName(block: #require(SubnetNames.block(block)), name: "office")
        #expect(SubnetNames.label(address, in: subnet) == expected)
    }

    @Test
    func blocksAreIPv4AndNormalized() throws {
        #expect(try SubnetNames.text(of: #require(SubnetNames.block(" 192.168.1.77/24 "))) == "192.168.1.0/24")
        #expect(SubnetNames.block("2001:db8::/32") == nil)
        #expect(SubnetNames.block("0.0.0.0/0") == nil)
        #expect(SubnetNames.block("192.168.1.0") == nil)
    }

    @Test
    func theMostSpecificBlockWinsAndAnAddressNameWinsOverBoth() throws {
        let suite = "subnet-names-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        let book = AddressNameBook()
        book.bind(to: defaults)
        #expect(book.setSubnetName("lab", for: "10.0.0.0/8"))
        #expect(book.setSubnetName("rack", for: "10.1.2.0/24"))
        #expect(!book.setSubnetName("v6", for: "2001:db8::/32"))
        #expect(book.displayName(for: "10.1.2.3") == "rack.3")
        #expect(book.displayName(for: "10.9.9.9") == "lab.9.9.9")
        #expect(book.displayName(for: "192.0.2.1") == nil)
        book.setName("nas", for: "10.1.2.3")
        #expect(book.displayName(for: "10.1.2.3") == "nas")

        let reloaded = AddressNameBook()
        reloaded.bind(to: defaults)
        #expect(reloaded.subnetNames == ["10.0.0.0/8": "lab", "10.1.2.0/24": "rack"])
        reloaded.setSubnetName("", for: "10.1.2.0/24")
        #expect(reloaded.displayName(for: "10.1.2.4") == "lab.1.2.4")
    }

    /// Grouping adds each side's traffic to its subnet's row; a session inside the
    /// subnet counts once; unnamed addresses keep their own rows.
    @Test
    func endpointsGroupByNamedSubnet() throws {
        let office = try SubnetName(block: #require(SubnetNames.block("192.168.1.0/24")), name: "office")
        let sessions = [
            session("a", client: "192.168.1.5", server: "203.0.113.9", up: (3, 300), down: (2, 2_000)),
            session("b", client: "192.168.1.6", server: "203.0.113.9", up: (1, 100), down: (1, 500)),
            session("c", client: "192.168.1.5", server: "192.168.1.6", up: (4, 40), down: (4, 60)),
        ]
        let rows = TrafficStatistics.endpoints(of: sessions, kind: .ipv4, subnets: [office])
        let subnet = try #require(rows.first { $0.isSubnet })
        #expect(subnet.address == "192.168.1.0/24")
        #expect(subnet.sessionCount == 3)
        #expect(subnet.txPackets == 3 + 1 + 4 + 4)
        #expect(subnet.rxBytes == 2_000 + 500 + 60 + 40)
        #expect(subnet.term == "ip in 192.168.1.0/24")
        #expect(throws: Never.self) { _ = try SessionQueryParser().parse(subnet.term) }
        let outside = try #require(rows.first { $0.address == "203.0.113.9" })
        #expect(outside.sessionCount == 2)
        // TCP rows carry ports, so they are never grouped.
        #expect(!TrafficStatistics.endpoints(of: sessions, kind: .tcp, subnets: [office]).contains { $0.isSubnet })
    }

    @Test
    func resolvedAddressesListNamedSubnets() {
        let rows = ResolvedAddresses.rows(
            sessions: [], namedAddresses: ["192.168.1.9": "printer"], namedSubnets: ["192.168.1.0/24": "office"]
        )
        #expect(rows.map(\.address) == ["192.168.1.0/24", "192.168.1.9"])
        #expect(rows.first?.source == .namedSubnet)
        #expect(rows.first.map(ResolvedAddresses.term) == "ip in 192.168.1.0/24")
    }

    // MARK: Private

    private func session(
        _ seed: String,
        client: String,
        server: String,
        up: (Int, Int),
        down: (Int, Int)
    )
        -> SessionSummary
    {
        let source = IPEndpoint(ip: client, port: 50_000)
        let destination = IPEndpoint(ip: server, port: 443)
        return SessionSummary(
            id: SessionBuilder.stableID("subnet-\(seed)"),
            startTime: nil,
            duration: nil,
            processName: nil,
            host: server,
            sourceEndpoint: source.display,
            destinationEndpoint: destination.display,
            sourceEndpointValue: source,
            destinationEndpointValue: destination,
            protocolStack: [.tcp],
            status: .ok,
            latencyMilliseconds: nil,
            bytesUp: up.1,
            bytesDown: down.1,
            packetsUp: up.0,
            packetsDown: down.0
        )
    }
}
