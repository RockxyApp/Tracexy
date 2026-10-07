import Foundation
import Testing
@testable import Tracexy

/// Tools ▸ Firewall Rules writes rule text for the selected session in each
/// firewall's own syntax. Every pf rule is checked by `pfctl -n` (parse only).
struct FirewallRulesTests {
    // MARK: Internal

    @Test
    func rulesUseEachFirewallsSyntax() {
        let request = Self.request(.pf, .conversation)
        #expect(FirewallRules.rule(request) == "block in quick proto tcp from 192.0.2.10 to 198.51.100.80 port 80")
        #expect(FirewallRules.rule(Self.request(.iptables, .conversation))
            == "iptables -A INPUT -p tcp -s 192.0.2.10 -d 198.51.100.80 --dport 80 -j DROP")
        #expect(FirewallRules.rule(Self.request(.nftables, .destinationPort))
            == "nft add rule inet filter input tcp dport 80 drop")
        #expect(FirewallRules.rule(Self.request(.ipfw, .sourceAddress))
            == "ipfw add deny ip from 192.0.2.10 to any in")
        #expect(FirewallRules.rule(Self.request(.ciscoACL, .conversation))
            == "access-list 101 deny tcp host 192.0.2.10 host 198.51.100.80 eq 80\n! apply: ip access-group 101 in")
        #expect(FirewallRules.rule(Self.request(.windows, .conversation))
            == "netsh advfirewall firewall add rule name=\"Tracexy rule\" dir=in action=block protocol=TCP "
            + "remoteip=192.0.2.10 localip=198.51.100.80 localport=80")

        var outbound = Self.request(.windows, .conversation)
        outbound.inbound = false
        outbound.deny = false
        #expect(FirewallRules.rule(outbound)
            == "netsh advfirewall firewall add rule name=\"Tracexy rule\" dir=out action=allow protocol=TCP "
            + "localip=192.0.2.10 remoteip=198.51.100.80 remoteport=80")

        let v6 = Self.request(.iptables, .destinationAddress, source: "2001:db8::1", destination: "2001:db8::2")
        #expect(FirewallRules.rule(v6) == "ip6tables -A INPUT -d 2001:db8::2 -j DROP")

        // A port scope needs a TCP or UDP port.
        #expect(FirewallRules.rule(Self.request(.pf, .destinationPort, transport: nil)) == nil)
        #expect(FirewallRules.rule(Self.request(.pf, .sourceAddress, transport: nil)) != nil)
    }

    @Test
    func everyPFRuleParses() throws {
        let pfctl = URL(fileURLWithPath: "/sbin/pfctl")
        guard FileManager.default.isExecutableFile(atPath: pfctl.path) else {
            return
        }
        var rules: [String] = []
        for scope in FirewallRuleScope.allCases {
            for (source, destination) in [("192.0.2.10", "198.51.100.80"), ("2001:db8::1", "2001:db8::2")] {
                for deny in [true, false] {
                    for inbound in [true, false] {
                        var request = Self.request(.pf, scope, source: source, destination: destination)
                        request.deny = deny
                        request.inbound = inbound
                        if let rule = FirewallRules.rule(request) {
                            rules.append(rule)
                        }
                    }
                }
            }
        }
        #expect(rules.count == 32)
        let process = Process()
        process.executableURL = pfctl
        process.arguments = ["-nf", "-"]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output
        try process.run()
        input.fileHandleForWriting.write(Data((rules.joined(separator: "\n") + "\n").utf8))
        try input.fileHandleForWriting.close()
        let text = String(bytes: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "\(text)")
    }

    // MARK: Private

    private static func request(
        _ product: FirewallProduct,
        _ scope: FirewallRuleScope,
        source: String = "192.0.2.10",
        destination: String = "198.51.100.80",
        transport: String? = "tcp"
    )
        -> FirewallRules.Request
    {
        FirewallRules.Request(
            product: product, scope: scope, source: IPEndpoint(ip: source, port: 51_000),
            destination: IPEndpoint(ip: destination, port: 80), transport: transport
        )
    }
}
