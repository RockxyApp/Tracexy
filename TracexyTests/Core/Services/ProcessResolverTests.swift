import Foundation
import Testing
@testable import Tracexy

@Suite("ProcessResolver lsof parsing")
struct ProcessResolverTests {
    @Test
    func parsesPortToProcess() {
        let output = """
        p743
        cNordVPN
        n10.5.0.2:50467->18.208.91.13:8883
        n10.5.0.2:52879->172.64.155.218:443
        p1363
        cGoogle Chrome
        n10.5.0.2:50761->142.251.10.188:5228
        n*:5353
        """
        let map = ProcessResolver.parse(output)
        #expect(map[50_467] == ProcessResolver.ResolvedProcess(pid: 743, command: "NordVPN"))
        #expect(map[52_879]?.command == "NordVPN")
        #expect(map[50_761] == ProcessResolver.ResolvedProcess(pid: 1_363, command: "Google Chrome"))
        #expect(map[5_353]?.pid == 1_363) // listening socket "*:5353"
    }

    @Test
    func extractsPortHandlingIPv6() {
        #expect(ProcessResolver.port(from: "10.0.0.2:50467") == 50_467)
        #expect(ProcessResolver.port(from: "[fe80::1]:443") == 443)
        #expect(ProcessResolver.port(from: "*:5353") == 5_353)
        #expect(ProcessResolver.port(from: "no-port") == nil)
    }
}
