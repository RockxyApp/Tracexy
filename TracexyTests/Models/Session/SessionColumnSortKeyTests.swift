import Foundation
import Testing
@testable import Tracexy

/// The optional Sessions columns sort by typed facts, and a missing fact sorts after
/// every present one in ascending order instead of reading as zero.
struct SessionColumnSortKeyTests {
    // MARK: Internal

    @Test
    func missingFactsSortLast() {
        let named = session(sni: "a.example", duration: 2, latency: 12)
        let unnamed = session(sni: nil, duration: nil, latency: nil)
        let blank = session(sni: "", duration: 0, latency: 0)
        let ascending = [unnamed, named, blank]
        #expect(ascending.sorted(using: KeyPathComparator(\.sortableServerName)).first?.sni == "a.example")
        #expect(ascending.sorted(using: KeyPathComparator(\.sortableDuration)).map(\.duration) == [0, 2, nil])
        #expect(ascending.sorted(using: KeyPathComparator(\.sortableLatency)).map(\.latencyMilliseconds) == [
            0,
            12,
            nil
        ])
        // An empty server name is treated as absent, like a missing one.
        #expect(blank.sortableServerName == unnamed.sortableServerName)
    }

    // MARK: Private

    private func session(sni: String?, duration: TimeInterval?, latency: Double?) -> SessionSummary {
        SessionSummary(
            id: UUID(),
            startTime: nil,
            duration: duration,
            processName: nil,
            host: "h",
            sourceEndpoint: "192.0.2.1:1",
            destinationEndpoint: "192.0.2.2:2",
            sourceEndpointValue: nil,
            destinationEndpointValue: nil,
            protocolStack: [.tcp],
            status: .ok,
            latencyMilliseconds: latency,
            bytesUp: 0,
            bytesDown: 0,
            sni: sni,
            dnsQuery: nil,
            dnsAnswers: []
        )
    }
}
