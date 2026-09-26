import Foundation
import Testing
@testable import Tracexy

/// The Timeline column places each session by its own capture time only.
struct SessionTimelineBarTests {
    // MARK: Internal

    @Test
    func spanAndFractionsComeFromKnownTimesOnly() throws {
        let base = Date(timeIntervalSince1970: 1_000)
        let first = session(start: base, duration: 2)
        let second = session(start: base.addingTimeInterval(6), duration: 4)
        let untimed = session(start: nil, duration: nil)
        let span = try #require(SessionTimelineBar.span(of: [first, untimed, second]))
        #expect(span == base ... base.addingTimeInterval(10))
        #expect(SessionTimelineBar.fraction(of: first, in: span) == 0 ... 0.2)
        #expect(SessionTimelineBar.fraction(of: second, in: span) == 0.6 ... 1)
        #expect(SessionTimelineBar.fraction(of: untimed, in: span) == nil)
        #expect(SessionTimelineBar.span(of: [untimed]) == nil)
        // A single instant fills the bar rather than dividing by zero.
        let instant = session(start: base, duration: 0)
        #expect(SessionTimelineBar.fraction(of: instant, in: base ... base) == 0 ... 1)
    }

    // MARK: Private

    private func session(start: Date?, duration: TimeInterval?) -> SessionSummary {
        SessionSummary(
            id: UUID(), startTime: start, duration: duration, processName: nil, host: "h",
            sourceEndpoint: "192.0.2.1:1", destinationEndpoint: "192.0.2.2:2",
            sourceEndpointValue: nil, destinationEndpointValue: nil, protocolStack: [.tcp], status: .ok,
            latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0, sni: nil, dnsQuery: nil, dnsAnswers: []
        )
    }
}
