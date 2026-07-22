import Foundation
import Testing
@testable import Tracexy

@Suite("LiveCapture binding")
struct LiveCaptureTests {
    @Test
    func libpcapLoadsAndSymbolsResolve() throws {
        // Throws only if libpcap is missing or a pcap_* symbol can't be found.
        _ = try LiveCapture()
    }
}
