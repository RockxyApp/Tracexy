import Foundation
import Testing
@testable import Tracexy

/// The capture-filter check runs the real libpcap compiler on a dead handle: no
/// interface, no privilege. It must agree with what a capture start would accept.
struct CaptureFilterValidatorTests {
    @Test
    func blankMeansEveryPacket() {
        #expect(CaptureFilterValidator.validate("") == .empty)
        #expect(CaptureFilterValidator.validate("  \n ") == .empty)
    }

    @Test
    func libpcapAcceptsAndSizesAValidFilter() {
        guard case let .valid(count) = CaptureFilterValidator.validate("tcp port 443 or udp port 53") else {
            Issue.record("expected a valid filter")
            return
        }
        #expect(count > 0)
        // A filter matching nothing extra still compiles to a real program.
        guard case .valid = CaptureFilterValidator.validate("host 192.0.2.1 and not port 22") else {
            Issue.record("expected a valid filter")
            return
        }
    }

    @Test
    func libpcapReasonIsReturnedForAnInvalidFilter() {
        guard case let .invalid(message) = CaptureFilterValidator.validate("tcp prot 443") else {
            Issue.record("expected an invalid filter")
            return
        }
        #expect(!message.isEmpty)
        guard case .invalid = CaptureFilterValidator.validate("port 99999") else {
            Issue.record("expected an out-of-range port to be refused")
            return
        }
    }

    @Test
    func anOversizedExpressionIsRefusedBeforeCompiling() {
        let long = String(repeating: "tcp or ", count: 700) + "udp"
        guard case .invalid = CaptureFilterValidator.validate(long) else {
            Issue.record("expected the size bound to refuse it")
            return
        }
    }

    @Test
    func savedFiltersReplaceByNameAndStayBounded() throws {
        var filters: [SavedCaptureFilter] = []
        filters = try #require(SavedCaptureFilter.saving("tcp port 443", named: "Web", into: filters))
        filters = try #require(SavedCaptureFilter.saving("tcp port 8443", named: "web", into: filters))
        #expect(filters.count == 1)
        #expect(filters[0].expression == "tcp port 8443")
        #expect(SavedCaptureFilter.saving(" ", named: "Blank", into: filters) == nil)
        #expect(SavedCaptureFilter.saving("udp", named: "  ", into: filters) == nil)
        for index in 1 ..< SavedCaptureFilter.maximumCount {
            filters = try #require(SavedCaptureFilter.saving("port \(index)", named: "F\(index)", into: filters))
        }
        #expect(SavedCaptureFilter.saving("udp", named: "One more", into: filters) == nil)
        #expect(SavedCaptureFilter.decode(SavedCaptureFilter.encode(filters)) == filters)
        #expect(SavedCaptureFilter.decode(Data("not json".utf8)).isEmpty)
    }
}
