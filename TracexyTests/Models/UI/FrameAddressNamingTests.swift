import Testing
@testable import Tracexy

struct FrameAddressNamingTests {
    @Test
    func returnsDistinctCanonicalIPAddressesAndRejectsOtherEndpoints() {
        #expect(FrameAddressNaming.addresses(
            source: "2001:0db8:0000:0000:0000:0000:0000:0001",
            destination: "2001:db8::1"
        ) == ["2001:db8::1"])

        #expect(FrameAddressNaming.addresses(source: "00:11:22:33:44:55", destination: "server.example").isEmpty)
    }
}
