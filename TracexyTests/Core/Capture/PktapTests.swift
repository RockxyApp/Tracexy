import Foundation
import Testing
@testable import Tracexy

@Suite("pktap process attribution")
struct PktapTests {
    // MARK: Internal

    @Test
    func parsesProcessAndInnerFrame() {
        let inner = PacketBuilder.httpRequestFrame(
            host: "example.com", path: "/", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let packet = makePktapPacket(
            process: "Safari",
            pid: 501,
            epid: 777,
            interface: "en0",
            innerDLT: 1,
            frame: inner
        )

        let parsed = PktapHeader.parse(packet)
        #expect(parsed?.process == "Safari")
        #expect(parsed?.pid == 501)
        #expect(parsed?.effectivePID == 777)
        #expect(parsed?.interface == "en0")
        #expect(parsed?.innerDLT == 1)
        #expect(parsed?.frame == inner)
    }

    @Test
    func rejectsTruncatedHeader() {
        #expect(PktapHeader.parse([0x10, 0x00]) == nil)
    }

    @Test
    func derivesAppNameFromExecutablePath() {
        #expect(PktapHeader.appName(
            fromExecutablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ) == "Google Chrome")
        #expect(PktapHeader.appName(
            fromExecutablePath: "/System/Applications/Mail.app/Contents/MacOS/Mail"
        ) == "Mail")
        // Non-bundled daemon → executable file name.
        #expect(PktapHeader.appName(fromExecutablePath: "/usr/libexec/nsurlsessiond") == "nsurlsessiond")
    }

    @Test
    func processNamePropagatesToSession() {
        let frameBytes = PacketBuilder.tlsClientHelloFrame(
            sni: "secure.example.com", src: "192.168.1.10", dst: "93.184.216.34"
        )
        let frame = CapturedFrame(
            bytes: frameBytes, timestamp: Date(), originalLength: frameBytes.count, processName: "Google Chrome"
        )
        let sessions = SessionBuilder.build(from: [frame], linkType: LinkType.ethernet)
        #expect(sessions.first?.processName == "Google Chrome")
    }

    // MARK: Private

    /// Builds a synthetic DLT_PKTAP packet: a header (process at offset 56,
    /// interface at 12, DLT at 8, length at 0) followed by the inner frame.
    private func makePktapPacket(
        process: String, pid: Int = 0, epid: Int = 0, interface: String, innerDLT: UInt32, frame: [UInt8]
    )
        -> [UInt8]
    {
        let headerLength = 108 // a realistic pktap header size (≥ 88, so epid fits)
        var header = [UInt8](repeating: 0, count: headerLength)
        writeU32LE(&header, at: 0, headerLength)
        writeU32LE(&header, at: 8, Int(innerDLT))
        writeCString(&header, at: 12, interface, max: 24)
        writeU32LE(&header, at: 52, pid)
        writeCString(&header, at: 56, process, max: 17)
        writeU32LE(&header, at: 84, epid)
        return header + frame
    }

    private func writeU32LE(_ bytes: inout [UInt8], at offset: Int, _ value: Int) {
        let v = UInt32(value)
        bytes[offset] = UInt8(v & 0xFF)
        bytes[offset + 1] = UInt8((v >> 8) & 0xFF)
        bytes[offset + 2] = UInt8((v >> 16) & 0xFF)
        bytes[offset + 3] = UInt8((v >> 24) & 0xFF)
    }

    private func writeCString(_ bytes: inout [UInt8], at offset: Int, _ string: String, max: Int) {
        for (index, byte) in Array(string.utf8).prefix(max - 1).enumerated() {
            bytes[offset + index] = byte
        }
    }
}
