import Foundation
import Testing
@testable import Tracexy

/// View ▸ Name Resolution ▸ Resolve Network Addresses shows, in frame lists, the
/// name the Project gave an address, else the name the capture's own DNS answer
/// carried (tshark `-N dn`: network names from captured DNS data), else its named subnet's form.
@MainActor
struct FrameAddressNamesTests {
    @Test
    func namesComeFromTheProjectThenTheCaptureThenSubnets() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("names-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let answer: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3] + Array("web".utf8) + [7]
            + Array("example".utf8) + [4] + Array("test".utf8) + [
                0,
                0,
                1,
                0,
                1,
                0xC0,
                0x0C,
                0,
                1,
                0,
                1,
                0,
                0,
                0,
                60,
                0,
                4,
                198,
                51,
                100,
                7
            ]
        let frames = [
            PacketBuilder.ethernetIPv4(
                proto: 17, src: "192.0.2.53", dst: "192.0.2.10",
                payload: PacketBuilder.udp(srcPort: 53, dstPort: 53_000, payload: answer)
            ),
            PacketBuilder.ethernetIPv4(
                proto: 6, src: "192.0.2.10", dst: "198.51.100.7",
                payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x02, payload: [], sequence: 1)
            ),
        ]
        try Data(ReplayCorpus.classicPcapBytes(frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        })).write(to: url)
        let sessions = try SavedCaptureStreamLoader(contentsOf: url).load().sessions
        let fileMapping = CaptureNameResolutionRecord(
            address: "198.51.100.7", name: CaptureBoundedText(text: "from-file.example.test")
        )

        let suite = "frame-names-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let book = AddressNameBook()
        book.bind(to: defaults)
        book.setSubnetName("lab", for: "192.0.2.0/24")

        var name = FrameAddressNames.resolver(sessions: sessions, book: book, captureFileRecords: [fileMapping])
        #expect(name("198.51.100.7") == "web.example.test")
        #expect(name("192.0.2.10") == "lab.10")
        #expect(name("203.0.113.1") == "203.0.113.1")
        book.setName("frontend", for: "198.51.100.7")
        name = FrameAddressNames.resolver(sessions: sessions, book: book, captureFileRecords: [fileMapping])
        #expect(name("198.51.100.7") == "frontend")

        guard WiresharkOracle.isAvailable else {
            return
        }
        #expect(try WiresharkOracle.tsharkFields(
            url, fields: ["ip.dst_host"], filter: "tcp", extraArguments: ["-N", "dn"]
        ) == [["web.example.test"]])
    }

    @Test
    func projectAndObservedDnsNamesPrecedePcapngFileMappings() throws {
        let suite = "frame-names-nrb-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let book = AddressNameBook()
        book.bind(to: defaults)
        let mapping = CaptureNameResolutionRecord(
            address: "192.0.2.10", name: CaptureBoundedText(text: "file.example.test")
        )
        var name = FrameAddressNames.resolver(sessions: [], book: book, captureFileRecords: [mapping])
        #expect(name("192.0.2.10") == "file.example.test")
        book.setName("project-name", for: "192.0.2.10")
        name = FrameAddressNames.resolver(sessions: [], book: book, captureFileRecords: [mapping])
        #expect(name("192.0.2.10") == "project-name")
    }

    @Test
    func theChoiceIsKeptPerProjectAndOffByDefault() throws {
        let suite = "frame-names-option-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let options = PacketDetailOptions()
        options.bind(to: defaults)
        #expect(!options.resolvesNetworkAddresses)
        options.resolvesNetworkAddresses = true
        let reloaded = PacketDetailOptions()
        reloaded.bind(to: defaults)
        #expect(reloaded.resolvesNetworkAddresses)
    }
}
