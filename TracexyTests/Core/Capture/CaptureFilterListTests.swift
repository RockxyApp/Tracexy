import Darwin
import Foundation
import Testing
@testable import Tracexy

@Suite("Capture filter list migration")
struct CaptureFilterListTests {
    @Test("Loading a chosen regular file preserves its bytes and rejects a FIFO without blocking")
    func fileKinds() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("cfilters")
        let original = Data("\"TLS\" tcp port 443\n".utf8)
        try original.write(to: url)
        #expect(try CaptureFilterList.load(from: url).first?.expression == "tcp port 443")
        #expect(try Data(contentsOf: url) == original)
        #expect(throws: CaptureFilterList.Failure.notRegularFile) {
            try CaptureFilterList.load(from: directory)
        }
        let fifo = directory.appendingPathComponent("pipe")
        let result = fifo.withUnsafeFileSystemRepresentation { $0.map { Darwin.mkfifo($0, 0o600) } ?? -1 }
        try #require(result == 0)
        #expect(throws: CaptureFilterList.Failure.notRegularFile) {
            try CaptureFilterList.load(from: fifo)
        }
    }

    @Test("Named capture filters preserve expression bytes and source order")
    func ordinaryList() throws {
        let text = "\u{FEFF}# personal filters\r\n\"Web\" tcp port 443\r\n\r\n\"DNS\"\tudp port 53\r\n"
        let entries = try CaptureFilterList.parse(Data(text.utf8))
        #expect(entries.map(\.name) == ["Web", "DNS"])
        #expect(entries.map(\.expression) == ["tcp port 443", "udp port 53"])
        #expect(entries.map(\.line) == [2, 4])
    }

    @Test("Duplicate names remain separate choices and quoted names are decoded")
    func duplicateNames() throws {
        let text = #""Web" tcp"# + "\n" + #""Web" udp"# + "\n" + #""A \"quoted\" name" port 53"#
        let entries = try CaptureFilterList.parse(Data(text.utf8))
        #expect(entries.map(\.name) == ["Web", "Web", "A \"quoted\" name"])
        #expect(Set(entries.map(\.id)).count == 3)
    }

    @Test("An invalid row rejects the whole list with its line number")
    func malformedRow() {
        let text = "# heading\n\"Valid\" tcp\n\"Missing expression\"\n"
        #expect(throws: CaptureFilterList.Failure.invalidLine(3)) {
            try CaptureFilterList.parse(Data(text.utf8))
        }
    }

    @Test("Malformed names, separators and invalid text cannot become a filter", arguments: [
        "tcp", "\"\" tcp", "\"name\"tcp", "\"unclosed tcp", "\"bad\\q\" tcp", "\"name\" tcp\0udp",
    ])
    func malformed(_ text: String) {
        #expect(throws: (any Error).self) { try CaptureFilterList.parse(Data(text.utf8)) }
    }

    @Test("Bytes, names, expressions and entry counts have finite limits")
    func bounds() throws {
        #expect(throws: CaptureFilterList.Failure.tooLarge) {
            try CaptureFilterList.parse(Data(repeating: 32, count: CaptureFilterList.maximumBytes + 1))
        }
        #expect(throws: CaptureFilterList.Failure.invalidText) {
            try CaptureFilterList.parse(Data([0xFF]))
        }
        let oversizedName = "\"" + String(repeating: "n", count: 129) + "\" tcp"
        #expect(throws: CaptureFilterList.Failure.invalidLine(1)) {
            try CaptureFilterList.parse(Data(oversizedName.utf8))
        }
        let oversizedExpression = "\"name\" " + String(repeating: "x", count: 1_025)
        #expect(throws: CaptureFilterList.Failure.invalidLine(1)) {
            try CaptureFilterList.parse(Data(oversizedExpression.utf8))
        }
        let maximum = Array(repeating: "\"TCP\" tcp", count: 256).joined(separator: "\n")
        #expect(try CaptureFilterList.parse(Data(maximum.utf8)).count == 256)
        #expect(throws: CaptureFilterList.Failure.tooManyEntries) {
            try CaptureFilterList.parse(Data((maximum + "\n\"UDP\" udp").utf8))
        }
    }

    @Test("An empty or comment-only list is explicit")
    func empty() {
        #expect(throws: CaptureFilterList.Failure.empty) {
            try CaptureFilterList.parse(Data("# no filters\n\n".utf8))
        }
    }
}
