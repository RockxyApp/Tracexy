import Foundation
import Testing
@testable import Tracexy

// MARK: - CaptureFileSetTests

struct CaptureFileSetTests {
    @Test
    func recognisesRotationNamesAndOrdersBySequence() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracexy-set-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let names = [
            "en0_00003_20260919120300.pcapng",
            "en0_00001_20260919120100.pcapng",
            "en0_00002_20260919120200.pcapng",
            "other_00001_20260919120100.pcapng",
            "en0_00001_20260919120100.pcap",
            "notes.txt",
        ]
        for name in names {
            try Data([0]).write(to: directory.appendingPathComponent(name))
        }
        let second = directory.appendingPathComponent("en0_00002_20260919120200.pcapng")
        let set = try #require(CaptureFileSet(member: second))
        #expect(set.count == 3)
        #expect(set.prefix == "en0")
        #expect(set.currentIndex == 1)
        #expect(set.next?.url.lastPathComponent == "en0_00003_20260919120300.pcapng")
        #expect(set.previous?.url.lastPathComponent == "en0_00001_20260919120100.pcapng")
        guard let nextURL = set.next?.url else {
            Issue.record("expected a next member")
            return
        }
        let last = CaptureFileSet(member: nextURL)
        #expect(last?.next == nil)
        #expect(last?.previous?.url == second)
        #expect(CaptureFileSet(member: directory.appendingPathComponent("notes.txt")) == nil)
        #expect(!CaptureFileSet.isMemberName(URL(fileURLWithPath: "/tmp/capture.pcapng")))
        #expect(CaptureFileSet.isMemberName(URL(fileURLWithPath: "/tmp/my_trace_00010_20260101000000.pcap")))
    }
}
