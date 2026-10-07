import Foundation
import Testing
@testable import Tracexy

/// File ▸ Export Objects ▸ TFTP rebuilds each transferred file as
/// `tshark --export-objects tftp` saves it: a read request answered from a new
/// server port with a negotiated 1,024-byte block size and one repeated block, a write
/// request at the default 512 bytes (which Wireshark 4.6 misses), and a read whose
/// second block is missing, which neither exports.
struct TFTPObjectsTests {
    // MARK: Internal

    @Test
    func rebuildsFilesAsWireshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        #expect(loaded.sessions.filter { $0.protocolStack.contains(.tftp) }.count == 3)
        let (streams, connections) = CaptureObjectScanner.inputs(.tftp, in: loaded.sessions, from: loaded.sessions)
        let objects = try CaptureObjectScanner.scan(
            .tftp, contentsOf: url, expectedIdentity: loaded.identity, streams: streams, connections: connections,
            sourceToken: SavedCaptureStreamLoader.sourceToken(for: loaded.identity)
        ).objects
        #expect(objects.map(\.fileName) == ["firmware.bin", "config.txt"])
        #expect(objects.map(\.body) == [Self.firmware, Self.config])
        #expect(objects.map(\.frameOrdinal) == [9, 15])
        #expect(objects.allSatisfy { $0.host.isEmpty && $0.contentType.isEmpty })

        let request = SessionBuilder.decodePacket(
            CapturedFrame(bytes: Self.frames[0], timestamp: nil, originalLength: 0), linkType: LinkType.ethernet
        )
        let tftp = try #require(request.layers.last)
        #expect(tftp.proto == .tftp)
        #expect(tftp.fields.map(\.name) == ["Opcode", "Source File", "Type", "Option"])
        #expect(tftp.fields.last?.value == "blksize: 1024")

        guard WiresharkOracle.isAvailable else {
            return
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("tftp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let process = Process()
        process.executableURL = WiresharkOracle.tsharkURL
        process.arguments = ["-r", url.path, "-q", "--export-objects", "tftp,\(folder.path)"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        var theirs: [String: [UInt8]] = [:]
        for name in try FileManager.default.contentsOfDirectory(atPath: folder.path) {
            theirs[name] = try [UInt8](Data(contentsOf: folder.appendingPathComponent(name)))
        }
        // Wireshark 4.6 dissects only the server's datagrams of a transfer (its comment
        // says both sides'), so it never rebuilds a write request's upload. Tracexy
        // does; every file tshark saves is the same here.
        let ours = Dictionary(uniqueKeysWithValues: objects.map { ($0.fileName, $0.body) })
        #expect(theirs == ours.filter { $0.key != "config.txt" })
        #expect(try WiresharkOracle.tsharkFields(url, fields: ["tftp.source_file"], filter: "tftp.opcode == 1")
            == [["boot/firmware.bin"], ["missing.bin"]])
    }

    // MARK: Private

    private static let firmware = [UInt8]((0 ..< 2_500).map { UInt8($0 % 251) })
    private static let config = Array(String(repeating: "option value\n", count: 60).utf8)
    private static let missing = [UInt8](repeating: 0x55, count: 1_100)

    private static let frames: [[UInt8]] = {
        let client = ("192.0.2.10", UInt16(50_069))
        let server = "198.51.100.69"
        func datagram(_ from: (String, UInt16), _ to: (String, UInt16), _ payload: [UInt8]) -> [UInt8] {
            PacketBuilder.ethernetIPv4(
                proto: 17, src: from.0, dst: to.0, payload: PacketBuilder.udp(
                    srcPort: from.1,
                    dstPort: to.1,
                    payload: payload
                )
            )
        }
        func strings(_ values: [String]) -> [UInt8] {
            values.flatMap { Array($0.utf8) + [0] }
        }
        func data(_ block: Int, _ bytes: ArraySlice<UInt8>) -> [UInt8] {
            [0, 3, UInt8(block >> 8), UInt8(block & 0xFF)] + bytes
        }
        func ack(_ block: Int) -> [UInt8] {
            [0, 4, UInt8(block >> 8), UInt8(block & 0xFF)]
        }
        let transfer = (server, UInt16(40_001))
        var list: [[UInt8]] = [
            // RRQ with blksize 1024, OACK from the transfer port, three blocks (one repeated).
            datagram(client, (server, 69), [0, 1] + strings(["boot/firmware.bin", "octet", "blksize", "1024"])),
            datagram(transfer, client, [0, 6] + strings(["blksize", "1024"])),
            datagram(client, transfer, ack(0)),
            datagram(transfer, client, data(1, firmware[0 ..< 1_024])),
            datagram(client, transfer, ack(1)),
            datagram(transfer, client, data(2, firmware[1_024 ..< 2_048])),
            datagram(transfer, client, data(2, firmware[1_024 ..< 2_048])),
            datagram(client, transfer, ack(2)),
            datagram(transfer, client, data(3, firmware[2_048...])),
            datagram(client, transfer, ack(3)),
        ]
        // WRQ at the default 512 bytes; the client sends the data.
        let writer = ("192.0.2.10", UInt16(50_070))
        let writeTransfer = (server, UInt16(40_002))
        list.append(datagram(writer, (server, 69), [0, 2] + strings(["config.txt", "netascii"])))
        list.append(datagram(writeTransfer, writer, ack(0)))
        list.append(datagram(writer, writeTransfer, data(1, config[0 ..< 512])))
        list.append(datagram(writeTransfer, writer, ack(1)))
        list.append(datagram(writer, writeTransfer, data(2, config[512...])))
        list.append(datagram(writeTransfer, writer, ack(2)))
        // A read whose second block never arrives.
        let reader = ("192.0.2.10", UInt16(50_071))
        let readTransfer = (server, UInt16(40_003))
        list.append(datagram(reader, (server, 69), [0, 1] + strings(["missing.bin", "octet"])))
        list.append(datagram(readTransfer, reader, data(1, missing[0 ..< 512])))
        list.append(datagram(readTransfer, reader, data(3, missing[1_024...])))
        return list
    }()

    private static func capture() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("tftp-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.enumerated().map {
            CapturedFrame(
                bytes: $0.element,
                timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double($0.offset)),
                originalLength: $0.element.count
            )
        }, to: url)
        return url
    }
}
