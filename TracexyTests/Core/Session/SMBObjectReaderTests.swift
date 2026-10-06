import Foundation
import Testing
@testable import Tracexy

// MARK: - SMBObjectReaderTests

/// SMB Export Objects is conservative: only a clear, paired, bounded transfer with
/// a trustworthy EOF and contiguous byte coverage can become a saveable object.
struct SMBObjectReaderTests {
    @Test
    func exportsACompleteWriteWithEveryProtocolFrameCited() throws {
        let fixture = SMBFixture()
        fixture.create("report.txt")
        fixture.write(offset: 0, bytes: Array("verified SMB bytes".utf8))
        fixture.close(eof: UInt64("verified SMB bytes".utf8.count))

        let result = try fixture.scan()
        #expect(result.objects.count == 1)
        let object = try #require(result.objects.first)
        #expect(object.fileName == "report.txt")
        #expect(object.contentType == "SMB file")
        #expect(object.body == Array("verified SMB bytes".utf8))
        #expect(object.frameOrdinal == object.contributingFrames.first?.ordinal.rawValue)
        #expect(object.contributingFrames.count == 6)
        #expect(Set(object.contributingFrames.map(\.ordinal.rawValue)).count == 6)
    }

    @Test
    func exportsContiguousBytesAcrossConfirmedShortWrites() throws {
        let fixture = SMBFixture()
        fixture.create("short-write.txt")
        fixture.write(offset: 0, bytes: [1, 2, 3], confirmedCount: 2)
        fixture.write(offset: 2, bytes: [3])
        fixture.close(eof: 3)

        #expect(try fixture.scan().objects.map(\.body) == [[1, 2, 3]])
    }

    @Test
    func keepsMultipleFilesScopedByTreeAndFileID() throws {
        let fixture = SMBFixture()
        let firstFileID = Array(0x20 ... 0x2F).map(UInt8.init)
        let secondFileID = Array(0x30 ... 0x3F).map(UInt8.init)
        fixture.create("one.txt", fileID: firstFileID, treeID: 0x200)
        fixture.create("two.txt", fileID: secondFileID, treeID: 0x201)
        fixture.write(offset: 0, bytes: [1], fileID: firstFileID, treeID: 0x200)
        fixture.write(offset: 0, bytes: [2], fileID: secondFileID, treeID: 0x201)
        fixture.close(eof: 1, fileID: firstFileID, treeID: 0x200)
        fixture.close(eof: 1, fileID: secondFileID, treeID: 0x201)

        let objects = try fixture.scan().objects
        #expect(objects.map(\.fileName) == ["one.txt", "two.txt"])
        #expect(objects.map(\.body) == [[1], [2]])
    }

    @Test
    func exportsAReadOnlyFileOnlyAfterObservedEOF() throws {
        let fixture = SMBFixture()
        fixture.create("read.txt")
        fixture.read(offset: 0, returned: Array("read ".utf8))
        fixture.read(offset: 5, returned: Array("data".utf8))
        fixture.readEOF(offset: 9)
        fixture.close(eof: nil)

        let result = try fixture.scan()
        #expect(result.objects.map(\.body) == [Array("read data".utf8)])
    }

    @Test(arguments: [true, false])
    func acceptsAnEndOfFileErrorWithOrWithoutErrorData(_ errorData: Bool) throws {
        let fixture = SMBFixture()
        fixture.create("read.txt")
        fixture.read(offset: 0, returned: Array("data".utf8))
        fixture.readEOF(offset: 4, errorData: errorData)
        fixture.close(eof: nil)
        #expect(try fixture.scan().objects.map(\.body) == [Array("data".utf8)])
    }

    /// Finder and Windows open the share root (an empty name) before a file, and
    /// most opens carry create contexts. Neither keeps the file from exporting.
    @Test
    func exportsPastTheShareRootOpenAndCreateContexts() throws {
        let fixture = SMBFixture()
        let rootID = Array(0x40 ... 0x4F).map(UInt8.init)
        fixture.create("", fileID: rootID)
        fixture.create("doc.txt", contexts: true)
        fixture.write(offset: 0, bytes: [7, 8])
        fixture.close(eof: 2)
        fixture.close(eof: nil, fileID: rootID)

        let objects = try fixture.scan().objects
        #expect(objects.map(\.fileName) == ["doc.txt"])
        #expect(objects.map(\.body) == [[7, 8]])
    }

    /// Complete files past the object bound are counted, and which ones are kept
    /// follows the order they appear in, not dictionary order.
    @Test
    func countsFilesPastTheObjectBoundInAppearanceOrder() throws {
        let fixture = SMBFixture()
        let ids = (0 ..< 3).map { index in Array(repeating: UInt8(0x50 + index), count: 16) }
        for (index, id) in ids.enumerated() {
            fixture.create("file\(index).txt", fileID: id)
            fixture.write(offset: 0, bytes: [UInt8(index)], fileID: id)
            fixture.close(eof: 1, fileID: id)
        }
        for _ in 0 ..< 3 {
            let bounded = try fixture.read(maxObjects: 2)
            #expect(bounded.objects.map(\.fileName) == ["file0.txt", "file1.txt"])
            #expect(bounded.omitted == 1)
        }
    }

    /// A server may hand out a FileId again after CLOSE: both files export, under
    /// distinct identities.
    @Test
    func keepsAClosedFileWhenItsFileIDIsReused() throws {
        let fixture = SMBFixture()
        fixture.create("first.txt")
        fixture.write(offset: 0, bytes: [1])
        fixture.close(eof: 1)
        fixture.create("second.txt")
        fixture.write(offset: 0, bytes: [2, 2])
        fixture.close(eof: 2)

        let objects = try fixture.scan().objects
        #expect(objects.map(\.fileName) == ["first.txt", "second.txt"])
        #expect(objects.map(\.body) == [[1], [2, 2]])
        #expect(Set(objects.map(\.id)).count == 2)
    }

    @Test
    func refusesMissingExtentAndSparseCoverage() throws {
        let noWitness = SMBFixture()
        noWitness.create("open.txt")
        noWitness.write(offset: 0, bytes: [1, 2, 3])
        noWitness.close(eof: nil)
        #expect(try noWitness.scan().objects.isEmpty)

        let sparse = SMBFixture()
        sparse.create("sparse.txt")
        sparse.write(offset: 2, bytes: [3, 4])
        sparse.close(eof: 4)
        #expect(try sparse.scan().objects.isEmpty)

        let missingReply = SMBFixture()
        missingReply.create("missing-reply.txt")
        missingReply.write(offset: 0, bytes: [1, 2], respond: false)
        missingReply.close(eof: 2)
        #expect(try missingReply.scan().objects.isEmpty)

        let failedWrite = SMBFixture()
        failedWrite.create("failed-write.txt")
        failedWrite.write(offset: 0, bytes: [1, 2], status: 0xC0000022)
        failedWrite.close(eof: 2)
        #expect(try failedWrite.scan().objects.isEmpty)
    }

    @Test
    func refusesConflictingOverlapCompoundAndUnsupportedTransform() throws {
        let overlap = SMBFixture()
        overlap.create("conflict.txt")
        overlap.write(offset: 0, bytes: [1, 2, 3])
        overlap.write(offset: 1, bytes: [9])
        overlap.close(eof: 3)
        #expect(try overlap.scan().objects.isEmpty)

        let compound = SMBFixture()
        compound.create("compound.txt", nextCommand: 8)
        #expect(try compound.scan().objects.isEmpty)

        // A file that would export, preceded by a transform header: only the
        // header check can empty the result.
        let transformed = SMBFixture()
        transformed.addClientPDU(
            transformed.header(signature: [0xFD, 0x53, 0x4D, 0x42], command: 8, response: false)
        )
        transformed.create("after-transform.txt")
        transformed.write(offset: 0, bytes: [1])
        transformed.close(eof: 1)
        #expect(try transformed.scan().objects.isEmpty)
    }

    @Test
    func refusesTraversalAndTupleIncarnationReuse() throws {
        let traversal = SMBFixture()
        traversal.create("folder/../secret.txt")
        #expect(try traversal.scan().objects.isEmpty)

        let reused = SMBFixture(reopenTuple: true)
        reused.create("reused.txt")
        reused.write(offset: 0, bytes: [1, 2])
        reused.close(eof: 2)
        #expect(try reused.scan().objects.isEmpty)
    }

    @Test
    func refusesNamedPipesAndWritesAfterClose() throws {
        let pipe = SMBFixture()
        pipe.create("\\PIPE\\service")
        pipe.write(offset: 0, bytes: [1, 2])
        pipe.close(eof: 2)
        #expect(try pipe.scan().objects.isEmpty)

        let postCloseWrite = SMBFixture()
        postCloseWrite.create("closed.txt")
        postCloseWrite.write(offset: 0, bytes: [1, 2])
        postCloseWrite.close(eof: 2)
        postCloseWrite.write(offset: 0, bytes: [3, 4])
        #expect(try postCloseWrite.scan().objects.isEmpty)
    }

    @Test
    func refusesMalformedReadRangesAndShortUncoveredWrite() throws {
        let badRead = SMBFixture()
        badRead.create("bad-read.txt")
        badRead.read(offset: 0, returned: [1, 2, 3], declaredLength: 2)
        badRead.close(eof: 3)
        #expect(try badRead.scan().objects.isEmpty)

        let shortWrite = SMBFixture()
        shortWrite.create("short.txt")
        shortWrite.write(offset: 0, bytes: [1, 2, 3], confirmedCount: 2)
        shortWrite.close(eof: 3)
        #expect(try shortWrite.scan().objects.isEmpty)
    }
}

// MARK: - SMBFixture

private final class SMBFixture {
    // MARK: Lifecycle

    init(reopenTuple: Bool = false) {
        addTCP(clientToServer: true, flags: 0x02, sequence: 1_000, payload: [])
        addTCP(clientToServer: false, flags: 0x12, sequence: 5_000, payload: [])
        addTCP(clientToServer: true, flags: 0x10, sequence: clientSequence, payload: [])
        if reopenTuple {
            addTCP(clientToServer: true, flags: 0x02, sequence: 1_000, payload: [])
        }
    }

    // MARK: Internal

    func create(
        _ name: String,
        nextCommand: UInt32 = 0,
        fileID: [UInt8]? = nil,
        treeID: UInt32? = nil,
        contexts: Bool = false
    ) {
        let selectedFileID = fileID ?? self.fileID
        let selectedTreeID = treeID ?? self.treeID
        let nameBytes = Array(name.utf16.flatMap { le16($0) })
        var request = header(
            command: 5, message: nextMessage(), response: false, nextCommand: nextCommand, tree: selectedTreeID
        )
        request.append(contentsOf: le16(57) + [0, 0])
        request += le32(0) + le32(0) + le32(0) + le32(0) + le32(0) + le32(0) + le32(0) + le32(1) + le32(0) + le32(0)
        // A create context (MxAc and QFid ride on most real opens) follows the
        // name on an 8-byte boundary.
        let context: [UInt8] = contexts ? Array(repeating: 0xC0, count: 24) : []
        let contextOffset = contexts ? 120 + (nameBytes.count + 7) / 8 * 8 : 0
        request += le16(120) + le16(UInt16(nameBytes.count))
        request += le32(UInt32(contextOffset)) + le32(UInt32(context.count)) + nameBytes
        if contexts {
            request += Array(repeating: 0, count: contextOffset - 120 - nameBytes.count) + context
        }
        let id = messageID - 1
        addClientPDU(request)

        var response = header(command: 5, message: id, response: true, tree: selectedTreeID)
        response += le16(89) + [0, 0] + le32(0) // structure, oplock, flags, action
        response += Array(repeating: 0, count: 40) // four times and allocation size
        response += le64(0) + le32(0) + le32(0) // EOF, attributes, reserved
        response += selectedFileID
        response += contexts ? le32(152) + le32(UInt32(context.count)) + context : le32(0) + le32(0)
        addServerPDU(response)
    }

    func write(
        offset: UInt64,
        bytes: [UInt8],
        confirmedCount: UInt32? = nil,
        status: UInt32 = 0,
        respond: Bool = true,
        fileID: [UInt8]? = nil,
        treeID: UInt32? = nil
    ) {
        let selectedFileID = fileID ?? self.fileID
        let selectedTreeID = treeID ?? self.treeID
        let id = nextMessage()
        var request = header(command: 9, message: id, response: false, tree: selectedTreeID)
        request += le16(49) + [112, 0] + le32(UInt32(bytes.count)) + le64(offset) + selectedFileID
        request += le32(0) + le32(0) + le16(0) + le16(0) + le32(0) + bytes
        addClientPDU(request)
        guard respond else {
            return
        }
        var response = header(command: 9, message: id, response: true, status: status, tree: selectedTreeID)
        response += le16(17) + le16(0) + le32(confirmedCount ?? UInt32(bytes.count)) + le32(0) + le16(0) + le16(0)
        addServerPDU(response)
    }

    func read(offset: UInt64, returned: [UInt8], declaredLength: UInt32? = nil) {
        let id = nextMessage()
        var request = header(command: 8, message: id, response: false)
        request += le16(49) + [0, 0] + le32(UInt32(returned.count)) + le64(offset) + fileID
        request += le32(0) + le32(0) + le32(0) + [0, 0, 0, 0]
        addClientPDU(request)
        var response = header(command: 8, message: id, response: true)
        response += le16(17) + [80, 0] + le32(declaredLength ?? UInt32(returned.count))
        response += le32(0) + le32(0) + returned
        addServerPDU(response)
    }

    /// An error response carries one byte of ErrorData (MS-SMB2 2.2.2); some
    /// servers send none.
    func readEOF(offset: UInt64, errorData: Bool = true) {
        let id = nextMessage()
        var request = header(command: 8, message: id, response: false)
        request += le16(49) + [0, 0] + le32(1) + le64(offset) + fileID
        request += le32(0) + le32(0) + le32(0) + [0, 0, 0, 0]
        addClientPDU(request)
        addServerPDU(
            header(command: 8, message: id, response: true, status: 0xC0000011)
                + le16(9) + [0, 0] + le32(0) + (errorData ? [0] : [])
        )
    }

    func close(eof: UInt64?, fileID: [UInt8]? = nil, treeID: UInt32? = nil) {
        let selectedFileID = fileID ?? self.fileID
        let selectedTreeID = treeID ?? self.treeID
        let id = nextMessage()
        var request = header(command: 6, message: id, response: false, tree: selectedTreeID)
        request += le16(24) + le16(1) + le32(0) + selectedFileID
        addClientPDU(request)
        var response = header(command: 6, message: id, response: true, tree: selectedTreeID)
        response += le16(60) + le16(eof == nil ? 0 : 1) + le32(0)
        response += Array(repeating: 0, count: 40)
        response += le64(eof ?? 0) + le32(0)
        addServerPDU(response)
    }

    func addClientPDU(_ pdu: [UInt8]) {
        addTCP(clientToServer: true, payload: nbss(pdu))
    }

    func scan() throws -> CaptureObjectList {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("smb-\(UUID().uuidString).pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let (streams, connections) = CaptureObjectScanner.inputs(.smb, in: loaded.sessions, from: loaded.sessions)
        #expect(streams.count == 1)
        return try CaptureObjectScanner.scan(
            .smb, contentsOf: url, expectedIdentity: loaded.identity, streams: streams,
            connections: connections, sourceToken: SavedCaptureStreamLoader.sourceToken(for: loaded.identity)
        )
    }

    /// The reader's own result for the one stream, under the given bounds.
    func read(maxObjects: Int) throws -> (objects: [CaptureObject], omitted: Int) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("smb-\(UUID().uuidString).pcap")
        let records = frames.enumerated().map {
            ReplayCorpus.Frame(bytes: $0.element, offsetSeconds: $0.offset, linkType: LinkType.ethernet)
        }
        try Data(ReplayCorpus.classicPcapBytes(records)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let loaded = try SavedCaptureStreamLoader(contentsOf: url).load()
        let (streams, _) = CaptureObjectScanner.inputs(.smb, in: loaded.sessions, from: loaded.sessions)
        let stream = try #require(streams.first)
        var result: (objects: [CaptureObject], omitted: Int) = ([], 0)
        try FollowStreamReader.readEach(
            contentsOf: url, expectedIdentity: loaded.identity, tuples: [stream.tuple],
            sourceToken: SavedCaptureStreamLoader.sourceToken(for: loaded.identity)
        ) { followed in
            result = SMBObjectReader.read(followed, sessionID: stream.sessionID, maxObjects: maxObjects)
        }
        return result
    }

    func header(
        signature: [UInt8] = [0xFE, 0x53, 0x4D, 0x42], command: UInt16 = 0,
        message: UInt64 = 1, response: Bool, status: UInt32 = 0, nextCommand: UInt32 = 0,
        tree: UInt32? = nil
    )
        -> [UInt8]
    {
        var bytes = signature + le16(64) + le16(1) + le32(status) + le16(command) + le16(1)
        bytes += le32(response ? 1 : 0) + le32(nextCommand) + le64(message) + le32(0) + le32(tree ?? treeID)
        bytes += le64(sessionID) + Array(repeating: 0, count: 16)
        return bytes
    }

    // MARK: Private

    private let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
    private let server = IPEndpoint(ip: "198.51.100.7", port: 445)
    private let sessionID: UInt64 = 0x100
    private let treeID: UInt32 = 0x200
    private let fileID = Array(0x20 ... 0x2F).map(UInt8.init)
    private var clientSequence: UInt32 = 1_001
    private var serverSequence: UInt32 = 5_001
    private var frames: [[UInt8]] = []
    private var messageID: UInt64 = 1

    private func nextMessage() -> UInt64 {
        defer { messageID += 1 }
        return messageID
    }

    private func addServerPDU(_ pdu: [UInt8]) {
        addTCP(clientToServer: false, payload: nbss(pdu))
    }

    private func addTCP(clientToServer: Bool, flags: UInt8 = 0x18, sequence: UInt32? = nil, payload: [UInt8]) {
        let source = clientToServer ? client : server
        let destination = clientToServer ? server : client
        let seq = sequence ?? (clientToServer ? clientSequence : serverSequence)
        let tcp = PacketBuilder.tcp(
            srcPort: source.port, dstPort: destination.port, flags: flags, payload: payload, sequence: seq
        )
        frames.append(PacketBuilder.ethernetIPv4(proto: 6, src: source.ip, dst: destination.ip, payload: tcp))
        if !payload.isEmpty {
            if clientToServer {
                clientSequence += UInt32(payload.count)
            } else {
                serverSequence += UInt32(payload.count)
            }
        }
    }

    private func nbss(_ pdu: [UInt8]) -> [UInt8] {
        [0, UInt8((pdu.count >> 16) & 0xFF), UInt8((pdu.count >> 8) & 0xFF), UInt8(pdu.count & 0xFF)] + pdu
    }

    private func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xFF), UInt8(value >> 8)]
    }

    private func le32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF),
        ]
    }

    private func le64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).map { UInt8((value >> ($0 * 8)) & 0xFF) }
    }
}
